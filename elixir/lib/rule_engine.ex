defmodule TspuX.RuleEngine do
  @moduledoc """
  Holds the rule table in an ETS set (read_concurrency: true).
  Rules hot-reloaded via Redis pub/sub — no process restart needed.

  Rule fields (all string keys, as decoded from JSON):
    id, scope, target, domain, time_from, time_to, days, action, minutes
  """
  use GenServer
  import Bitwise
  require Logger

  @table :tspu_rules

  def start_link(_opts), do: GenServer.start_link(__MODULE__, [], name: __MODULE__)

  # ─── Public API ─────────────────────────────

  def matching_rules(client_ip, domain, unix_ts) do
    :ets.tab2list(@table)
    |> Enum.filter(fn {_id, rule} -> rule_matches?(rule, client_ip, domain, unix_ts) end)
    |> Enum.map(fn {_id, rule} -> rule end)
  end

  def add_rule(rule) do
    GenServer.call(__MODULE__, {:add, rule})
  end

  def remove_rule(rule_id) do
    GenServer.call(__MODULE__, {:remove, rule_id})
  end

  def list_rules do
    :ets.tab2list(@table) |> Enum.map(fn {_id, rule} -> rule end)
  end

  @doc """
  When a new rule is added, immediately apply it to all active clients.
  This eliminates the delay between rule creation and enforcement.
  """
  def apply_rule_to_active_clients(rule) do
    action = Map.get(rule, "action", "")
    domain = Map.get(rule, "domain", "")
    scope  = Map.get(rule, "scope", "")

    cond do
      # Global rule — send ONE real "global" key. C++ already supports
      # matching "global:<domain>" in is_blocked(), it just was never
      # used before. This way newly-connected devices, and C++ after a
      # restart (via the periodic resync, see push_all_rules_to_cpp/0),
      # get the block immediately without depending on which client IPs
      # happened to be registered at the time.
      scope == "global" and action in ["block", "throttle"] ->
        case action do
          "block" ->
            log_result("block", "global", domain, TspuX.CppBridge.block("global", domain))
          "throttle" ->
            delay_ms = Map.get(rule, "delay_ms", 1000)
            log_result("throttle", "global", domain, TspuX.CppBridge.throttle("global", domain, delay_ms))
        end

      action in ["block", "throttle"] ->
        client_ips = Registry.select(TspuX.ClientRegistry, [{{:"$1", :_, :_}, [], [:"$1"]}])
        Enum.each(client_ips, fn ip ->
          if ip_matches?(rule, ip) do
            case action do
              "block" ->
                log_result("block", ip, domain, TspuX.CppBridge.block(ip, domain))
              "throttle" ->
                delay_ms = Map.get(rule, "delay_ms", 1000)
                log_result("throttle", ip, domain, TspuX.CppBridge.throttle(ip, domain, delay_ms))
            end
          end
        end)

      true -> :ok
    end

    if action == "block_after_minutes" do
      limit_s = Map.get(rule, "minutes", 30) * 60
      client_ips = Registry.select(TspuX.ClientRegistry, [{{:"$1", :_, :_}, [], [:"$1"]}])
      Enum.each(client_ips, fn ip ->
        if ip_matches?(rule, ip) do
          stats = case Registry.lookup(TspuX.ClientRegistry, ip) do
            [{pid, _}] ->
              state = :sys.get_state(pid)
              Map.get(state.domains, domain, %{total_seconds: 0})
            [] -> %{total_seconds: 0}
          end
          if stats.total_seconds >= limit_s do
            secs = 86400 - rem(System.os_time(:second), 86400)
            log_result("block", ip, domain, TspuX.CppBridge.block(ip, domain, duration_seconds: secs))
          end
        end
      end)
    end
  end

  defp log_result(action, ip, domain, :ok) do
    Logger.info("[RuleEngine] #{action} confirmed: #{ip} -> #{domain}")
  end
  defp log_result(action, ip, domain, {:error, reason}) do
    Logger.warning("[RuleEngine] #{action} FAILED (not delivered to C++): #{ip} -> #{domain} (#{inspect(reason)})")
  end

  @doc """
  When a block/throttle rule is removed, send unblock/unthrottle to C++
  for every active client that was covered by this rule.
  """
  def unblock_for_rule(%{"action" => action, "domain" => domain, "scope" => "global"})
      when action in ["block", "block_after_minutes", "throttle"] do
    result = case action do
      "throttle" -> TspuX.CppBridge.unthrottle("global", domain)
      _          -> TspuX.CppBridge.unblock("global", domain)
    end
    log_result("unblock", "global", domain, result)
  end
  def unblock_for_rule(%{"action" => action, "domain" => domain} = rule)
      when action in ["block", "block_after_minutes", "throttle"] do
    # Get all active client IPs from Registry
    client_ips = Registry.select(TspuX.ClientRegistry, [{{:"$1", :_, :_}, [], [:"$1"]}])
    Enum.each(client_ips, fn ip ->
      # Only unblock if this rule actually covered this client
      if ip_matches?(rule, ip) do
        result = case action do
          "throttle" -> TspuX.CppBridge.unthrottle(ip, domain)
          _          -> TspuX.CppBridge.unblock(ip, domain)
        end
        log_result("unblock", ip, domain, result)
      end
    end)
  end
  def unblock_for_rule(_rule), do: :ok

  # ─── GenServer ──────────────────────────────

  # g_block_table in C++ lives only in the sniffer process's memory and
  # gets wiped on every sniffer restart (image rebuild, crash, docker
  # compose up -d sniffer, etc.), while Elixir usually keeps running —
  # so a one-shot push at RuleEngine startup isn't enough. Re-send the
  # full active rule set on this interval so C++ self-heals after any
  # restart without manual intervention on the Pi.
  @resync_interval_ms 30_000

  @impl true
  def init(_) do
    :ets.new(@table, [:set, :named_table, :public, read_concurrency: true])
    load_from_file()
    Process.send_after(self(), :resync_cpp, 2_000)
    :timer.send_interval(@resync_interval_ms, :resync_cpp)
    {:ok, %{}}
  end

  @impl true
  def handle_call({:add, rule}, _from, state) do
    :ets.insert(@table, {rule["id"], rule})
    Logger.info("[RuleEngine] Added rule #{rule["id"]}")
    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:remove, rule_id}, _from, state) do
    :ets.delete(@table, rule_id)
    Logger.info("[RuleEngine] Removed rule #{rule_id}")
    {:reply, :ok, state}
  end

  @impl true
  def handle_info(:resync_cpp, state) do
    push_all_rules_to_cpp()
    {:noreply, state}
  end

  @doc """
  Re-sends all active block/throttle rules to the C++ sniffer.
  Idempotent — safe to call repeatedly.
  """
  def push_all_rules_to_cpp do
    list_rules()
    |> Enum.each(&apply_rule_to_active_clients/1)
  end

  # ─── Matching ───────────────────────────────

  defp rule_matches?(rule, client_ip, domain, unix_ts) do
    ip_matches?(rule, client_ip) and
    domain_matches?(rule, domain) and
    time_matches?(rule, unix_ts)
  end

  defp ip_matches?(%{"scope" => "global"}, _), do: true
  defp ip_matches?(%{"scope" => "ip", "target" => t}, ip), do: t == ip
  defp ip_matches?(%{"scope" => "subnet", "target" => cidr}, ip), do: cidr_contains?(cidr, ip)
  defp ip_matches?(_, _), do: false

  defp domain_matches?(%{"domain" => pattern}, domain) do
    cond do
      String.starts_with?(pattern, "~") ->
        regex_str = String.slice(pattern, 1..-1//1)
        match?({:ok, _}, Regex.compile(regex_str)) and
          Regex.match?(Regex.compile!(regex_str), domain)
      String.starts_with?(pattern, "*.") ->
        suffix = String.slice(pattern, 2..-1//1)
        domain == suffix or String.ends_with?(domain, "." <> suffix)
      true ->
        domain == pattern
    end
  end

  defp time_matches?(rule, unix_ts) do
    time_from = Map.get(rule, "time_from")
    time_to   = Map.get(rule, "time_to")
    days      = Map.get(rule, "days", [])

    # No time restriction
    if is_nil(time_from) or time_from == "" do
      true
    else
      dt = DateTime.from_unix!(unix_ts)
      day_ok = case days do
        nil -> true
        []  -> true
        ds  when is_list(ds) ->
          day_str = dt |> DateTime.to_date() |> Date.day_of_week() |> day_atom() |> to_string()
          day_str in ds
      end
      time_ok = if is_binary(time_from) and is_binary(time_to) and time_from != "" do
        current = {dt.hour, dt.minute}
        [fh, fm] = String.split(time_from, ":") |> Enum.map(&String.to_integer/1)
        [th, tm] = String.split(time_to,   ":") |> Enum.map(&String.to_integer/1)
        current >= {fh, fm} and current <= {th, tm}
      else
        true
      end
      day_ok and time_ok
    end
  end

  defp day_atom(1), do: :mon
  defp day_atom(2), do: :tue
  defp day_atom(3), do: :wed
  defp day_atom(4), do: :thu
  defp day_atom(5), do: :fri
  defp day_atom(6), do: :sat
  defp day_atom(7), do: :sun

  # IPv4 CIDR containment check
  defp cidr_contains?(cidr, ip_str) do
    try do
      [net_str, prefix_str] = String.split(cidr, "/")
      prefix = String.to_integer(prefix_str)
      {:ok, net_tuple} = :inet.parse_address(String.to_charlist(net_str))
      {:ok, ip_tuple}  = :inet.parse_address(String.to_charlist(ip_str))
      net_int = tuple_to_int(net_tuple)
      ip_int  = tuple_to_int(ip_tuple)
      mask    = (0xFFFFFFFF <<< (32 - prefix)) &&& 0xFFFFFFFF
      (net_int &&& mask) == (ip_int &&& mask)
    rescue
      _ -> false
    end
  end

  defp tuple_to_int({a, b, c, d}),
    do: (a <<< 24) + (b <<< 16) + (c <<< 8) + d

  defp load_from_file do
    path = Application.get_env(:tspu_x, :rules_file, "/etc/tspu_x/rules.json")
    case File.read(path) do
      {:ok, content} ->
        case Jason.decode(content) do
          {:ok, rules} when is_list(rules) ->
            Enum.each(rules, fn r -> :ets.insert(@table, {r["id"], r}) end)
            Logger.info("[RuleEngine] Loaded #{length(rules)} rules from #{path}")
          _ ->
            Logger.warning("[RuleEngine] Invalid rules JSON at #{path}")
        end
      {:error, _} ->
        Logger.info("[RuleEngine] No rules file at #{path}, starting empty")
    end
  end
end