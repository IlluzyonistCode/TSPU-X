defmodule TspuX.ClientWorker do
  @moduledoc """
  One GenServer per connected client IP.
  Tracks domain session times, enforces rules, commands C++ via CppBridge.
  """
  use GenServer, restart: :temporary
  require Logger

  @idle_timeout_ms  30 * 60 * 1000
  @flush_interval_ms 10_000
  @session_gap_s 300

  # ─── Public API ─────────────────────────────

  def start_link(opts) do
    ip = Keyword.fetch!(opts, :ip)
    GenServer.start_link(__MODULE__, ip, name: via(ip))
  end

  def record_event(pid, domain, type, ts) do
    GenServer.cast(pid, {:event, domain, type, ts})
  end

  def get_stats(ip) do
    case Registry.lookup(TspuX.ClientRegistry, ip) do
      [{pid, _}] -> GenServer.call(pid, :get_stats)
      []         -> nil
    end
  end

  # ─── GenServer callbacks ─────────────────────

  @impl true
  def init(ip) do
    Logger.info("[ClientWorker] Started for #{ip}")
    schedule_flush()
    {:ok, %{
      ip:      ip,
      domains: %{},
      last_event_at: System.monotonic_time(:millisecond)
    }, @idle_timeout_ms}
  end

  @impl true
  def handle_cast({:event, domain, _type, ts}, state) do
    state = update_domain_stats(state, domain, ts)
    check_rules(state, domain)
    {:noreply, %{state | last_event_at: System.monotonic_time(:millisecond)}, @idle_timeout_ms}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, %{ip: state.ip, domains: state.domains}, state, @idle_timeout_ms}
  end

  @impl true
  def handle_info(:flush, state) do
    flush_to_scala(state)
    schedule_flush()
    {:noreply, state, @idle_timeout_ms}
  end

  @impl true
  def handle_info(:timeout, state) do
    Logger.info("[ClientWorker] Idle timeout for #{state.ip}")
    {:stop, :normal, state}
  end

  # ─── Internal ───────────────────────────────

  defp via(ip), do: {:via, Registry, {TspuX.ClientRegistry, ip}}

  defp update_domain_stats(state, domain, ts) do
    existing = Map.get(state.domains, domain, %{
      count: 0, total_seconds: 0,
      session_start_ts: ts, last_event_ts: ts
    })
    gap = ts - existing.last_event_ts
    session_secs = cond do
      gap < 0             -> 0
      gap > @session_gap_s -> 0
      true                -> gap
    end
    new_start = if gap > @session_gap_s or gap < 0, do: ts, else: existing.session_start_ts
    updated = %{existing |
      count:            existing.count + 1,
      total_seconds:    max(0, existing.total_seconds + session_secs),
      last_event_ts:    max(existing.last_event_ts, ts),
      session_start_ts: new_start
    }
    %{state | domains: Map.put(state.domains, domain, updated)}
  end

  defp check_rules(state, domain) do
    now_ts = TspuX.NtpTime.now()
    rules = TspuX.RuleEngine.matching_rules(state.ip, domain, now_ts)
    domain_stats = Map.get(state.domains, domain, %{total_seconds: 0})
    Enum.each(rules, fn rule -> apply_rule(state.ip, domain, domain_stats, rule) end)
  end

  # Block immediately — fire and forget
  defp apply_rule(ip, domain, _stats, %{"action" => "block"}) do
    Logger.info("[ClientWorker] Blocking #{ip} -> #{domain}")
    TspuX.CppBridge.block(ip, domain)
  end

  # Block after N minutes per day
  defp apply_rule(ip, domain, stats, %{"action" => "block_after_minutes", "minutes" => limit_min}) do
    limit_s = (limit_min || 30) * 60
    if stats.total_seconds >= limit_s do
      secs_until_midnight = seconds_until_midnight()
      Logger.info("[ClientWorker] Daily limit reached #{ip} -> #{domain} (#{stats.total_seconds}s >= #{limit_s}s)")
      TspuX.CppBridge.block(ip, domain, duration_seconds: secs_until_midnight)
    end
  end

  # Throttle — send delay command
  defp apply_rule(ip, domain, _stats, %{"action" => "throttle"} = rule) do
    delay_ms = Map.get(rule, "delay_ms", 1000)
    Logger.info("[ClientWorker] Throttling #{ip} -> #{domain} at #{delay_ms}ms")
    TspuX.CppBridge.throttle(ip, domain, delay_ms)
  end

  defp apply_rule(_ip, _domain, _stats, _rule), do: :ok

  defp seconds_until_midnight do
    now = TspuX.NtpTime.now()
    86400 - rem(now, 86400)
  end

  defp flush_to_scala(state) do
    event_ts = state.domains
      |> Map.values()
      |> Enum.map(& &1.last_event_ts)
      |> Enum.max(fn -> TspuX.NtpTime.now() end)

    payload = %{
      ip: state.ip,
      ts: event_ts,
      domains: Enum.map(state.domains, fn {domain, stats} ->
        %{domain: domain, count: stats.count, totalSeconds: max(0, stats.total_seconds)}
      end)
    }

    case Jason.encode(payload) do
      {:ok, body} ->
        scala_url = Application.get_env(:tspu_x, :scala_url, "http://127.0.0.1:8080")
        req = Finch.build(:post, "#{scala_url}/api/ingest",
          [{"content-type", "application/json"}], body)
        case Finch.request(req, TspuX.Finch, receive_timeout: 3000) do
          {:ok, %{status: 200}} -> :ok
          {:ok, %{status: s, body: b}} ->
            Logger.warning("[ClientWorker] Scala flush HTTP #{s}: #{b}")
          {:error, e} ->
            Logger.warning("[ClientWorker] Scala flush error: #{inspect(e)}")
        end
      _ -> :ok
    end
  end

  defp schedule_flush, do: Process.send_after(self(), :flush, @flush_interval_ms)
end