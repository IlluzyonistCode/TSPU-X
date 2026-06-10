defmodule TspuX.RuleSubscriber do
  @moduledoc """
  Subscribes to Redis pub/sub channel "tspu_rules" to receive hot rule updates
  from the Python admin backend. No restart needed when rules change.
  """
  use GenServer
  require Logger

  @channel "tspu_rules"

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  @impl true
  def init(_) do
    redis_url = Application.get_env(:tspu_x, :redis_url, "redis://127.0.0.1:6379")
    case Redix.PubSub.start_link(redis_url) do
      {:ok, conn} ->
        Redix.PubSub.subscribe(conn, @channel, self())
        Logger.info("[RuleSubscriber] Subscribed to Redis channel '#{@channel}'")
        {:ok, %{conn: conn}}
      {:error, reason} ->
        Logger.warning("[RuleSubscriber] Redis unavailable: #{inspect(reason)}, retrying in 5s")
        Process.send_after(self(), :connect, 5_000)
        {:ok, %{conn: nil}}
    end
  end

  @impl true
  def handle_info({:redix_pubsub, _conn, _ref, :message, %{channel: @channel, payload: payload}}, state) do
    case Jason.decode(payload) do
      {:ok, %{"action" => "add", "rule" => rule}} ->
        TspuX.RuleEngine.add_rule(rule)
        # Apply rule immediately to all active clients — don't wait for next event
        TspuX.RuleEngine.apply_rule_to_active_clients(rule)

      {:ok, %{"action" => "remove", "id" => rule_id}} ->
        # Before removing — find the rule and unblock all affected clients
        rule = TspuX.RuleEngine.list_rules() |> Enum.find(& &1["id"] == rule_id)
        if rule, do: TspuX.RuleEngine.unblock_for_rule(rule)
        TspuX.RuleEngine.remove_rule(rule_id)

      {:ok, %{"action" => "reload_all", "rules" => rules}} ->
        Enum.each(rules, &TspuX.RuleEngine.add_rule/1)
        Logger.info("[RuleSubscriber] Bulk-reloaded #{length(rules)} rules")

      other ->
        Logger.warning("[RuleSubscriber] Unknown message: #{inspect(other)}")
    end
    {:noreply, state}
  end

  @impl true
  def handle_info({:redix_pubsub, _conn, _ref, :subscribed, _}, state) do
    {:noreply, state}
  end

  @impl true
  def handle_info(:connect, _state) do
    {:ok, new_state} = init([])
    {:noreply, new_state}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}
end