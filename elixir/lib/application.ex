defmodule TspuX.Application do
  use Application
  require Logger

  @impl true
  def start(_type, _args) do
    Logger.info("[tspu_x] Starting application")

    children = [
      {Registry, keys: :unique, name: TspuX.ClientRegistry},
      TspuX.RuleEngine,
      {DynamicSupervisor, name: TspuX.ClientSupervisor, strategy: :one_for_one},
      {TspuX.EventServer, port: Application.get_env(:tspu_x, :event_port, 4040)},
      TspuX.RuleSubscriber,
      TspuX.CppBridge,
      TspuX.MetricsServer,
      {Finch, name: TspuX.Finch},
      # Persistent Redis connection for live event publishing
      {Redix, {Application.get_env(:tspu_x, :redis_url, "redis://127.0.0.1:6379"), [name: :redix_live]}}
    ]

    opts = [strategy: :one_for_one, name: TspuX.MainSupervisor]
    Supervisor.start_link(children, opts)
  end
end