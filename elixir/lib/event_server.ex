defmodule TspuX.EventServer do
  @moduledoc """
  TCP server on port 4040 — receives newline-delimited JSON events from C++.
  Each accepted connection is handled in its own lightweight process.
  """
  use GenServer
  require Logger

  def start_link(opts) do
    port = Keyword.fetch!(opts, :port)
    GenServer.start_link(__MODULE__, port, name: __MODULE__)
  end

  @impl true
  def init(port) do
    {:ok, lsock} = :gen_tcp.listen(port, [
      :binary, packet: :line, active: false, reuseaddr: true
    ])
    Logger.info("[EventServer] Listening on port #{port}")
    spawn_link(fn -> accept_loop(lsock) end)
    {:ok, %{listen_sock: lsock, port: port}}
  end

  defp accept_loop(lsock) do
    case :gen_tcp.accept(lsock) do
      {:ok, csock} ->
        spawn(fn -> handle_connection(csock) end)
        accept_loop(lsock)
      {:error, reason} ->
        Logger.warning("[EventServer] Accept error: #{inspect(reason)}")
        :timer.sleep(500)
        accept_loop(lsock)
    end
  end

  defp handle_connection(sock) do
    case :gen_tcp.recv(sock, 0) do
      {:ok, line} ->
        line = String.trim(line)
        case Jason.decode(line) do
          {:ok, event} ->
            TspuX.MetricsServer.increment_events()
            # Publish to Redis for live SSE stream in UI
            publish_live_event(line)
            dispatch_event(event)
          {:error, _} ->
            Logger.warning("[EventServer] Bad JSON: #{line}")
        end
        handle_connection(sock)
      {:error, :closed} -> :ok
      {:error, reason}  ->
        Logger.warning("[EventServer] Recv error: #{inspect(reason)}")
    end
  end

  defp publish_live_event(json_line) do
    case Redix.command(:redix_live, ["PUBLISH", "tspu_live_events", json_line]) do
      {:ok, _} -> :ok
      _ -> :ok  # non-critical, silently ignore
    end
  end

  defp dispatch_event(%{"ip" => ip, "domain" => domain, "type" => type, "ts" => ts}) do
    case ensure_worker(ip) do
      nil -> :ok
      pid -> TspuX.ClientWorker.record_event(pid, domain, type, ts)
    end
  end
  defp dispatch_event(_), do: :ok

  defp ensure_worker(ip) do
    case Registry.lookup(TspuX.ClientRegistry, ip) do
      [{pid, _}] -> pid
      [] ->
        {:ok, pid} = DynamicSupervisor.start_child(
          TspuX.ClientSupervisor, {TspuX.ClientWorker, ip: ip}
        )
        pid
    end
  end
end