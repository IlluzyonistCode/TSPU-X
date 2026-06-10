defmodule TspuX.MetricsServer do
  @moduledoc """
  Minimal HTTP server on port 4043: /health and /metrics.
  Uses raw line-mode TCP to avoid OTP version quirks with :http_bin.
  """
  use GenServer
  require Logger

  @port 4043

  def start_link(_opts), do: GenServer.start_link(__MODULE__, [], name: __MODULE__)

  # ─── Public counter API ──────────────────────

  def increment_events do
    ref = counter_ref()
    :counters.add(ref, 1, 1)
  end

  def event_count do
    :counters.get(counter_ref(), 1)
  end

  defp counter_ref do
    case :persistent_term.get({__MODULE__, :counter}, :not_found) do
      :not_found ->
        ref = :counters.new(1, [:atomics])
        :persistent_term.put({__MODULE__, :counter}, ref)
        ref
      ref -> ref
    end
  end

  # ─── GenServer ──────────────────────────────

  @impl true
  def init(_) do
    # initialise counter early so it's available before first event
    counter_ref()
    {:ok, lsock} = :gen_tcp.listen(@port, [
      :binary, packet: :line, active: false, reuseaddr: true
    ])
    Logger.info("[MetricsServer] Listening on port #{@port}")
    spawn_link(fn -> accept_loop(lsock) end)
    {:ok, %{}}
  end

  defp accept_loop(lsock) do
    case :gen_tcp.accept(lsock) do
      {:ok, csock} -> spawn(fn -> handle(csock) end)
      _            -> :ok
    end
    accept_loop(lsock)
  end

  defp handle(sock) do
    # Read request line: "GET /health HTTP/1.1\r\n"
    case :gen_tcp.recv(sock, 0, 3000) do
      {:ok, req_line} ->
        path = parse_path(req_line)
        drain_until_blank(sock)
        body = build_body(path)
        resp =
          "HTTP/1.1 200 OK\r\n" <>
          "Content-Type: application/json\r\n" <>
          "Content-Length: #{byte_size(body)}\r\n" <>
          "Connection: close\r\n\r\n" <> body
        :gen_tcp.send(sock, resp)
        :gen_tcp.close(sock)
      _ ->
        :gen_tcp.close(sock)
    end
  end

  defp parse_path(line) do
    # "GET /health HTTP/1.1\r\n" → "/health"
    case String.split(String.trim(line), " ") do
      [_method, path | _] -> path
      _                   -> "/"
    end
  end

  defp drain_until_blank(sock) do
    case :gen_tcp.recv(sock, 0, 500) do
      {:ok, "\r\n"} -> :ok
      {:ok, "\n"}   -> :ok
      {:ok, _}      -> drain_until_blank(sock)
      _             -> :ok
    end
  end

  defp build_body("/health") do
    Jason.encode!(%{
      status:         "ok",
      component:      "elixir",
      active_clients: active_client_count(),
      rule_count:     rule_count(),
      events_total:   event_count()
    })
  end

  defp build_body("/metrics") do
    Jason.encode!(%{
      active_clients: active_client_count(),
      rule_count:     rule_count(),
      events_total:   event_count()
    })
  end

  defp build_body(_) do
    Jason.encode!(%{error: "not_found"})
  end

  defp active_client_count do
    Registry.select(TspuX.ClientRegistry, [{{:_, :_, :_}, [], [true]}])
    |> length()
  end

  defp rule_count do
    try do
      :ets.info(:tspu_rules, :size) || 0
    rescue
      _ -> 0
    end
  end
end