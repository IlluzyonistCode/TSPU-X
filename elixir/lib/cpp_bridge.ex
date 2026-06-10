defmodule TspuX.CppBridge do
  @moduledoc """
  Sends block/unblock/throttle/unthrottle commands to the C++ sniffer (port 4041).
  Uses connect-send-close per command for reliable delivery.
  """
  use GenServer
  require Logger

  def start_link(_opts), do: GenServer.start_link(__MODULE__, [], name: __MODULE__)

  def block(ip, domain, opts \\ []) do
    payload = %{cmd: "block", ip: ip, domain: domain}
    payload = maybe_add_duration(payload, opts)
    payload = maybe_add_until(payload, opts)
    GenServer.cast(__MODULE__, {:send, payload})
  end

  def unblock(ip, domain) do
    GenServer.cast(__MODULE__, {:send, %{cmd: "unblock", ip: ip, domain: domain}})
  end

  def throttle(ip, domain, delay_ms, opts \\ []) do
    payload = %{cmd: "throttle", ip: ip, domain: domain, delay_ms: delay_ms}
    payload = maybe_add_duration(payload, opts)
    GenServer.cast(__MODULE__, {:send, payload})
  end

  def unthrottle(ip, domain) do
    GenServer.cast(__MODULE__, {:send, %{cmd: "unthrottle", ip: ip, domain: domain}})
  end

  @impl true
  def init(_), do: {:ok, %{}}

  @impl true
  def handle_cast({:send, payload}, state) do
    msg = Jason.encode!(payload) <> "\n"
    host = System.get_env("CPP_HOST", "sniffer") |> String.to_charlist()
    port = System.get_env("CPP_CMD_PORT", "4041") |> String.to_integer()
    case :gen_tcp.connect(host, port, [:binary, active: false], 3000) do
      {:ok, sock} ->
        :gen_tcp.send(sock, msg)
        :gen_tcp.close(sock)
        Logger.info("[CppBridge] Sent: #{inspect(payload)}")
      {:error, reason} ->
        Logger.warning("[CppBridge] Cannot connect to C++: #{inspect(reason)}, retry in 10s")
    end
    {:noreply, state}
  end

  defp maybe_add_duration(payload, opts) do
    case Keyword.get(opts, :duration_seconds) do
      nil -> payload
      dur -> Map.put(payload, :duration_seconds, dur)
    end
  end

  defp maybe_add_until(payload, opts) do
    case Keyword.get(opts, :until) do
      nil -> payload
      u   -> Map.put(payload, :until, u)
    end
  end
end