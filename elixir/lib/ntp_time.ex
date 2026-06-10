defmodule TspuX.NtpTime do
  @moduledoc """
  Получает реальное Unix-время с публичных NTP-серверов.
  Кешируется на 60 секунд чтобы не спамить NTP при каждом flush.
  """
  require Logger

  @ntp_servers [~c"pool.ntp.org", ~c"time.cloudflare.com", ~c"time.google.com"]
  @ntp_epoch_offset 2_208_988_800
  @cache_ttl_ms 60_000

  def now() do
    case :persistent_term.get({__MODULE__, :cache}, nil) do
      {ts, cached_at} ->
        elapsed_ms = :erlang.monotonic_time(:millisecond) - cached_at
        if elapsed_ms < @cache_ttl_ms do
          ts + div(elapsed_ms, 1000)
        else
          fetch_and_cache()
        end
      nil ->
        fetch_and_cache()
    end
  end

  defp fetch_and_cache() do
    ts = fetch_ntp() || System.os_time(:second)
    :persistent_term.put({__MODULE__, :cache}, {ts, :erlang.monotonic_time(:millisecond)})
    ts
  end

  defp fetch_ntp() do
    Enum.find_value(@ntp_servers, &try_ntp/1)
  end

  defp try_ntp(server) do
    try do
      {:ok, sock} = :gen_udp.open(0, [:binary, active: false])
      packet = <<0x1B>> <> :binary.copy(<<0>>, 47)
      :ok = :gen_udp.send(sock, server, 123, packet)
      result = case :gen_udp.recv(sock, 0, 3000) do
        {:ok, {_addr, _port, data}} when byte_size(data) >= 48 ->
          <<_::binary-size(40), ntp_secs::unsigned-32, _::binary>> = data
          unix_ts = ntp_secs - @ntp_epoch_offset
          Logger.info("[NtpTime] Got time from #{server}: #{unix_ts}")
          unix_ts
        _ ->
          nil
      end
      :gen_udp.close(sock)
      result
    rescue
      _ -> nil
    catch
      _, _ -> nil
    end
  end
end