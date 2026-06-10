defmodule TspuX.JsonLogger do
  @moduledoc "Custom Logger formatter that emits newline-delimited JSON to stdout."

  def format(level, message, {date, time}, metadata) do
    ts = format_ts(date, time)

    entry = %{
      ts:        ts,
      level:     to_string(level),
      component: "elixir",
      msg:       to_string(message)
    }
    |> maybe_add(:client_ip, metadata[:client_ip])
    |> maybe_add(:domain,    metadata[:domain])
    |> maybe_add(:module,    metadata[:module])

    Jason.encode!(entry) <> "\n"
  rescue
    _ ->
      # ts может быть недоступен если format_ts упало — используем fallback
      fallback_ts = inspect({date, time})
      "[#{level}] #{fallback_ts} #{message}\n"
  end

  defp maybe_add(map, _key, nil), do: map
  defp maybe_add(map, key, val),  do: Map.put(map, key, to_string(val))

  defp format_ts({y, m, d}, {h, min, s, _ms}) do
    :io_lib.format("~4..0B-~2..0B-~2..0BT~2..0B:~2..0B:~2..0B", [y, m, d, h, min, s])
    |> IO.iodata_to_binary()
  end
end