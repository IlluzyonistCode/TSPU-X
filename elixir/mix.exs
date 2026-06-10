defmodule TspuX.MixProject do
  use Mix.Project

  def project do
    [
      app: :tspu_x,
      version: "1.0.0",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger],
      mod: {TspuX.Application, []}
    ]
  end

  defp deps do
    [
      {:jason,  "~> 1.4"},
      {:finch,  "~> 0.16"},
      {:redix,  "~> 1.2"},
      {:castore, "~> 1.0"}
    ]
  end
end