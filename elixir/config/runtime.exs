import Config

config :tspu_x,
  event_port:   String.to_integer(System.get_env("EVENT_PORT", "4040")),
  redis_url:    System.get_env("REDIS_URL",    "redis://127.0.0.1:6379"),
  scala_url:    System.get_env("SCALA_URL",    "http://127.0.0.1:8080"),
  rules_file:   System.get_env("RULES_FILE",   "/etc/tspu_x/rules.json"),
  cpp_host:     String.to_charlist(System.get_env("CPP_HOST", "sniffer")),
  cpp_cmd_port: String.to_integer(System.get_env("CPP_CMD_PORT", "4041"))

config :logger,
  backends: [:console],
  level: :info

config :logger, :console,
  format: {TspuX.JsonLogger, :format},
  metadata: [:module, :client_ip, :domain]
