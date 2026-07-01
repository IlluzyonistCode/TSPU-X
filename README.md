# TSPU X

> *Control your network. See everything. Miss nothing.*

![Flask](https://img.shields.io/badge/Flask-000000.svg?style=flat-square&logo=Flask&logoColor=white)  ![Scala](https://img.shields.io/badge/Scala-DC322F.svg?style=flat-square&logo=Scala&logoColor=white)  ![Redis](https://img.shields.io/badge/Redis-FF4438.svg?style=flat-square&logo=Redis&logoColor=white)  ![Mix](https://img.shields.io/badge/Mix-FF8126.svg?style=flat-square&logo=Mix&logoColor=white)  ![Gunicorn](https://img.shields.io/badge/Gunicorn-499848.svg?style=flat-square&logo=Gunicorn&logoColor=white)  ![Docker](https://img.shields.io/badge/Docker-2496ED.svg?style=flat-square&logo=Docker&logoColor=white)  ![XML](https://img.shields.io/badge/XML-005FAD.svg?style=flat-square&logo=XML&logoColor=white)  ![CMake](https://img.shields.io/badge/CMake-064F8C.svg?style=flat-square&logo=CMake&logoColor=white)  ![Python](https://img.shields.io/badge/Python-3776AB.svg?style=flat-square&logo=Python&logoColor=white)  ![Elixir](https://img.shields.io/badge/Elixir-4B275F.svg?style=flat-square&logo=Elixir&logoColor=white)

## Overview

TSPU X is a polyglot network traffic management platform. A C++ packet sniffer and proxy engine handles low-level enforcement, an Elixir layer orchestrates per-client policy decisions, a Scala service aggregates events into a persistent store, and a Python Flask interface provides administrative control — all wired together through Docker and Redis.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Contributing](#contributing)
- [License](#license)

---

## Features

|      | Component         | Details                                                                                                                                                                                                                                                                  |
| :--- | :---------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ⚙️  | **Architecture**  | <ul><li>**Polyglot microservices** architecture spanning C++, Python, Scala, and Elixir</li><li>C++ core (`tspu_sniffer`) handles low-level packet sniffing via `spdlog`</li><li>Python layer exposes HTTP API via **Flask + Gunicorn + Gevent**</li><li>Scala service handles structured logging (`logback.xml`)</li><li>Elixir service manages concurrent workloads via OTP (`mix.exs`)</li><li>Services orchestrated through `docker-compose.yml`</li></ul> |
| 🔩 | **Code Quality**  | <ul><li>C++ build managed by **CMake** (`CMakeLists.txt`) with explicit target linking (`spdlog::spdlog`, `tspu_sniffer`)</li><li>Scala build via **SBT** (`build.sbt` + `plugins.sbt`) with structured logging via `logback.xml`</li><li>Elixir dependencies locked via `mix.lock` — ensures reproducible builds</li><li>Python dependencies pinned in `requirements.txt`</li></ul> |
| 📄 | **Documentation** | <ul><li>Docker Compose file (`docker/docker-compose.yml`) serves as primary infrastructure reference</li><li>HTML files present — likely static docs or a dashboard UI</li><li>`LICENSE` file included — project is openly licensed</li><li>No dedicated wiki or API docs detected</li></ul> |
| 🔌 | **Integrations**  | <ul><li>**Redis** — used by Python service for caching or pub/sub messaging</li><li>**Gunicorn + Gevent** — async WSGI integration for non-blocking Python HTTP handling</li><li>`requests` library — Python service makes outbound HTTP calls</li><li>Elixir integrates via `mix.lock`-managed Hex packages</li><li>Scala emits structured logs consumed cross-service</li></ul> |
| 🧩 | **Modularity**    | <ul><li>Each language runtime is **isolated into its own directory** (`cpp/`, `python/`, `scala/`, `elixir/`)</li><li>Separate `Dockerfile` per service (`dockerfile.python`, `dockerfile.elixir`)</li><li>Independent build systems per module: `cmake`, `sbt`, `mix`, `pip`</li><li>Services are loosely coupled — communicate via Redis or HTTP</li></ul> |

---

## Project Structure

```
└── TSPU X/
    ├── cpp
    │   ├── .dockerignore
    │   ├── CMakeLists.txt
    │   ├── dns_parser.hpp
    │   ├── main.cpp
    │   └── tls_parser.hpp
    ├── docker
    │   ├── docker-compose.yml
    │   ├── Dockerfile.cpp
    │   ├── Dockerfile.elixir
    │   ├── Dockerfile.python
    │   ├── Dockerfile.scala
    │   └── scala_log.txt
    ├── elixir
    │   ├── .dockerignore
    │   ├── config
    │   ├── lib
    │   ├── mix.exs
    │   └── mix.lock
    ├── LICENSE
    ├── python
    │   ├── .dockerignore
    │   ├── app.py
    │   ├── requirements.txt
    │   ├── static
    │   └── templates
    ├── README.md
    └── scala
        ├── .dockerignore
        ├── build.sbt
        ├── project
        └── src
```

---

## Getting Started

### Prerequisites

- Python 3.10+ / Node.js 18+ *(depending on the stack above)*

### Installation

```sh
git clone "https://github.com/IlluzyonistCode/TSPU X"
cd "TSPU X"
docker-compose up --build
```

### Usage

```sh
docker-compose up --build
```

---

## Contributing

- [Report Issues](https://github.com/IlluzyonistCode/TSPU X/issues)
- [Submit Pull Requests](https://github.com/IlluzyonistCode/TSPU X/pulls)
- [Discussions](https://github.com/IlluzyonistCode/TSPU X/discussions)

---

## License

Distributed under the [AGPL-3.0](LICENSE) license.
