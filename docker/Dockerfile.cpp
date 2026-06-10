# ── Build stage ───────────────────────────────────────────────────────────────
FROM ubuntu:22.04 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake libpcap-dev libspdlog-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

RUN cmake -DCMAKE_BUILD_TYPE=Release -B build && \
    cmake --build build -j$(nproc)

# ── Runtime image ─────────────────────────────────────────────────────────────
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap0.8 libspdlog1 && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /var/log/tspu_x

COPY --from=builder /build/build/tspu_sniffer /usr/local/bin/tspu_sniffer

CMD ["tspu_sniffer", "--iface", "any"]
