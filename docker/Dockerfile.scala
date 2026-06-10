# ── Build stage ───────────────────────────────────────────────────────────────
# Используем официальный eclipse-temurin JDK 17 (стабильный тег, не меняется)
# и устанавливаем sbt вручную — так Dockerfile не ломается при ротации тегов sbtscala.
FROM eclipse-temurin:17-jdk AS builder

# Установить sbt
ARG SBT_VERSION=1.9.9
RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    curl -fsSL "https://github.com/sbt/sbt/releases/download/v${SBT_VERSION}/sbt-${SBT_VERSION}.tgz" \
      | tar -xz -C /usr/local && \
    ln -s /usr/local/sbt/bin/sbt /usr/local/bin/sbt && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Копируем описания зависимостей — слой кэшируется пока build.sbt не меняется
COPY project/plugins.sbt project/
COPY build.sbt .
RUN sbt update

# Копируем исходники и собираем fat JAR
COPY src ./src
RUN sbt assembly

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM eclipse-temurin:17-jre-alpine

RUN mkdir -p /var/lib/tspu_x

COPY --from=builder /build/target/scala-2.13/tspu-aggregator-assembly-1.0.0.jar /app.jar

EXPOSE 8080 8081
CMD ["java", "-Xmx256m", "-jar", "/app.jar"]
