# Stage 1: Build
FROM rust:1.93-slim-bookworm AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY registry/ registry/
COPY templates/ templates/

RUN cargo build --release --bin gws

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/gws /usr/local/bin/gws
COPY config/ /app/config/

WORKDIR /app

# Cloud Run sets PORT env var (default 8080)
ENV PORT=8080

EXPOSE 8080

# Start MCP gateway in HTTP mode
# OAuth credentials should be provided via env vars or Secret Manager
ENTRYPOINT ["gws", "mcp", "-t", "http", "--host", "0.0.0.0", "--port", "8080", "-s", "all", "--permissions-file", "/app/config/permissions.yaml"]
