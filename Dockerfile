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
# PORT is set by Cloud Run (default 8080), read via clap env("PORT")
# OAuth credentials are required via env vars (set by Cloud Run / Secret Manager):
#   GOOGLE_WORKSPACE_CLI_CLIENT_ID, GOOGLE_WORKSPACE_CLI_CLIENT_SECRET, GWS_GATEWAY_BASE_URL
ENTRYPOINT ["gws", "mcp", "--host", "0.0.0.0", "--port", "8080", "-s", "all", "--permissions-file", "/app/config/permissions.yaml"]
