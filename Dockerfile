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

RUN addgroup --system --gid 1001 appuser && adduser --system --uid 1001 --gid 1001 appuser

COPY --from=builder /app/target/release/gws /usr/local/bin/gws
COPY config/ /app/config/

WORKDIR /app
USER appuser

# Cloud Run sets PORT env var (default 8080)
ENV PORT=8080

EXPOSE 8080

# Start MCP gateway in HTTP mode
# PORT is set by Cloud Run (default 8080), read via clap env("PORT")
# Required env vars (set by Cloud Run / Secret Manager):
#   GOOGLE_WORKSPACE_CLI_CLIENT_ID, GOOGLE_WORKSPACE_CLI_CLIENT_SECRET, GWS_GATEWAY_BASE_URL
# Optional env vars for session persistence:
#   GWS_TOKEN_STORE_BACKEND=secret-manager  (default: memory)
#   GWS_SECRET_MANAGER_PROJECT=<project-id>
#   GWS_SECRET_MANAGER_SECRET=gws-mcp-sessions
ENTRYPOINT ["gws", "mcp", "--host", "0.0.0.0", "--port", "8080", "-s", "all", "--permissions-file", "/app/config/permissions.yaml"]
