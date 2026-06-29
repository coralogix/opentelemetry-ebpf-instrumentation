# Integration-test image for Rust/Tokio context propagation.
#
# Builds just the two binaries the integration test needs:
#   server  — Axum on a multi-thread work-stealing runtime, with endpoints that
#             exercise tokio::spawn (async ancestry walk + cross-thread migration)
#             and spawn_blocking (blocking-pool bridge).
#   backend — downstream service that echoes the traceparent on /ping.
#
# Both run in ONE container so server can reach backend over 127.0.0.1 (the
# server hard-codes localhost). See docker-compose-rust-tokio.yml.
#
# Build context must be the repo root.
FROM rust:1.96.0-bookworm@sha256:13c186980fa33cc12759b429662a1322939dbe697484b7c33b47dd2698d28460 AS rustbuilder

WORKDIR /build
COPY internal/test/integration/components/rusttokiotest .

# Release build (what users ship), only the two packages we need.
RUN cargo build --locked --release -p server -p backend

FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=rustbuilder /build/target/release/server  ./server
COPY --from=rustbuilder /build/target/release/backend ./backend

# Run the backend in the background and the server in the foreground (one container,
# shared localhost). The server stays in the foreground so the container's lifecycle
# tracks it.
CMD ["sh", "-c", "./backend & exec ./server"]
