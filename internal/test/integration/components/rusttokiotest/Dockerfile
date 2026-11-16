# Integration-test image for Rust/Tokio context propagation.
#
# Builds the backend and one server, selected by SERVER_BIN:
#   server       — Axum on a multi-thread work-stealing runtime, with endpoints that
#                  exercise tokio::spawn (async ancestry walk + cross-thread migration)
#                  and spawn_blocking (blocking-pool bridge).
#   server-actix — actix-web, one current-thread runtime per worker thread.
#   backend      — downstream service that echoes the traceparent on /ping.
#
# Both run in ONE container so server can reach backend over 127.0.0.1 (the
# server hard-codes localhost). See docker-compose-rust-tokio.yml.
#
# Build context must be the repo root.
#
# RUST_LEG selects the toolchain, and with it the symbol mangling scheme the probes must
# resolve: v0 (rust 1.99.0; the _R… scheme is the stable default since Rust 1.97) or
# legacy (rust 1.96.0, the last toolchain emitting _ZN…E by default: what a binary built
# before Rust 1.97 carries). Legacy cannot be selected by flag on stable 1.97+, so it is a
# second pinned image. Both are tested. Declared before the first FROM: only such ARGs
# can be used by a FROM.
ARG RUST_LEG=v0
FROM rust:1.96.0-bookworm@sha256:13c186980fa33cc12759b429662a1322939dbe697484b7c33b47dd2698d28460 AS rust-legacy
FROM rust:1.99.0-bookworm@sha256:59037199c44290f2befcdd58dcc540164763fc296950255aaefeef096a1866b0 AS rust-v0
FROM rust-${RUST_LEG} AS rustbuilder

# CARGO_PROFILE selects release (default, what users ship) or debug. Both are tested:
# tokio's task-id setter stays out of line only in debug, so the id walk runs only
# there. The output dir name matches the profile (target/debug or target/release).
ARG CARGO_PROFILE=release

# SERVER_BIN selects the server crate (server or server-actix); it is copied into the
# image as ./server either way, so the service name is the same in every suite.
ARG SERVER_BIN=server

WORKDIR /build
COPY internal/test/integration/components/rusttokiotest .

RUN if [ "$CARGO_PROFILE" = "debug" ]; then \
        cargo build --locked -p "$SERVER_BIN" -p backend; \
    else \
        cargo build --locked --release -p "$SERVER_BIN" -p backend; \
    fi

FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

ARG CARGO_PROFILE=release
ARG SERVER_BIN=server

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=rustbuilder /build/target/${CARGO_PROFILE}/${SERVER_BIN} ./server
COPY --from=rustbuilder /build/target/${CARGO_PROFILE}/backend ./backend

# Run one backend process per port in the background and the server in the foreground
# (one container, shared localhost). Two backend processes, not one with two listeners:
# OBI keys a server's inbound trace by the client's address and port plus the server's
# pid, and the A/B bursts open connections from one ephemeral port to both backend ports
# a few times per run. The server stays in the foreground so the container's lifecycle
# tracks it. START_DELAY (seconds, default 0) holds all three back so a suite can have OBI
# attached before the app exists (docker-compose-rust-tokio-obi-first.yml).
CMD ["sh", "-c", "sleep ${START_DELAY:-0}; ./backend 8093 & ./backend 8094 & exec ./server"]
