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

# CARGO_PROFILE selects release (default, what users ship) or debug. The
# probe-discrimination experiment builds debug, where the Tokio poll probe
# (RawTask::poll) is NOT inlined and therefore fires on multi-thread workers —
# letting us demonstrate "probes on -> pass / probes off -> fail" before the
# release raw::poll re-target. The output dir name matches the profile
# (target/debug or target/release).
ARG CARGO_PROFILE=release

# RUSTFLAGS is threaded through so tests can select the symbol mangling scheme,
# e.g. RUSTFLAGS="-C symbol-mangling-version=v0" to build the v0 (_R…) scheme
# instead of the legacy (_ZN…E) default. Empty by default (legacy), so existing
# builds are unchanged. It applies to every crate in the build, including tokio,
# so its monomorphized symbols are emitted under the chosen scheme.
ARG RUSTFLAGS=""

WORKDIR /build
COPY internal/test/integration/components/rusttokiotest .

RUN if [ "$CARGO_PROFILE" = "debug" ]; then \
        RUSTFLAGS="${RUSTFLAGS}" cargo build --locked -p server -p backend; \
    else \
        RUSTFLAGS="${RUSTFLAGS}" cargo build --locked --release -p server -p backend; \
    fi

FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

ARG CARGO_PROFILE=release

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=rustbuilder /build/target/${CARGO_PROFILE}/server  ./server
COPY --from=rustbuilder /build/target/${CARGO_PROFILE}/backend ./backend

# Run the backend in the background and the server in the foreground (one container,
# shared localhost). The server stays in the foreground so the container's lifecycle
# tracks it.
CMD ["sh", "-c", "./backend & exec ./server"]
