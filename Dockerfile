# syntax=docker/dockerfile:1

# ---- build stage: static musl binary ----
# TARGETARCH is injected by BuildKit per platform, so this single Dockerfile
# covers amd64 (x86_64) and arm64 (aarch64), plus 32-bit arm/v7:
#   docker buildx build --platform linux/amd64,linux/arm64 -t fernhttp .
FROM rust:1.97-slim AS build
ARG TARGETARCH
WORKDIR /build

# Memory-conscious defaults for single-board hosts (Raspberry Pi etc.): the
# Cargo.toml release profile (fat LTO + one codegen unit) can OOM/ICE rustc
# while linking the bundled SQLite into a musl binary. Thin LTO + more codegen
# units cut peak memory by ~10x with a slightly larger binary; serial jobs
# protect low-RAM boards. Override per host to restore the original profile:
#   docker compose build --build-arg CARGO_LTO=true --build-arg CARGO_JOBS=4
ARG CARGO_LTO=thin
ARG CARGO_CODEGEN_UNITS=16
ARG CARGO_JOBS=1
ARG CARGO_OPTLVL=3
ENV CARGO_PROFILE_RELEASE_LTO=$CARGO_LTO \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=$CARGO_CODEGEN_UNITS \
    CARGO_PROFILE_RELEASE_OPT_LEVEL=$CARGO_OPTLVL \
    CARGO_BUILD_JOBS=$CARGO_JOBS

# Map Docker arch names to rustup musl targets. The triple is reused by later
# RUN steps via /tmp/triple, and the final binary is copied to a fixed path.
RUN case "$TARGETARCH" in \
      amd64) TRIPLE=x86_64-unknown-linux-musl ;; \
      arm64) TRIPLE=aarch64-unknown-linux-musl ;; \
      arm)   TRIPLE=armv7-unknown-linux-musleabihf ;; \
      *)     echo "Unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && echo "$TRIPLE" > /tmp/triple \
    && apt-get update \
    && apt-get install -y --no-install-recommends musl-tools \
    && rm -rf /var/lib/apt/lists/* \
    && rustup target add "$TRIPLE"

# Cache compiled dependencies: build once against a stub main.rs, then let
# the real source overlay it. Changing only src/* skips the rusqlite C build.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs \
    && cargo build --release --target "$(cat /tmp/triple)" \
    && rm -rf src

COPY src ./src
# Never let the stub build leak into the image: drop every artifact and
# fingerprint of the package so cargo cannot treat the app as up-to-date
# against the stub. cargo's freshness check is mtime-first and COPY keeps
# the sources' original (old) mtimes, so the just-written stub fingerprint
# would otherwise win and ship an empty binary. Dependency objects stay
# cached; only the app itself is forced to recompile.
RUN rm -rf \
        "target/$(cat /tmp/triple)"/.fingerprint/fernhttp-* \
        "target/$(cat /tmp/triple)"/release/fernhttp \
        "target/$(cat /tmp/triple)"/release/deps/fernhttp-* \
    && cargo build --release --target "$(cat /tmp/triple)" > /tmp/cargo.log 2>&1 \
    || { echo "--- cargo build failed; last 100 lines:" >&2; tail -n 100 /tmp/cargo.log >&2; exit 1; } \
    && BIN="target/$(cat /tmp/triple)/release/fernhttp" \
    && case "$($BIN --help 2>&1 | head -1)" in \
         "Usage: fernhttp"*) ;; \
         *) echo "BUILD FAILED: $BIN is not a working fernhttp" >&2; \
            echo "  src/main.rs line 1: $(head -1 src/main.rs)" >&2; \
            echo "  binary size: $(wc -c < "$BIN") bytes" >&2; \
            echo "  --help first line: '$($BIN --help 2>&1 | head -1)'" >&2; \
            exit 1 ;; \
       esac \
    && mkdir -p /build/out \
    && cp "$BIN" /build/out/fernhttp

# ---- runtime stage ----
FROM alpine:3.20

RUN mkdir -p /logs /data

COPY --from=build /build/out/fernhttp /usr/local/bin/fernhttp
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 7890
VOLUME ["/logs", "/data"]

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]