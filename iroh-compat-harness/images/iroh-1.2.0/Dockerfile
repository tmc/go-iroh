FROM rust:1.96-bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends git pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Fetch only the pinned commit. A full clone downloads history the build never
# reads, and the commit is part of this layer's cache key either way.
ARG IROH_DOCTOR_COMMIT=c6abce70cbd3aa0ccea75401d141b4050d2f036b
WORKDIR /src/iroh-doctor
RUN git init -q . && \
    git remote add origin https://github.com/n0-computer/iroh-doctor.git && \
    git fetch -q --depth 1 origin ${IROH_DOCTOR_COMMIT} && \
    git checkout -q --detach FETCH_HEAD
COPY images/iroh-1.2.0/Cargo.lock ./Cargo.lock

# iroh-doctor 0.101.0 calls tokio::runtime::Builder::new_multi_thread but
# declares only tokio's "signal" feature. Against iroh 1.0.x it got
# "rt-multi-thread" incidentally, unified in through hickory-net's tokio
# feature; the iroh 1.2.0 graph no longer pulls that, and upstream has shipped
# no iroh-doctor for the 1.2 train (main is one commit past the pin and still
# declares iroh 1.0.0). So the feature the crate already uses is declared here.
# The gate holds the edit to that one line, and cargo --locked below proves the
# resolution did not move: a feature already present in the lock cannot change
# it. No iroh source is patched and no iroh behaviour changes -- tokio features
# are additive, and this is the same multi-thread runtime upstream always got.
RUN set -eu; \
    grep -qxF 'tokio = { version = "1.40.0", features = ["signal"] }' Cargo.toml || \
        { echo "iroh-doctor tokio dependency is not in the expected upstream form" >&2; exit 1; }; \
    sed -i '/^tokio = /s/"signal"/"signal", "rt-multi-thread"/' Cargo.toml; \
    git diff --numstat -- Cargo.toml | awk 'NR!=1 || $1!=1 || $2!=1 { exit 1 }' || \
        { echo "tokio feature declaration changed more than one line" >&2; git diff -- Cargo.toml >&2; exit 1; }

# The cargo caches hold only inputs cargo fingerprints itself, so a cached
# object is a rebuild it proved it could skip. Binaries are copied to /out
# inside the RUN because a cache mount is not part of the layer.
ARG IROH_VERSION=1.2.0
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/src/iroh-doctor/target,id=iroh-doctor-${IROH_VERSION},sharing=locked \
    cargo build --release --locked && \
    mkdir -p /out/bin && cp target/release/iroh-doctor /out/bin/iroh-doctor

# One target directory for both installs: iroh-relay and iroh-dns-server share
# most of their dependency graph, so the second build reuses the first.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/cargo-target,id=iroh-cli-${IROH_VERSION},sharing=locked \
    CARGO_TARGET_DIR=/cargo-target \
    cargo install --root /out iroh-relay --version ${IROH_VERSION} --locked --features server
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/cargo-target,id=iroh-cli-${IROH_VERSION},sharing=locked \
    CARGO_TARGET_DIR=/cargo-target \
    cargo install --root /out iroh-dns-server --version ${IROH_VERSION} --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/bin/iroh-doctor /usr/local/bin/iroh-doctor
COPY --from=build /out/bin/iroh-relay /usr/local/bin/iroh-relay
COPY --from=build /out/bin/iroh-dns-server /usr/local/bin/iroh-dns-server
COPY drivers/rust-native/driver /usr/local/bin/driver
LABEL org.opencontainers.image.source="https://github.com/tmc/go-iroh"
LABEL org.opencontainers.image.version="iroh-1.2.0"
ENTRYPOINT ["/usr/local/bin/driver"]
