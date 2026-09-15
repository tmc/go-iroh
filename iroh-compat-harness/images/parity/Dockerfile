ARG RUST_IMAGE
FROM ${RUST_IMAGE} AS rust-peer

# The baseline vector driver builds in its own stage: an edit to its sources
# no longer rebuilds the CustomAddr driver or re-fetches the upstream checkout,
# and BuildKit runs the two Rust stages concurrently.
FROM rust:1.96-bookworm AS driver-build
WORKDIR /src
COPY drivers/rust-driver/ ./
# The PQ peer enables upstream iroh's documented tls-aws-lc-rs feature. The
# iroh source is not patched; this small command adapter remains Tier B.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/src/target,id=rust-driver,sharing=locked \
    cargo build --release --locked && \
    mkdir -p /out && cp target/release/go-iroh-compat-rust-driver /out/

# The upstream fetch comes before the driver sources so that editing the driver
# does not invalidate the checkout, which is keyed only by its commit.
FROM rust:1.96-bookworm AS custom-build
ARG IROH_CUSTOM_COMMIT
RUN git init -q /upstream-iroh && \
    git -C /upstream-iroh remote add origin https://github.com/n0-computer/iroh.git && \
    git -C /upstream-iroh fetch -q --depth 1 origin ${IROH_CUSTOM_COMMIT} && \
    git -C /upstream-iroh checkout -q --detach FETCH_HEAD
COPY drivers/custom-addr/ /custom-addr/
# build.sh re-resolves the patch and re-reads Cargo.lock on every invocation,
# so the unused-patch gate still runs when compilation itself is cached.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/custom-target,id=custom-addr,sharing=locked \
    sh /custom-addr/build.sh /upstream-iroh /custom-target && \
    mkdir -p /out && cp /custom-target/release/go-iroh-custom-addr /out/

FROM golang:1.26-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates make && rm -rf /var/lib/apt/lists/*
COPY --from=rust-peer /usr/local/bin/iroh-doctor /usr/local/bin/iroh-doctor
COPY --from=rust-peer /usr/local/bin/iroh-relay /usr/local/bin/iroh-relay
COPY --from=rust-peer /usr/local/bin/iroh-dns-server /usr/local/bin/iroh-dns-server
COPY --from=driver-build /out/go-iroh-compat-rust-driver /usr/local/bin/rust-driver
COPY --from=custom-build /out/go-iroh-custom-addr /usr/local/bin/rust-driver-custom
WORKDIR /work/iroh-compat-harness
ENV RUST_DOCTOR_BIN=/usr/local/bin/iroh-doctor
ENV RUST_RELAY_BIN=/usr/local/bin/iroh-relay
ENV RUST_DNS_BIN=/usr/local/bin/iroh-dns-server
ENV RUST_VECTOR_BIN=/usr/local/bin/rust-driver
ENV RUST_CUSTOM_VECTOR_BIN=/usr/local/bin/rust-driver-custom
