ARG RUST_IMAGE
FROM ${RUST_IMAGE} AS rust-peer

# The vector driver builds in its own stage so that editing its sources leaves
# the peer image untouched.
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

FROM golang:1.26-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates make && rm -rf /var/lib/apt/lists/*
COPY --from=rust-peer /usr/local/bin/iroh-doctor /usr/local/bin/iroh-doctor
COPY --from=rust-peer /usr/local/bin/iroh-relay /usr/local/bin/iroh-relay
COPY --from=rust-peer /usr/local/bin/iroh-dns-server /usr/local/bin/iroh-dns-server
COPY --from=driver-build /out/go-iroh-compat-rust-driver /usr/local/bin/rust-driver
WORKDIR /work/iroh-compat-harness
ENV RUST_DOCTOR_BIN=/usr/local/bin/iroh-doctor
ENV RUST_RELAY_BIN=/usr/local/bin/iroh-relay
ENV RUST_DNS_BIN=/usr/local/bin/iroh-dns-server
ENV RUST_VECTOR_BIN=/usr/local/bin/rust-driver
