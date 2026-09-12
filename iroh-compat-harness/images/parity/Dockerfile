ARG RUST_IMAGE
FROM ${RUST_IMAGE} AS rust-peer

FROM rust:1.96-bookworm AS vector-build
WORKDIR /src
COPY drivers/rust-driver/ ./
# The PQ peer enables upstream iroh's documented tls-aws-lc-rs feature. The
# iroh source is not patched; this small command adapter remains Tier B.
RUN cargo build --release --locked
COPY drivers/custom-addr/ /custom-addr/
ARG IROH_CUSTOM_COMMIT
RUN git init /upstream-iroh && \
    git -C /upstream-iroh remote add origin https://github.com/n0-computer/iroh.git && \
    git -C /upstream-iroh fetch --depth 1 origin ${IROH_CUSTOM_COMMIT} && \
    git -C /upstream-iroh checkout --detach FETCH_HEAD
RUN sh /custom-addr/build.sh /upstream-iroh /custom-target

FROM golang:1.26-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates make && rm -rf /var/lib/apt/lists/*
COPY --from=rust-peer /usr/local/bin/iroh-doctor /usr/local/bin/iroh-doctor
COPY --from=rust-peer /usr/local/bin/iroh-relay /usr/local/bin/iroh-relay
COPY --from=rust-peer /usr/local/bin/iroh-dns-server /usr/local/bin/iroh-dns-server
COPY --from=vector-build /src/target/release/go-iroh-compat-rust-driver /usr/local/bin/rust-driver
COPY --from=vector-build /custom-target/release/go-iroh-custom-addr /usr/local/bin/rust-driver-custom
WORKDIR /work/iroh-compat-harness
ENV RUST_DOCTOR_BIN=/usr/local/bin/iroh-doctor
ENV RUST_RELAY_BIN=/usr/local/bin/iroh-relay
ENV RUST_DNS_BIN=/usr/local/bin/iroh-dns-server
ENV RUST_VECTOR_BIN=/usr/local/bin/rust-driver
ENV RUST_CUSTOM_VECTOR_BIN=/usr/local/bin/rust-driver-custom
