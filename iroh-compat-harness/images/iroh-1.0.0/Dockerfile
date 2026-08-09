FROM rust:1.96-bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends git pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git clone https://github.com/n0-computer/iroh-doctor.git && \
    cd iroh-doctor && git checkout c6abce70cbd3aa0ccea75401d141b4050d2f036b
COPY images/iroh-1.0.0/Cargo.lock /src/iroh-doctor/Cargo.lock
RUN cd iroh-doctor && cargo build --release --locked
RUN cargo install iroh-relay --version 1.0.0 --locked --features server
RUN cargo install iroh-dns-server --version 1.0.0 --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/iroh-doctor/target/release/iroh-doctor /usr/local/bin/iroh-doctor
COPY --from=build /usr/local/cargo/bin/iroh-relay /usr/local/bin/iroh-relay
COPY --from=build /usr/local/cargo/bin/iroh-dns-server /usr/local/bin/iroh-dns-server
COPY drivers/rust-native/driver /usr/local/bin/driver
LABEL org.opencontainers.image.source="https://github.com/tmc/go-iroh"
LABEL org.opencontainers.image.version="iroh-1.0.0"
ENTRYPOINT ["/usr/local/bin/driver"]
