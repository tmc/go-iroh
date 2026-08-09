FROM rust:1.96-bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends git pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git clone https://github.com/n0-computer/iroh-doctor.git && \
    cd iroh-doctor && git checkout c6abce70cbd3aa0ccea75401d141b4050d2f036b
COPY images/iroh-1.0.3/Cargo.lock /src/iroh-doctor/Cargo.lock
RUN cd iroh-doctor && cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/iroh-doctor/target/release/iroh-doctor /usr/local/bin/iroh-doctor
COPY drivers/rust-native/driver /usr/local/bin/driver
LABEL org.opencontainers.image.source="https://github.com/tmc/go-iroh"
LABEL org.opencontainers.image.version="iroh-1.0.3"
ENTRYPOINT ["/usr/local/bin/driver"]
