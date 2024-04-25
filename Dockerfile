FROM rust:1.77.2

ENV PKG_CONFIG_ALLOW_CROSS=1
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates openssl libssl-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
RUN update-ca-certificates

WORKDIR /usr/src/daedalus
COPY . .
RUN cargo build --release
RUN cp target/release/daedalus_client .

CMD ["./daedalus_client"]