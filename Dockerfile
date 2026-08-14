FROM rust:1.94.0 AS builder

ENV PKG_CONFIG_ALLOW_CROSS=1
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates openssl libssl-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/daedalus
COPY . .
RUN cargo build --release --locked

# The runtime base must track the builder image's Debian release: the binary
# links against that image's glibc and OpenSSL, and rust:1.94.0 is trixie. If
# the builder tag moves to a newer Debian, this base and the package names below
# move with it.
FROM debian:trixie-slim

# Exactly what `ldd daedalus_binary` resolves outside the base image: libssl.so.3
# and libcrypto.so.3 from libssl3t64, libbz2.so.1.0, libz and libzstd.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3t64 \
        libbz2-1.0 \
        zlib1g \
        libzstd1 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
RUN update-ca-certificates

# CDN_UPLOAD_DIR defaults to ./upload_cdn and is resolved relative to the working
# directory, and startup refuses to boot when it is missing — so the mirror ships
# in the image and this WORKDIR is load-bearing, not cosmetic.
WORKDIR /usr/src/daedalus
COPY --from=builder /usr/src/daedalus/target/release/daedalus_client ./daedalus_binary
COPY --from=builder /usr/src/daedalus/upload_cdn ./upload_cdn

CMD ["./daedalus_binary"]
