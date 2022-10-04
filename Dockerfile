FROM rust:latest
MAINTAINER caleb <calebsmithwoolrich@gmail.com>

RUN mkdir /opt/atlas && mkdir -p /app && git clone https://github.com/PixelCoda/rust_rouille_hello /app \
    && cd /app \
    && cargo build --release  \
    && rm -Rf /app/src  /app/target/release/build /app/target/release/deps /app/target/release/examples/ /app/target/release/incremental/ /app/target/release/native
WORKDIR /app/target/release
CMD ["./atlas"]