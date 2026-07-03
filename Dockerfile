FROM rust:slim-bookworm AS builder

WORKDIR /usr/src/quiclime

COPY Cargo.toml Cargo.lock ./
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

COPY src ./src

RUN touch src/main.rs && cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash quiclime
USER quiclime

WORKDIR /app

COPY --from=builder /usr/src/quiclime/target/release/quiclime /usr/local/bin/quiclime

ENTRYPOINT ["quiclime"]
