FROM rust:1-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release -p subconverter-server

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /src/target/release/subconverter-server /usr/local/bin/subconverter
COPY base/ /app/base/
EXPOSE 25500
ENV LISTEN=0.0.0.0
ENV PORT=25500
CMD ["subconverter"]
