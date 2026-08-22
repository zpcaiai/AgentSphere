# syntax=docker/dockerfile:1.7
FROM rust:1.89.0-bookworm@sha256:71a7d1555b6c2f193b3f61c689e0263553fc52730f0d60e67fcba9a4b7757c51 AS build
WORKDIR /workspace
COPY Cargo.toml Cargo.lock ./
COPY rust/crates ./rust/crates
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/workspace/target,sharing=locked \
    cargo build --locked --release --package agent-trust-context-governance \
      --bin agenttrust-context-governance-service && \
    install -D -m 0555 /workspace/target/release/agenttrust-context-governance-service \
      /out/agenttrust-context-governance-service

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:4e8f8c7f3622a4a38bb8433ee01a9259a3099e62d35f70a0c8f89bda5bc86f4a
COPY --from=build /out/agenttrust-context-governance-service /usr/local/bin/agenttrust-context-governance-service
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/agenttrust-context-governance-service"]
