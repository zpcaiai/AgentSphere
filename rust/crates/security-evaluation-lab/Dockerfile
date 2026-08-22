# syntax=docker/dockerfile:1.7
ARG RUST_BUILDER_IMAGE
ARG RUNTIME_BASE_IMAGE
FROM ${RUST_BUILDER_IMAGE} AS build
WORKDIR /workspace
COPY Cargo.toml Cargo.lock ./
COPY rust/crates ./rust/crates
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/workspace/target,sharing=locked \
    cargo build --locked --release --package agent-trust-security-evaluation-lab \
      --bin agenttrust-security-evaluation-authority && \
    install -D -m 0555 /workspace/target/release/agenttrust-security-evaluation-authority \
      /out/agenttrust-security-evaluation-authority

FROM ${RUNTIME_BASE_IMAGE}
COPY --from=build /out/agenttrust-security-evaluation-authority /usr/local/bin/agenttrust-security-evaluation-authority
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/agenttrust-security-evaluation-authority"]
