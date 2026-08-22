ARG RUST_BUILDER_IMAGE
ARG RUNTIME_BASE_IMAGE
FROM ${RUST_BUILDER_IMAGE} AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY rust ./rust
RUN cargo build --locked --release -p agent-trust-policy-pep --bin agenttrust-pep-service

FROM ${RUNTIME_BASE_IMAGE}
COPY --from=build /src/target/release/agenttrust-pep-service /usr/local/bin/agenttrust-pep-service
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/agenttrust-pep-service"]
CMD ["--listen", "0.0.0.0", "--port", "8086", "--management-listen", "0.0.0.0", "--management-port", "9096"]
