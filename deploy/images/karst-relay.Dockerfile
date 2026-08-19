# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.

# Build from the repository root:
#   docker build -f deploy/images/karst-relay.Dockerfile -t ghcr.io/karst-net/karst-relay:dev .
FROM rust:1.88-bookworm AS build
RUN apt-get update \
    && apt-get install --no-install-recommends -y libprotobuf-dev protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY bins ./bins
COPY server/shared/management/proto ./server/shared/management/proto
RUN cp -R /usr/include/google ./server/shared/management/proto/google
RUN cargo build --locked --release --package karst-relay

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /etc/karst
COPY --from=build /src/target/release/karst-relay /usr/local/bin/karst-relay
EXPOSE 443
ENTRYPOINT ["/usr/local/bin/karst-relay"]
CMD ["--config", "/etc/karst/relay.toml"]
