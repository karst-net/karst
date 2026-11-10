# syntax=docker/dockerfile:1
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.

# Build from the repository root:
#   docker build -f deploy/images/karst-estavelle.Dockerfile -t ghcr.io/karst-net/karst-estavelle:dev .
FROM rust:1.89-bookworm AS build
RUN apt-get update \
    && apt-get install --no-install-recommends -y libprotobuf-dev protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY bins ./bins
COPY server/shared/management/proto ./server/shared/management/proto
RUN cp -R /usr/include/google ./server/shared/management/proto/google
# See karstd.Dockerfile's identical step for why the binary is copied out of
# the cache mount before it is torn down, and what each mount caches.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --locked --release --package karst-estavelle \
    && cp /src/target/release/karst-estavelle /usr/local/bin/karst-estavelle-built

FROM debian:bookworm-slim
ARG KARST_VERSION=development
ARG KARST_REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/karst-net/karst" \
      org.opencontainers.image.version="${KARST_VERSION}" \
      org.opencontainers.image.revision="${KARST_REVISION}"
RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /etc/karst
COPY --from=build /usr/local/bin/karst-estavelle-built /usr/local/bin/karst-estavelle
EXPOSE 443
ENTRYPOINT ["/usr/local/bin/karst-estavelle"]
CMD ["--config", "/etc/karst/estavelle.toml"]
