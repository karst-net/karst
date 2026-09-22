# syntax=docker/dockerfile:1
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.

# Build from the repository root:
#   docker build -f deploy/images/karstd.Dockerfile -t ghcr.io/karst-net/karstd:dev .
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
# Cache mounts are BuildKit-local and not part of the resulting layer — a
# binary left inside /src/target would vanish when the mount is torn down,
# so the release build is copied out to an ordinary path in the same RUN
# before that happens. registry/git cache the downloaded crate sources and
# index; target caches compiled (including incremental) build artifacts
# across CI runs, restored via the workflow's `cache-from: type=gha`.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --locked --release --package karstd \
    && cp /src/target/release/karstd /usr/local/bin/karstd-built

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /etc/karst /run/karst
COPY --from=build /usr/local/bin/karstd-built /usr/local/bin/karstd

# The Kubernetes DaemonSet deliberately runs this as root with the privileges
# documented there. Keeping the image unopinionated lets other service
# managers make their own capability decision.
ENTRYPOINT ["/usr/local/bin/karstd"]
CMD ["--config", "/etc/karst/karstd.toml"]
