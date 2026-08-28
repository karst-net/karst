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
RUN cargo build --locked --release --package karstd

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /etc/karst /run/karst
COPY --from=build /src/target/release/karstd /usr/local/bin/karstd

# The Kubernetes DaemonSet deliberately runs this as root with the privileges
# documented there. Keeping the image unopinionated lets other service
# managers make their own capability decision.
ENTRYPOINT ["/usr/local/bin/karstd"]
CMD ["--config", "/etc/karst/karstd.toml"]
