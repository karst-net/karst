# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright the Karst contributors.

# Build from the repository root:
#   docker build -f deploy/images/karst-control.Dockerfile -t ghcr.io/karst-net/karst-control:dev .
#
# The coordination server: the forked NetBird management daemon with
# KarstControlService attached (ADR-0011). See server/cmd/karst-control.

# GOTOOLCHAIN=auto fetches the version server/go.mod pins rather than pinning it
# a second time here. crypto/mldsa is a 1.27 addition and 1.27.0 is not out, so
# the required toolchain is a release candidate with no official base image;
# duplicating that fact in this file would leave two places to update and one of
# them silently stale.
FROM golang:1.26-bookworm AS build
ENV GOTOOLCHAIN=auto
WORKDIR /src

# Dependencies first, so editing server code does not re-download the module
# graph. This fork's graph is large enough for that to matter.
COPY server/go.mod server/go.sum ./
RUN go mod download

COPY server/ ./
# CGO on, deliberately. The SQLite store is go-sqlite3, which is a cgo binding:
# built with CGO_ENABLED=0 it compiles and links into a working-looking binary
# that dies at first use with "Binary was compiled with 'CGO_ENABLED=0' ... This
# is a stub". The runtime image below is glibc-based for the same reason.
RUN CGO_ENABLED=1 go build -trimpath -o /out/karst-control ./cmd/karst-control

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /etc/netbird /var/lib/netbird /etc/karst
COPY --from=build /out/karst-control /usr/local/bin/karst-control

# 33073 is the gRPC port both the NetBird agent and KarstControlService use.
EXPOSE 33073
ENTRYPOINT ["/usr/local/bin/karst-control"]
CMD ["management", "--config", "/etc/netbird/management.json", \
     "--datadir", "/var/lib/netbird", "--port", "33073", "--log-file", "console"]
