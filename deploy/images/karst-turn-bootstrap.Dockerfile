# syntax=docker/dockerfile:1
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.

# ADR-0045 §7b (issue #311): the reference coturn bootstrap #310 named as a
# non-goal. No Karst code runs inside coturn itself -- this wraps the
# official coturn/coturn image with the one script that enrolls this
# instance against /karst/v1/turn/enroll before exec'ing turnserver. See
# karst-turn-bootstrap-entrypoint.sh's own doc comment for the required
# environment variables and docs/operations/scaler-turn-bootstrap.md for
# the operations reference.
#
# Build from the repository root:
#   docker build -f deploy/images/karst-turn-bootstrap.Dockerfile \
#     -t ghcr.io/karst-net/karst-turn-bootstrap:dev .
FROM coturn/coturn:4.6
USER root
# coturn/coturn's own Debian base has no curl -- the entrypoint's only
# dependency beyond what the base image already provides (sh, mktemp).
RUN apt-get update \
    && apt-get install --no-install-recommends -y curl \
    && rm -rf /var/lib/apt/lists/*
COPY deploy/images/karst-turn-bootstrap-entrypoint.sh /usr/local/bin/karst-turn-bootstrap-entrypoint.sh
RUN chmod +x /usr/local/bin/karst-turn-bootstrap-entrypoint.sh
EXPOSE 3478/udp 3478/tcp
ENTRYPOINT ["/usr/local/bin/karst-turn-bootstrap-entrypoint.sh"]
