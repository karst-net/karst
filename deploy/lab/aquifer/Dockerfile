# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    iproute2 nftables miniupnpd tayga dnsmasq curl coturn iputils-ping \
    netcat-openbsd ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/*
