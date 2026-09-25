# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# The lab peer: the ordinary karstd image plus what the fixtures need.
ARG KARST_LAB_TAG
FROM karst-ne-lab/karstd:${KARST_LAB_TAG}
RUN apt-get update \
    && apt-get install --no-install-recommends -y iproute2 iptables python3 \
    && rm -rf /var/lib/apt/lists/*
COPY peer-entrypoint.sh peer-fixtures.py /usr/local/libexec/
ENTRYPOINT ["/bin/sh", "/usr/local/libexec/peer-entrypoint.sh"]
