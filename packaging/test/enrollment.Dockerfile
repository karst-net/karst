# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
# Disposable desktop for exercising the installed client under real systemd.
ARG BASE_IMAGE=ubuntu:24.04
FROM ${BASE_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends \
    systemd dbus dbus-x11 iproute2 ca-certificates zenity pkexec polkitd \
    xvfb xauth xdotool xclip openbox sudo python3 policykit-1-gnome imagemagick \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --create-home --groups sudo enrollment-test \
    && echo 'enrollment-test:test-password' | chpasswd
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
