# syntax=docker/dockerfile:1.4
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright the Karst contributors.

# Build with the web/ workspace as context, not the repository root -- the
# root .dockerignore excludes all of web/ wholesale (the Rust/Go images never
# need it), and this image's own context only needs web/'s own .dockerignore
# (node_modules, dist) rather than re-litigating the root one:
#   docker build -f deploy/images/karst-console.Dockerfile -t karst-console:dev web
#
# The admin console (console/) packaged as a standalone image, serving the
# same dist/ output .github/workflows/deliverables.yml's web-assets job
# tarballs up for the self-hoster docs -- just behind nginx instead of
# unpacked onto a host. Workspace packages under packages/* are copied in
# full since console depends on them at build time (@karst-net/ui, /tokens,
# /api-client, /auth); portal is a sibling workspace member but is not part
# of this image, and pnpm install is fine with its directory simply absent.

FROM node:24.12.0-bookworm AS build
WORKDIR /src
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages ./packages
COPY console ./console
RUN corepack enable \
    && corepack pnpm install --frozen-lockfile
ARG KARST_VERSION=development
ENV KARST_VERSION=${KARST_VERSION}
RUN corepack pnpm --filter @karst-net/console build

FROM nginx:1.28-alpine
ARG KARST_VERSION=development
ARG KARST_REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/karst-net/karst" \
      org.opencontainers.image.version="${KARST_VERSION}" \
      org.opencontainers.image.revision="${KARST_REVISION}"
COPY --from=build /src/console/dist /usr/share/nginx/html
# A plain SPA static server. Edge concerns (TLS, gzip, /config.json's
# no-cache override, and the /auth, /management, /api, /releases and
# /portal routes) belong to the Caddy in front of this container, per
# deploy/nomad/prod/Caddyfile and deploy/compose/prod/Caddyfile -- this
# just needs to turn any unknown path back into index.html for
# client-side routing to take over.
RUN <<'EOF' cat > /etc/nginx/conf.d/default.conf
server {
    listen 80;
    server_name _;
    root /usr/share/nginx/html;

    location / {
        try_files $uri $uri/ /index.html;
    }
}
EOF
EXPOSE 80
