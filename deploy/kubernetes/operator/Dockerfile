# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /karst-operator .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /karst-operator /karst-operator
USER 65532:65532
ENTRYPOINT ["/karst-operator"]
