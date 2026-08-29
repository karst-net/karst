#!/bin/bash
set -e

if ! which realpath > /dev/null 2>&1
then
  echo realpath is not installed
  echo run: brew install coreutils
  exit 1
fi

old_pwd=$(pwd)
script_path=$(dirname $(realpath "$0"))
cd "$script_path"
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.26
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1
export PATH="$(go env GOPATH)/bin:$PATH"
protoc -I ./ ./management.proto --go_out=../ --go-grpc_out=../
protoc -I ./ ./proxy_service.proto --go_out=../ --go-grpc_out=../
protoc -I ./ ./karst_control.proto --go_out=../ --go-grpc_out=../

# protoc-gen-go copies a .proto's leading file comment — SPDX header and all —
# into the .pb.go it produces, which is why karst_control.pb.go carries one and
# needs nothing here. protoc-gen-go-grpc copies nothing, so the _grpc file comes
# out with no identifier at all and fails `just licenses-check` (ADR-0007).
#
# Stamping it here rather than by hand: a header added by hand to a generated
# file is one the next regeneration silently strips, and the failure then
# resurfaces as a license-check error nobody associates with running this
# script. Only Karst's own generated files are stamped — the upstream ones stay
# byte-identical to the fork point.
stamp_spdx() {
  if head -1 "$1" | grep -q 'SPDX-License-Identifier'; then
    return 0
  fi
  { printf '// SPDX-License-Identifier: AGPL-3.0-or-later\n// Copyright the Karst contributors.\n\n'; cat "$1"; } > "$1.spdx"
  mv "$1.spdx" "$1"
}
stamp_spdx karst_control_grpc.pb.go

cd "$old_pwd"
