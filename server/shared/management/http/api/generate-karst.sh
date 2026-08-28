#!/bin/bash
set -euo pipefail

script_path=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$script_path"
# Keep the generator version aligned with generate.sh without requiring a
# mutable global Go bin. `go run` uses the module cache after its first run.
go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.7.1 \
	--config karst-cfg.yaml karst-openapi.yml
sed -i '1i// SPDX-License-Identifier: AGPL-3.0-or-later\n// Copyright the Karst contributors.\n' karst/types.gen.go
gofmt -w karst/types.gen.go
