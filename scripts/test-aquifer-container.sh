#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
# Run real namespace tests without changing the host's forwarding or DNS state.
set -euo pipefail
repo_dir=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo_dir"
products=$(mktemp -d "${TMPDIR:-/tmp}/karst-aquifer-products.XXXXXXXX")
trap 'rm -rf "$products"' EXIT
cargo build --locked -p karstd -p karst-cli -p karst-relay
cargo test --locked -p karstd --test aquifer --no-run --message-format=json > "$products/artifacts.jsonl"
python3 - "$products" <<'PY'
import json
from pathlib import Path
import shutil
import sys
products = Path(sys.argv[1])
executables = [row["executable"] for line in (products / "artifacts.jsonl").read_text().splitlines()
               if (row := json.loads(line)).get("reason") == "compiler-artifact"
               and row.get("target", {}).get("name") == "aquifer" and row.get("executable")]
if len(executables) != 1:
    raise SystemExit("expected exactly one compiled aquifer test executable")
shutil.copy2(executables[0], products / "aquifer")
# The executable is target/<profile>/deps/aquifer-HASH, so these are the
# products from that same build even when CARGO_TARGET_DIR is customized.
profile = Path(executables[0]).parent.parent
for name in ("karstd", "karst", "karst-relay"):
    shutil.copy2(profile / name, products / name)
(products / "artifacts.jsonl").unlink()
PY
# SQLite's inherited driver needs CGO; building outside the runtime image also
# avoids mounting the repository, Go module cache or deployment credentials.
(cd server && CGO_ENABLED=1 go build -o "$products/karst-testserver" ./management/internals/karst/testserver/)
image=${KARST_AQUIFER_TEST_IMAGE:-karst-aquifer-test:local}
docker build -t "$image" deploy/lab/aquifer
docker run --rm --network none \
    --cap-add NET_ADMIN --cap-add SYS_ADMIN \
    --security-opt apparmor=unconfined --security-opt seccomp=unconfined \
    --device /dev/net/tun \
    --mount "type=bind,src=$products,dst=/products,readonly" \
    -e KARST_AQUIFER_BIN_DIR=/products \
    -e KARST_AQUIFER_TESTSERVER=/products/karst-testserver \
    -e KARST_REQUIRE_PREREQUISITES=1 \
    "$image" sh -ec '
        # Docker masks sysctls read-only. Only expose network sysctls; these
        # fixtures write them inside their own network namespaces.
        mount --bind /proc/sys/net /proc/sys/net
        mount -o remount,bind,rw /proc/sys/net
        exec /products/aquifer "$@" --ignored --test-threads=1 --nocapture
    ' aquifer "$@"
