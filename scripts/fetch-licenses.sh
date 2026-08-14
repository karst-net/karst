#!/usr/bin/env bash
# Canonical licence texts must be fetched, never transcribed by hand.
set -euo pipefail
cd "$(dirname "$0")/../LICENSES"
curl -fsSLo MIT.txt        https://spdx.org/licenses/MIT.txt
curl -fsSLo Apache-2.0.txt https://spdx.org/licenses/Apache-2.0.txt
curl -fsSLo AGPL-3.0.txt   https://www.gnu.org/licenses/agpl-3.0.txt
curl -fsSLo CC-BY-4.0.txt  https://spdx.org/licenses/CC-BY-4.0.txt
echo "Fetched 4 licence texts."
