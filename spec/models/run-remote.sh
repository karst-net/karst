#!/usr/bin/env bash
# SPDX-License-Identifier: CC-BY-4.0
#
# Run the ProVerif suite on a machine that will still be alive in an hour.
#
# The broken-primitive variants take minutes to hours and MUST NOT be run on a
# transient VM — a killed run is indistinguishable from a model that does not
# terminate, which is exactly the confusion this script exists to prevent.
#
#   ./run-remote.sh lovelace
#   ./run-remote.sh turing
#
# Results land in results/<host>-<model>.out and a summary is printed.
set -euo pipefail

HOST="${1:?usage: run-remote.sh <ssh-host>}"
REMOTE_DIR="karst-verify-$(date +%Y%m%d-%H%M%S)"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$HERE/results"

echo "==> Checking $HOST for proverif"
if ! ssh -o BatchMode=yes "$HOST" 'command -v proverif' >/dev/null 2>&1; then
    cat >&2 <<'MSG'
proverif not found on the remote host.

Install without root (the opam package pulls in lablgtk -> libgtk2.0-dev, which
needs root and is only used for the GUI; building from source avoids it):

    opam init --bare -y --no-setup --disable-sandboxing
    opam switch create pv ocaml-base-compiler.5.2.0 -y --no-depexts
    eval "$(opam env --switch=pv)"
    opam install -y --no-depexts ocamlfind ocamlbuild
    curl -fsSLO https://bblanche.gitlabpages.inria.fr/proverif/proverif2.05.tar.gz
    tar xzf proverif2.05.tar.gz && cd proverif2.05 && ./build
    install -m755 proverif ~/.local/bin/
MSG
    exit 1
fi

echo "==> Copying models"
ssh -o BatchMode=yes "$HOST" "mkdir -p ~/$REMOTE_DIR"
scp -q -o BatchMode=yes "$HERE"/*.pv "$HERE"/gen-variants.sh "$HOST:~/$REMOTE_DIR/"
ssh -o BatchMode=yes "$HOST" "cd ~/$REMOTE_DIR && ./gen-variants.sh"

# Base model first: fast, and a failure there invalidates the rest.
for m in phreatic phreatic-kem-broken; do
    echo "==> $m (nohup, detached)"
    ssh -o BatchMode=yes "$HOST" \
        "cd ~/$REMOTE_DIR && nohup nice -n 10 proverif $m.pv > $m.out 2>&1 &"
done

cat <<MSG

Launched detached on $HOST in ~/$REMOTE_DIR.

Expected: phreatic ~seconds,
phreatic-kem-broken may not terminate at all (see spec/models/README.md).

Collect with:
    ./collect-remote.sh $HOST $REMOTE_DIR
MSG
