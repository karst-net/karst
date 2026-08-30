#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.

"""Read the executable steps of docs/GETTING-STARTED.md out of the document.

The walkthrough jobs in CI run paths A, B and C by *extracting the commands
from the document and running those*, rather than from a script that repeats
them. That distinction is the entire point. A hand-written copy of the
walkthrough drifts from the document at the same rate the document drifts from
the code, and buys a second thing to maintain in exchange for catching
nothing.

# The tag

Every fenced block in the document carries a `walkthrough=` tag in its info
string, and `check` fails if one does not — so a block added without a tag
fails CI rather than quietly falling outside the test.

    ```sh walkthrough=A step=genkey
    ```toml walkthrough=B,C step=node-config file=karstd.toml
    ```toml walkthrough=A step=peer-config file=karstd.toml append=1
    ```sh walkthrough=A step=start bg=1
    ```sh walkthrough=none reason="long-running dev servers"

    walkthrough=  the paths this block belongs to, or `none`
    step=         a name unique within each of its paths (required unless none)
    file=         write the body to this file instead of executing it
    append=1      append rather than truncate; only with file=
    bg=1          the block's last line does not return; background it
    reason=       why this block is not executed (required with none)

`none` is not an escape hatch, it is the honest half of the record: a block
that cannot run — a diagram, a prerequisite the runner image already
satisfies, `watch`, a command that needs an identity provider — says so in the
document, next to itself, with its reason.

# Substitution

The document is written for a reader with two hosts and a public address.
`emit` rewrites it for the fixture in two passes:

  1. Literal replacement from the JSON object in `WT_SUBST`, which the runner
     owns: `/etc/karst` for a per-node directory in path A, `203.0.113.7` for
     the address the fixture's relay actually answers on, and so on.

  2. Placeholder resolution, in `file=` blocks only. The document writes the
     values a reader must paste in as ellipses — `server_kem_pin = "…2368 hex
     characters…"` — so any quoted value containing `…` is replaced by the
     environment variable named after its key: `WTP_server_kem_pin`. An
     unresolvable placeholder is a hard error naming the key, which means a
     new field in the document fails loudly here instead of being written to a
     configuration file as a literal ellipsis.

Placeholder resolution is deliberately *not* applied to command blocks: their
ellipses are sample output in comments, and the `pubkey` step's own comments
show the very values it exists to produce.
"""

import json
import os
import re
import sys

PATHS = ("A", "B", "C")

# The document under test. Set by main(); a module-level name because every
# error message names a file and a line in it, and hard-coding the path meant
# `WT_DOC=/tmp/other.md check` reported problems against a file it had not
# read — which is exactly the sort of misdirection this tool exists to prevent
# elsewhere.
DOC = "docs/GETTING-STARTED.md"

FENCE = re.compile(r"^(?P<quote>> )?(?P<ticks>```+)(?P<info>.*)$")

# A quoted value with an ellipsis in it, keyed by the field it is assigned to,
# in either TOML (`key = "…"`) or JSON (`"key": "…"`).
#
# **Deliberately not anchored to the start of a line.** management.json's
# TURNConfig puts four fields on one line, `"Secret": "…"` among them, and an
# anchored pattern silently left that ellipsis in place — producing a
# configuration file that parses, starts a server, and hands out TURN
# credentials derived from the literal string "…".
PLACEHOLDER = re.compile(
    r'(?:"(?P<jkey>[^"]+)"|(?P<tkey>[A-Za-z_][\w-]*))(?P<sep>\s*[:=]\s*)"(?P<val>[^"]*…[^"]*)"'
)


class Block:
    def __init__(self, line, lang, attrs, body):
        self.line = line
        self.lang = lang
        self.attrs = attrs
        self.body = body

    @property
    def paths(self):
        raw = self.attrs.get("walkthrough", "")
        return [] if raw == "none" else [p.strip() for p in raw.split(",") if p.strip()]

    @property
    def step(self):
        return self.attrs.get("step", "")


def parse_info(info):
    """Split a fence info string into a language and a dict of attributes.

    Values may be bare or double-quoted; `reason="…"` routinely contains
    spaces, and a bare split would truncate it at the first one.
    """
    info = info.strip()
    attrs = {}
    lang = ""
    token = re.compile(r'(?P<key>[A-Za-z_][\w-]*)=(?:"(?P<quoted>[^"]*)"|(?P<bare>\S*))')
    pos = 0
    first = True
    while pos < len(info):
        if info[pos].isspace():
            pos += 1
            continue
        m = token.match(info, pos)
        if m:
            attrs[m.group("key")] = m.group("quoted") if m.group("quoted") is not None else m.group("bare")
            pos = m.end()
            continue
        end = info.find(" ", pos)
        end = len(info) if end < 0 else end
        if first:
            lang = info[pos:end]
        first = False
        pos = end
    return lang, attrs


def load(path):
    """Every fenced block in the document, in order.

    Blocks are found by walking rather than by regex over the whole file,
    because a closing fence is only a closing fence while a block is open —
    the four backticks that would open one inside a body do not close it.
    """
    blocks = []
    lines = open(path, encoding="utf-8").read().split("\n")
    i = 0
    while i < len(lines):
        m = FENCE.match(lines[i])
        if not m:
            i += 1
            continue
        opened_at = i + 1
        quote, ticks = m.group("quote") or "", m.group("ticks")
        lang, attrs = parse_info(m.group("info"))
        body = []
        i += 1
        while i < len(lines):
            close = FENCE.match(lines[i])
            if close and close.group("ticks") == ticks and not close.group("info").strip():
                break
            line = lines[i]
            # A block inside a blockquote — §5's hex-conversion warning is one
            # — carries the quote marker on every line of its body.
            if quote and line.startswith("> "):
                line = line[2:]
            elif quote and line == ">":
                line = ""
            body.append(line)
            i += 1
        blocks.append(Block(opened_at, lang, attrs, body))
        i += 1
    return blocks


def check(blocks):
    """Every block is accounted for, and no path has two steps with one name."""
    problems = []
    seen = {p: {} for p in PATHS}
    for b in blocks:
        where = f"{DOC}:{b.line}"
        tag = b.attrs.get("walkthrough")
        if tag is None:
            problems.append(
                f"{where}: ```{b.lang} has no walkthrough= tag. Every fenced block "
                f"needs one: a path and a step, or `walkthrough=none reason=\"…\"`."
            )
            continue
        if tag == "none":
            if not b.attrs.get("reason"):
                problems.append(f"{where}: walkthrough=none needs a reason=\"…\"")
            if b.attrs.get("step"):
                problems.append(f"{where}: walkthrough=none cannot also have a step")
            continue
        unknown = [p for p in b.paths if p not in PATHS]
        if unknown:
            # `continue`, not just a report: the duplicate-step check below
            # indexes `seen` by path, and falling through raised a KeyError
            # traceback over the top of the diagnosis it had just made.
            problems.append(f"{where}: unknown path(s) {unknown}; expected any of {list(PATHS)}")
            continue
        if not b.step:
            problems.append(f"{where}: walkthrough={tag} needs a step=")
            continue
        if b.attrs.get("append") and not b.attrs.get("file"):
            problems.append(f"{where}: append=1 only means something with file=")
        if b.attrs.get("bg") and b.attrs.get("file"):
            problems.append(f"{where}: bg=1 and file= are mutually exclusive")
        for p in b.paths:
            if b.step in seen[p]:
                problems.append(
                    f"{where}: path {p} already has a step named {b.step!r} "
                    f"at line {seen[p][b.step]}"
                )
            seen[p][b.step] = b.line
    return problems


def substitute(block, body):
    literal = json.loads(os.environ.get("WT_SUBST", "{}"))
    # **One pass, not one pass per rule.** Path A gives the two nodes mirrored
    # substitutions — 10.77.0.1 becomes .2 and .2 becomes .1 — and applying
    # those in sequence turns every address into the second rule's output. The
    # alternation is built longest-key-first so that a rule for `/etc/karst`
    # is not pre-empted by one for `/etc`.
    literal_re = None
    if literal:
        literal_re = re.compile("|".join(re.escape(k) for k in sorted(literal, key=len, reverse=True)))
    out = []
    for line in body:
        if literal_re:
            line = literal_re.sub(lambda m: literal[m.group(0)], line)
        if block.attrs.get("file"):
            line = PLACEHOLDER.sub(lambda m: resolve(block, m), line)
        out.append(line)
    return out


def resolve(block, m):
    """One placeholder, replaced by the environment variable named for its key."""
    key = m.group("jkey") or m.group("tkey")
    var = "WTP_" + key
    if var not in os.environ:
        sys.exit(
            f"getting-started-blocks: {DOC}:{block.line} "
            f"({block.step}) has a placeholder for {key!r} and {var} is not set. "
            f"The runner has to learn this value from an earlier step and export it."
        )
    quoted = f'"{key}"' if m.group("jkey") else key
    return f'{quoted}{m.group("sep")}"{os.environ[var]}"'


def find(blocks, path, step):
    for b in blocks:
        if path in b.paths and b.step == step:
            return b
    sys.exit(f"getting-started-blocks: path {path} has no step named {step!r}")


def main():
    global DOC
    DOC = os.environ.get("WT_DOC", DOC)
    if len(sys.argv) < 2:
        sys.exit(__doc__.strip().split("\n")[0])
    blocks = load(DOC)
    cmd = sys.argv[1]

    if cmd == "check":
        problems = check(blocks)
        for p in problems:
            print(f"::error::{p}" if os.environ.get("GITHUB_ACTIONS") else p, file=sys.stderr)
        if problems:
            sys.exit(1)
        tagged = sum(1 for b in blocks if b.attrs.get("walkthrough") != "none")
        print(f"{len(blocks)} fenced blocks, all tagged; {tagged} are executed by a path")
        for p in PATHS:
            steps = [b.step for b in blocks if p in b.paths]
            print(f"  path {p}: {len(steps)} steps — {' '.join(steps)}")
        return

    if cmd == "list":
        path = sys.argv[2]
        for b in blocks:
            if path in b.paths:
                print(b.step)
        return

    if cmd == "attrs":
        b = find(blocks, sys.argv[2], sys.argv[3])
        # The destination is substituted like everything else, so that path A's
        # `/etc/karst/karstd.toml` lands in the per-node directory the same
        # `private_key_file` inside it points at. Emitting the raw path here
        # and substituting it in the shell would be two places that have to
        # agree about the mapping.
        dest = substitute(b, [b.attrs["file"]])[0] if b.attrs.get("file") else ""
        print(f"WT_FILE={dest}")
        print(f"WT_APPEND={b.attrs.get('append', '')}")
        print(f"WT_BG={b.attrs.get('bg', '')}")
        print(f"WT_LINE={b.line}")
        return

    if cmd == "emit":
        b = find(blocks, sys.argv[2], sys.argv[3])
        print("\n".join(substitute(b, b.body)))
        return

    sys.exit(f"getting-started-blocks: unknown command {cmd!r}")


if __name__ == "__main__":
    main()
