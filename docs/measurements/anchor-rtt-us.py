#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
"""One-shot US anchor measurement using the actual karstd Rust probe functions.

Requires rustc and matplotlib. Run from any directory with Python 3.
Outputs raw CSV, summary CSV, metadata JSON, PNG and SVG in --output.
"""
import argparse
import csv
import datetime as dt
import hashlib
import json
import platform
from pathlib import Path
import statistics
import subprocess
import tempfile
import time

REGIONS = {
    "aws": "us-east-1 us-east-2 us-west-1 us-west-2".split(),
    "azure": "centralus eastus eastus2 northcentralus southcentralus westcentralus westus westus2 westus3".split(),
    "gcp": "us-central1 us-east1 us-east4 us-east5 us-south1 us-west1 us-west2 us-west3 us-west4".split(),
}
SOURCES = [
    "https://docs.aws.amazon.com/global-infrastructure/latest/regions/aws-regions.html",
    "https://learn.microsoft.com/en-us/azure/reliability/regions-list",
    "https://docs.cloud.google.com/storage/docs/locations",
]
BUCKETS = ["<20 ms", "20–<50 ms", "50–<100 ms", "≥100 ms"]


def rust_function(source, name):
    """Extract these simple functions verbatim, failing if the source changes."""
    start = source.index(f"fn {name}(")
    brace = source.index("{", start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=20)
    parser.add_argument("--interval", type=float, default=1.0,
                        help="Pause between serial passes (seconds)")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.samples < 1 or args.interval < 0:
        parser.error("samples must be positive and interval nonnegative")
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    repo = Path(__file__).resolve().parents[2]
    source = (repo / "bins/karstd/src/anchor_probe.rs").read_text()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    harness = "use std::net::{TcpStream, ToSocketAddrs as _};\nuse std::time::{Duration, Instant};\n"
    for name in ["PROBE_BUDGET", "PROBE_PORT"]:
        harness += next(line for line in source.splitlines() if line.startswith(f"const {name}:")) + "\n"
    for name in ["anchor_hostname", "azure_anchor", "azure_anchor_fallback", "probe", "rtt_ms"]:
        harness += rust_function(source, name) + "\n"
    harness += '''
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let host = anchor_hostname(&args[1], &args[2]).expect("supported provider");
    match probe(&host) {
        Some(rtt) => println!("{},{:.6},{}", host, rtt.as_secs_f64()*1000.0, rtt_ms(rtt)),
        None => println!("{},,", host),
    }
}
'''
    rows = []
    with tempfile.TemporaryDirectory(prefix="karst-anchor-rtt-") as work:
        rust = Path(work) / "probe.rs"
        rust.write_text(harness)
        executable = Path(work) / "probe"
        subprocess.run(["rustc", "--edition=2021", "-O", str(rust), "-o", str(executable)], check=True)
        with (out / "raw.csv").open("w", newline="") as f:
            writer = csv.writer(f, lineterminator="\n")
            writer.writerow(["utc", "pass", "provider", "region", "anchor", "elapsed_ms", "reported_rtt_ms", "status"])
            targets = [(p, r) for p, regions in REGIONS.items() for r in regions]
            for sample in range(args.samples):
                # Rotate the first target to reduce consistent ordering bias.
                offset = sample % len(targets)
                for provider, region in targets[offset:] + targets[:offset]:
                    stamp = dt.datetime.now(dt.timezone.utc).isoformat()
                    result = subprocess.run([str(executable), provider, region], check=True,
                                            capture_output=True, text=True, timeout=30)
                    anchor, elapsed, reported = result.stdout.strip().split(",")
                    row = [stamp, sample + 1, provider, region, anchor, elapsed, reported,
                           "ok" if reported else "unmeasured"]
                    rows.append(row)
                    writer.writerow(row)
                    f.flush()
                print(f"Pass {sample + 1}/{args.samples} complete", flush=True)
                if sample + 1 < args.samples:
                    time.sleep(args.interval)
    metadata = dict(started_utc=started, finished_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
                    host=platform.node(), platform=platform.platform(),
                    commit=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip(),
                    probe_source_sha256=hashlib.sha256(source.encode()).hexdigest(),
                    samples_per_region=args.samples, interval_seconds=args.interval,
                    regions=REGIONS, region_sources=SOURCES,
                    method="Verbatim Rust hostname/probe/rtt_ms functions; first DNS address; TCP 443; 1s connect timeout; DNS excluded. Serial probes. Milliseconds truncated as in client. No TLS or HTTP.",
                    scope="Public commercial US regions; excludes government partitions and local zones. One host, short sample window; production interval is 15 minutes.")
    (out / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    summaries = []
    with (out / "summary.csv").open("w", newline="") as f:
        writer = csv.writer(f, lineterminator="\n")
        writer.writerow(["provider", "region", "success", "unmeasured", "min_ms", "median_ms", "max_ms", *BUCKETS])
        for provider, regions in REGIONS.items():
            for region in regions:
                matching = [r for r in rows if r[2:4] == [provider, region]]
                values = [float(r[5]) for r in matching if r[7] == "ok"]
                counts = [0] * 4
                for r in matching:
                    if r[7] == "ok":
                        value = int(r[6])
                        counts[sum(value >= b for b in [20, 50, 100])] += 1
                stats = [min(values), statistics.median(values), max(values)] if values else [None]*3
                entry = [provider, region, len(values), len(matching)-len(values), *stats, *counts]
                summaries.append(entry)
                writer.writerow(entry)

    colors = ["#15803d", "#0e7490", "#d97706", "#be123c"]
    fig, axes = plt.subplots(1, 3, figsize=(17, 7), gridspec_kw={"width_ratios": [1, 1.3, 1.2]})
    for ax, provider in zip(axes, REGIONS):
        entries = [s for s in summaries if s[0] == provider]
        positions = list(range(len(entries)))
        left = [0]*len(entries)
        for i, (label, color) in enumerate(zip(BUCKETS, colors)):
            counts = [s[7+i] for s in entries]
            ax.barh(positions, counts, left=left, color=color, label=label)
            for y, n, start in zip(positions, counts, left):
                if n:
                    ax.text(start+n/2, y, str(n), ha="center", va="center", color="white", fontsize=9)
            left = [a+b for a, b in zip(left, counts)]
        ax.barh(positions, [s[3] for s in entries], left=left, color="#d1d5db", label="Unmeasured")
        ax.set_yticks(positions, [s[1] for s in entries])
        ax.invert_yaxis()
        ax.set_xlim(0, args.samples)
        ax.set_title(provider.upper(), fontweight="bold")
        ax.set_xlabel("Observations per region")
        ax.spines[["top", "right"]].set_visible(False)
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", ncol=5, frameon=False, bbox_to_anchor=(0.5, 0.04))
    fig.suptitle("US cloud regions · TCP RTT histogram", fontsize=21, fontweight="bold", y=0.98)
    fig.text(0.5, 0.91, f"Source: {platform.node()}  |  {started[:10]} UTC  |  {args.samples} probes per region  |  issue #234 bucket boundaries", ha="center")
    fig.text(0.5, 0.01, "TCP connect only, DNS excluded · One source host; short-run observations, not fleet demand · Government regions excluded", ha="center", fontsize=10)
    fig.tight_layout(rect=(0, 0.11, 1, 0.89), w_pad=3)
    fig.savefig(out / "histogram.png", dpi=180)
    fig.savefig(out / "histogram.svg")
    svg = out / "histogram.svg"
    svg.write_text("\n".join(line.rstrip() for line in svg.read_text().splitlines()) + "\n")
    print(json.dumps(summaries, indent=2))


if __name__ == "__main__":
    main()
