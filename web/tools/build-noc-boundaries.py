#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright the Karst contributors.
"""Trim Natural Earth admin-1 lines for the NOC's bundled basemap.

Usage: python3 web/tools/build-noc-boundaries.py input.geojson output.geojson
Source and precision are documented in console/public/noc-boundaries.md.
"""

import json
import sys


def simplify(points, tolerance=0.02):
    """Douglas-Peucker in source degrees, preserving each line's endpoints."""
    keep = {0, len(points) - 1}
    pending = [(0, len(points) - 1)]
    while pending:
        start, end = pending.pop()
        ax, ay = points[start]
        bx, by = points[end]
        dx, dy = bx - ax, by - ay
        length = dx * dx + dy * dy
        farthest, distance = start, tolerance * tolerance
        for index in range(start + 1, end):
            x, y = points[index]
            t = max(0, min(1, ((x - ax) * dx + (y - ay) * dy) / length)) if length else 0
            squared = (x - ax - t * dx) ** 2 + (y - ay - t * dy) ** 2
            if squared > distance:
                farthest, distance = index, squared
        if farthest != start:
            keep.add(farthest)
            pending.extend([(start, farthest), (farthest, end)])
    return [[round(value, 3) for value in points[index]] for index in sorted(keep)]


def build(source):
    features = []
    for feature in source["features"]:
        geometry = feature["geometry"]
        if geometry is None:
            continue
        kind = geometry["type"]
        if kind == "LineString":
            coordinates = simplify(geometry["coordinates"])
        elif kind == "MultiLineString":
            coordinates = [simplify(line) for line in geometry["coordinates"]]
        else:
            raise ValueError(f"Unexpected geometry: {kind}")
        features.append({"type": "Feature", "properties": {}, "geometry": {"type": kind, "coordinates": coordinates}})
    return {"type": "FeatureCollection", "features": features}


if __name__ == "__main__":
    with open(sys.argv[1]) as source:
        result = build(json.load(source))
    with open(sys.argv[2], "w") as output:
        json.dump(result, output, separators=(",", ":"))
        output.write("\n")
