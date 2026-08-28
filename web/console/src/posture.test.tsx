// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { renderToStaticMarkup } from "react-dom/server";
import { expect, test } from "vitest";
import type { SessionPosture } from "@karst-net/api-client";
import { Observed, Status } from "@karst-net/ui";
import { filterSessions } from "./posture";

test("status communicates its state with a shape and text", () => {
  const markup = renderToStaticMarkup(<Status state="warning" label="Lattice only" />);
  expect(markup).toContain("▲");
  expect(markup).toContain("Lattice only");
});

test("observations retain machine-readable time and a human-readable age", () => {
  const markup = renderToStaticMarkup(<Observed at="2026-08-22T20:32:00Z" />);
  expect(markup).toContain('dateTime="2026-08-22T20:32:00Z"');
  expect(markup).toContain("ago");
});

const rows: SessionPosture[] = [
  { node_handle: "one", peer_handle: "two", status: "pq", lattice_only: false, observed_at: "2026-08-22T20:32:00Z" },
  { node_handle: "three", peer_handle: "four", status: "lattice_only", lattice_only: true, observed_at: "2026-08-22T20:32:00Z" },
  { node_handle: "five", peer_handle: "six", status: "stale", lattice_only: false, observed_at: "2026-08-22T19:02:00Z" },
];

test("posture filtering does not silently include a different category", () => {
  expect(filterSessions(rows, "lattice_only")).toEqual([rows[1]]);
  expect(filterSessions(rows, "all")).toHaveLength(3);
});

test("exceptions means every non-compliant category, not just lattice-only", () => {
  // Defaulting to lattice_only alone hid stale sessions behind a filter the
  // auditor would have had to know to construct.
  expect(filterSessions(rows, "exceptions").map((row) => row.status)).toEqual(["stale", "lattice_only"]);
});

test("worst sorts first, so the compliant rows never head the table", () => {
  expect(filterSessions(rows, "all").map((row) => row.status)).toEqual(["stale", "lattice_only", "pq"]);
});
