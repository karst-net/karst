// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { expect, test } from "vitest";
import { sessionsCsv } from "./csv";

test("exports session data with escaped cells", () => {
  expect(sessionsCsv([{ node_handle: "node-1", peer_handle: "node-2", status: "pq", suite: "suite \"A\"", psk_epoch: 7, observed_at: "2026-08-22T20:32:00Z" }])).toContain('"suite ""A"""');
});
