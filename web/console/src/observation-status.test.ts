// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { describe, expect, it } from "vitest";
import { observationStatus } from "./observation-status";

const observed = "2026-10-31T18:00:00Z";
const timestamp = Date.parse(observed);

describe("observation freshness", () => {
  it("uses the observation's age, including the stale boundary", () => {
    expect(observationStatus(observed, timestamp)).toBe("Current");
    expect(observationStatus(observed, timestamp + 15 * 60_000)).toBe("Current");
    expect(observationStatus(observed, timestamp + 15 * 60_000 + 1)).toBe("Stale");
  });

  it.each([undefined, null, "", "invalid"])("keeps an absent/invalid observation unknown: %s", (at) => {
    expect(observationStatus(at, timestamp)).toBe("Unknown");
  });

  it("does not treat a far-future observation as current", () => {
    expect(observationStatus(observed, timestamp - 60_000)).toBe("Current");
    expect(observationStatus(observed, timestamp - 60_001)).toBe("Unknown");
  });
});
