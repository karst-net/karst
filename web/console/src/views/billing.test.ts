// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { expect, test } from "vitest";
import { formatUsdMinor, parseUsdMinor } from "./billing";

test("USD caps convert to cents exactly and reject excess precision", () => {
  expect(parseUsdMinor("12")).toBe(1200);
  expect(parseUsdMinor("12.3")).toBe(1230);
  expect(parseUsdMinor("12.34")).toBe(1234);
  expect(parseUsdMinor("12.345")).toBeNull();
  expect(parseUsdMinor("-0.01")).toBeNull();
  expect(parseUsdMinor("1e2")).toBeNull();
  expect(formatUsdMinor(1234)).toBe("12.34");
});
