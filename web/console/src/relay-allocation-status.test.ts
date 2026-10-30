// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { expect, test } from "vitest";
import type { RelayAllocation } from "@karst-net/api-client";
import { allocationStatus } from "./relay-allocation-status";

const allocation = (state: RelayAllocation["state"], extra: Partial<RelayAllocation> = {}): RelayAllocation =>
  ({ name: "denver", infra_connection_id: "conn-1", location: "us-west-2", permitted_groups: ["engineering"], state, ...extra });

test("every non-terminal state renders unknown, not a false positive", () => {
  expect(allocationStatus(allocation("requested")).state).toBe("unknown");
  expect(allocationStatus(allocation("provisioning")).state).toBe("unknown");
  expect(allocationStatus(allocation("granting")).state).toBe("unknown");
  expect(allocationStatus(allocation("deprovisioned")).state).toBe("unknown");
});

test("ready is the only healthy state", () => {
  expect(allocationStatus(allocation("ready")).state).toBe("healthy");
});

test("teardown in progress is a warning, not ready and not failed", () => {
  expect(allocationStatus(allocation("revoking")).state).toBe("warning");
  expect(allocationStatus(allocation("deprovisioning")).state).toBe("warning");
});

test("failed carries the step and reason in its own label, never silently hidden", () => {
  const label = allocationStatus(allocation("failed", { failed_step: "granting", failure_reason: "quota exceeded" })).label;
  expect(label).toContain("granting");
  expect(label).toContain("quota exceeded");
  expect(allocationStatus(allocation("failed")).state).toBe("danger");
});

test("a failure with no reported reason still says so rather than showing nothing", () => {
  expect(allocationStatus(allocation("failed")).label).toContain("no reason reported");
});
