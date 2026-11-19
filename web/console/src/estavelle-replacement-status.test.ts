// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { expect, test } from "vitest";
import type { EstavelleAllocation } from "@karst-net/api-client";
import { replacementStatus } from "./estavelle-replacement-status";

const allocation = (replacementState: EstavelleAllocation["replacement_state"], extra: Partial<EstavelleAllocation> = {}): EstavelleAllocation =>
  ({ name: "denver", infra_connection_id: "conn-1", location: "us-west-2", permitted_groups: ["engineering"], state: "ready", replacement_state: replacementState, ...extra });

test("no replacement in flight renders nothing, not an empty badge", () => {
  expect(replacementStatus(allocation(undefined))).toBeNull();
});

test("provisioning names the desired image being created", () => {
  const status = replacementStatus(allocation("provisioning", { desired_image: "v2" }));
  expect(status?.state).toBe("unknown");
  expect(status?.label).toContain("v2");
});

test("admitting is still unknown, not yet a warning -- the old instance hasn't been touched", () => {
  expect(replacementStatus(allocation("admitting"))?.state).toBe("unknown");
});

test("draining and destroying are warnings -- the old instance is being torn down", () => {
  expect(replacementStatus(allocation("draining"))?.state).toBe("warning");
  expect(replacementStatus(allocation("destroying"))?.state).toBe("warning");
});

test("failed carries the step and reason in its own label, never silently hidden", () => {
  const label = replacementStatus(allocation("failed", { replacement_failed_step: "admitting", replacement_failure_reason: "never admitted" }))?.label;
  expect(label).toContain("admitting");
  expect(label).toContain("never admitted");
  expect(replacementStatus(allocation("failed"))?.state).toBe("danger");
});

test("a failure with no reported reason still says so rather than showing nothing", () => {
  expect(replacementStatus(allocation("failed"))?.label).toContain("no reason reported");
});
