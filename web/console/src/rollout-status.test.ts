// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { expect, test } from "vitest";
import type { RolloutPlan } from "@karst-net/api-client";
import { rolloutStatus } from "./rollout-status";

const plan = (state: RolloutPlan["state"], extra: Partial<RolloutPlan> = {}): RolloutPlan =>
  ({ target_release: "v0.9.0", components: [], state, ...extra });

test("planned and in_progress both render unknown, not a false positive", () => {
  expect(rolloutStatus(plan("planned")).state).toBe("unknown");
  expect(rolloutStatus(plan("in_progress")).state).toBe("unknown");
});

test("completed is the only healthy state", () => {
  expect(rolloutStatus(plan("completed")).state).toBe("healthy");
});

test("rolled_back is a warning, not failed and not healthy", () => {
  expect(rolloutStatus(plan("rolled_back")).state).toBe("warning");
});

test("failed carries the component and reason in its own label, never silently hidden", () => {
  const label = rolloutStatus(plan("failed", { failed_component: "control", failure_reason: "nomad job run failed" })).label;
  expect(label).toContain("control");
  expect(label).toContain("nomad job run failed");
  expect(rolloutStatus(plan("failed")).state).toBe("danger");
});

test("a failure with no reported reason still says so rather than showing nothing", () => {
  expect(rolloutStatus(plan("failed")).label).toContain("no reason reported");
});
