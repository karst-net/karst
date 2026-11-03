// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import type { StatusState } from "@karst-net/ui";
import type { RolloutPlan } from "@karst-net/api-client";

/** ADR-0066's state machine, rendered the same way relay-allocation-status.ts
 * renders its own — a plain label, not a progress bar: in_progress spans
 * however long the operator takes to run the documented cosign/nomad steps
 * by hand, not a bounded wait control itself is driving. */
export function rolloutStatus(plan: RolloutPlan): { state: StatusState; label: string } {
  switch (plan.state) {
    case "completed": return { state: "healthy", label: "Completed" };
    case "planned": return { state: "unknown", label: "Planned" };
    case "in_progress": return { state: "unknown", label: "In progress" };
    case "rolled_back": return { state: "warning", label: "Rolled back" };
    case "failed": return { state: "danger", label: `Failed${plan.failed_component ? ` at ${plan.failed_component}` : ""}: ${plan.failure_reason || "no reason reported"}` };
    default: return { state: "unknown", label: plan.state ?? "Unknown" };
  }
}
