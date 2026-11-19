// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import type { StatusState } from "@karst-net/ui";
import type { EstavelleAllocation } from "@karst-net/api-client";

/** Issue #560's zero-downtime version replacement, rendered the same plain-
 * label way estavelle-allocation-status.ts renders the main state machine --
 * null means no replacement is in flight, which the caller treats as
 * "nothing extra to show" rather than rendering an empty badge. */
export function replacementStatus(allocation: EstavelleAllocation): { state: StatusState; label: string } | null {
  switch (allocation.replacement_state) {
    case undefined:
      return null;
    case "provisioning": return { state: "unknown", label: `Creating replacement (${allocation.desired_image})` };
    case "admitting": return { state: "unknown", label: "Waiting for replacement to admit" };
    case "draining": return { state: "warning", label: "Draining previous instance" };
    case "destroying": return { state: "warning", label: "Removing previous instance" };
    case "failed": return { state: "danger", label: `Replacement failed${allocation.replacement_failed_step ? ` at ${allocation.replacement_failed_step}` : ""}: ${allocation.replacement_failure_reason || "no reason reported"}` };
    default: return { state: "unknown", label: allocation.replacement_state };
  }
}
