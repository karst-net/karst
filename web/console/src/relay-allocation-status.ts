// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import type { StatusState } from "@karst-net/ui";
import type { RelayAllocation } from "@karst-net/api-client";

/** ADR-0063's state machine, rendered the same way relay-readiness.ts
 * renders operational status — a plain label, not a progress bar: every
 * step here can fail, and "in progress" covers a real range of wait
 * times (a cloud instance boot is not instant). */
export function allocationStatus(allocation: RelayAllocation): { state: StatusState; label: string } {
  switch (allocation.state) {
    case "ready": return { state: "healthy", label: "Ready" };
    case "requested": return { state: "unknown", label: "Requested" };
    case "provisioning": return { state: "unknown", label: "Provisioning" };
    case "granting": return { state: "unknown", label: "Granting access" };
    case "revoking": return { state: "warning", label: "Revoking access" };
    case "deprovisioning": return { state: "warning", label: "Deprovisioning" };
    case "deprovisioned": return { state: "unknown", label: "Deprovisioned" };
    case "failed": return { state: "danger", label: `Failed${allocation.failed_step ? ` at ${allocation.failed_step}` : ""}: ${allocation.failure_reason || "no reason reported"}` };
    default: return { state: "unknown", label: allocation.state ?? "Unknown" };
  }
}
