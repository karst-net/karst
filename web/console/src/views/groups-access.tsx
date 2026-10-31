// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { Groups } from "./groups";
import { Access } from "./access";
import { ComplianceGuardrails } from "./compliance-guardrails";

export function GroupsAccess({ tab }: { tab: "groups" | "access" | "compliance" }) {
  return <section><h2>Groups &amp; access</h2><nav className="actions" aria-label="Groups and access view"><button aria-pressed={tab === "groups"} onClick={() => { location.hash = "/groups"; }}>Groups</button><button aria-pressed={tab === "access"} onClick={() => { location.hash = "/groups/access"; }}>Access grants</button><button aria-pressed={tab === "compliance"} onClick={() => { location.hash = "/groups/compliance"; }}>Compliance guardrails</button></nav>{tab === "groups" ? <Groups /> : tab === "access" ? <Access /> : <ComplianceGuardrails />}</section>;
}
