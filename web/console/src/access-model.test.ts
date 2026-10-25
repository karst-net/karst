// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { expect, test } from "vitest";
import { withGrant, withoutGrant, type AccessDocument, type AccessGrant } from "./access-model";
const grant: AccessGrant = { id: "one", name: "Engineering web", source_groups: ["stable-id"], target_groups: ["servers"], ports: "443" };

test("grant edits preserve legacy rules, memberships, bindings and empty SSH gate", () => {
  const legacy: AccessDocument = { groups: {"group:old": ["legacy-user"]}, groupBindings: {"group:old": "stable-id"}, acls: [{action:"accept",src:["*"],dst:["server:80"]}], ssh: [], tagOwners: {"tag:prod":["owner"]} };
  const added = withGrant(legacy,grant);
  expect(added).toEqual({...legacy,grants:[grant]});
  expect(withGrant(added,{...grant,name:"Renamed"}).grants).toHaveLength(1);
  expect(withoutGrant(added,"one")).toEqual({...legacy,grants:[]});
  expect(legacy.grants).toBeUndefined();
  expect(JSON.parse(JSON.stringify(added)).ssh).toEqual([]);
});

test("removing the last SSH grant preserves the additional deny-by-default gate", () => {
  const doc = withGrant({}, { ...grant, ports: "22", ssh: true });
  expect(doc.ssh).toEqual([]);
  expect(withoutGrant(doc,grant.id).ssh).toEqual([]);
  expect(withGrant(doc,{...grant,ssh:false}).ssh).toEqual([]);
});
