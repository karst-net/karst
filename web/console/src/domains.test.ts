// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { expect, test } from "vitest";
import { byTree } from "./domains";
import type { MeshDomain } from "./api";

const root: MeshDomain = { id: "root", label: "", path: "", is_root: true, dns_suffix: "karst" };
const engineering: MeshDomain = { id: "engineering", parent_id: root.id, label: "engineering", path: "engineering" };
const build: MeshDomain = { id: "build", parent_id: engineering.id, label: "build", path: "build.engineering" };

test("explicit root remains visible above its descendants", () => {
  expect(byTree([build, root, engineering]).map(({ domain, depth }) => [domain.id, depth]))
    .toEqual([["root", 0], ["engineering", 1], ["build", 2]]);
});

test("delegated domain trees display even when the account root is outside their scope", () => {
  expect(byTree([build, engineering]).map(({ domain, depth }) => [domain.id, depth]))
    .toEqual([["engineering", 0], ["build", 1]]);
});
