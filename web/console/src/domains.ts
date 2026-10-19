// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import type { MeshDomain } from "./api";

/** Depth-first, root-first order, so a subdomain always renders under its
 *  parent — the only order that makes an indented table read as a tree
 *  rather than a shuffled list. */
export function byTree(domains: MeshDomain[]): Array<{ domain: MeshDomain; depth: number }> {
  const children = new Map<string, MeshDomain[]>();
  const visibleIds = new Set(domains.map((domain) => domain.id));
  for (const domain of domains) {
    const key = domain.parent_id && visibleIds.has(domain.parent_id) ? domain.parent_id : "";
    children.set(key, [...(children.get(key) ?? []), domain]);
  }
  for (const list of children.values()) list.sort((a, b) => a.label.localeCompare(b.label));
  const ordered: Array<{ domain: MeshDomain; depth: number }> = [];
  const visit = (parentId: string, depth: number) => { for (const domain of children.get(parentId) ?? []) { ordered.push({ domain, depth }); visit(domain.id, depth + 1); } };
  visit("", 0);
  return ordered;
}
