// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

export type AccessGrant = {
  id: string; name: string; source_groups: string[]; target_groups?: string[];
  target_nodes?: string[]; gateway?: string; networks?: string[]; ports: string; ssh?: boolean;
};
export type AccessDocument = {
  groups?: Record<string, string[]>; groupBindings?: Record<string, string>;
  grants?: AccessGrant[]; acls?: Array<{ action: string; src: string[]; dst: string[] }>;
  ssh?: Array<{ action: string; src: string[]; dst: string[] }>;
  tagOwners?: Record<string, string[]>;
};

// Preserve every legacy field. Editing one grant must never discard rules,
// tag ownership, or the absent-vs-empty SSH distinction.
export function withGrant(document: AccessDocument, grant: AccessGrant): AccessDocument {
  const grants = document.grants ?? [];
  return { ...document, ...((grant.ssh || grants.some(g => g.ssh)) && document.ssh === undefined ? { ssh: [] } : {}), grants: grants.some(g => g.id === grant.id) ? grants.map(g => g.id === grant.id ? grant : g) : [...grants, grant] };
}
export function withoutGrant(document: AccessDocument, id: string): AccessDocument {
  return { ...document, ...((document.grants ?? []).some(g => g.ssh) && document.ssh === undefined ? { ssh: [] } : {}), grants: (document.grants ?? []).filter(g => g.id !== id) };
}
