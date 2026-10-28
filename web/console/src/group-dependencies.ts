// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { api, ApiError, type Group } from "./api";
import type { AccessDocument } from "./access-model";

export type GroupDependencyReview = {
  group: Group;
  dependencies: Array<{ key: string; label: string; href: string }>;
  history: string[];
  fingerprint: string;
};

// Load when reviewing a group change and again before applying it. Missing or malformed dependency
// data must never be interpreted as a group with no access relationships.
export async function loadGroupDependencies(id: string): Promise<GroupDependencyReview> {
  const [group, policy, relays, routes, nameservers, dns, users, invitations] = await Promise.all([
    api.group(id), api.policy().catch(error => {
      if (error instanceof ApiError && error.status === 404 && error.message === "no Karst policy version") return { version: 0, document: "{}" };
      throw error;
    }), api.relayServices(), api.routes(), api.nameservers(), api.dnsSettings(), api.users(), api.invitations(),
  ]);
  const document = JSON.parse(policy.document) as AccessDocument;
  const dependencies: GroupDependencyReview["dependencies"] = [];
  const add = (key: string, label: string, href: string) => dependencies.push({ key, label, href });
  for (const grant of document.grants ?? []) {
    if (grant.source_groups.includes(id) || grant.target_groups?.includes(id)) add(`grant:${grant.id}`, `Access grant: ${grant.name}`, grant.id.startsWith("relay-exit-") ? "#/relays" : "#/groups/access");
  }
  for (const [name, bound] of Object.entries(document.groupBindings ?? {})) {
    if (bound === id) add(`binding:${name}`, `Legacy membership mapping: ${name.replace(/^group:/, "")}`, "#/groups/access");
  }
  const relatedRelays = relays.filter(relay => relay.allowed_groups?.includes(id)).sort((a, b) => a.id.localeCompare(b.id));
  for (const relay of relatedRelays) add(`relay:${relay.id}`, `Relay: ${relay.id}`, "#/relays");
  const relatedRoutes = routes.filter(route => [...(route.peer_groups ?? []), ...(route.groups ?? []), ...(route.access_control_groups ?? [])].includes(id)).sort((a, b) => a.id.localeCompare(b.id));
  for (const route of relatedRoutes) add(`route:${route.id}`, `Gateway route: ${route.network_id}`, route.id.startsWith("relay-exit-") ? "#/relays" : "#/routes");
  for (const server of nameservers) if (server.groups.includes(id)) add(`dns:${server.id}`, `DNS servers: ${server.name}`, "#/dns");
  if (dns.disabled_management_groups.includes(id)) add("dns-settings", "DNS management exception", "#/dns");
  for (const user of users) if (user.auto_groups?.includes(id)) add(`user:${user.id}`, `Automatic assignment: ${user.name || user.email || "Unnamed user"}`, "#/users");
  for (const invitation of invitations) if (invitation.groups.includes(id) && invitation.state === "pending") add(`invitation:${invitation.id}`, `Active device invitation: ${invitation.name}`, "#/machines/add");
  if (group.resources_count > 0) add("resources", `${group.resources_count} assigned network resources`, "#/groups");
  dependencies.sort((a, b) => a.key.localeCompare(b.key));
  const history = invitations.filter(invitation => invitation.groups.includes(id) && invitation.state !== "pending").map(invitation => `${invitation.name} (${invitation.state})`);
  const fingerprint = JSON.stringify({ name: group.name, issued: group.issued, members: (group.peers ?? []).map(peer => peer.id).sort(), count: group.peers_count, resources: group.resources, policy: policy.version, dependencies, relays: relatedRelays, routes: relatedRoutes });
  return { group, dependencies, history, fingerprint };
}
