// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { beforeEach, expect, test, vi } from "vitest";
import { api, ApiError } from "./api";
import { reviewGroupDeletion } from "./group-deletion";

vi.mock("./api", () => ({ ApiError: class extends Error { constructor(message: string, readonly status: number) { super(message); } }, api: { group: vi.fn(), policy: vi.fn(), relayServices: vi.fn(), routes: vi.fn(), nameservers: vi.fn(), dnsSettings: vi.fn(), users: vi.fn(), invitations: vi.fn() } }));
beforeEach(() => {
  vi.mocked(api.group).mockResolvedValue({ id: "g", name: "Engineering", peers_count: 0, resources_count: 0, peers: [] });
  vi.mocked(api.policy).mockResolvedValue({ version: 1, document: "{}" } as Awaited<ReturnType<typeof api.policy>>);
  vi.mocked(api.relayServices).mockResolvedValue([]);
  vi.mocked(api.routes).mockResolvedValue([]);
  vi.mocked(api.nameservers).mockResolvedValue([]);
  vi.mocked(api.dnsSettings).mockResolvedValue({ disabled_management_groups: [] });
  vi.mocked(api.users).mockResolvedValue([]);
  vi.mocked(api.invitations).mockResolvedValue([]);
});

test("all Gateway group roles and DNS/user assignments are dependencies, including disabled resources", async () => {
  const defaults = { description: "", enabled: true, network: "10.0.0.0/24", metric: 9999, masquerade: true, keep_route: false, skip_auto_apply: true };
  vi.mocked(api.routes).mockResolvedValue([
    { ...defaults, id: "source", network_id: "Private subnet", peer_groups: ["g"], groups: [], access_control_groups: [], enabled: false },
    { ...defaults, id: "distribution", network_id: "Distribution", peer_groups: [], groups: ["g"], access_control_groups: [] },
    { ...defaults, id: "relay-exit-denver-0", network_id: "Denver egress", peer_groups: [], groups: [], access_control_groups: ["g"] },
  ] as Awaited<ReturnType<typeof api.routes>>);
  vi.mocked(api.nameservers).mockResolvedValue([{ id: "dns", name: "Internal DNS", groups: ["g"], enabled: false }] as Awaited<ReturnType<typeof api.nameservers>>);
  vi.mocked(api.dnsSettings).mockResolvedValue({ disabled_management_groups: ["g"] });
  vi.mocked(api.users).mockResolvedValue([{ id: "owner", name: "Operator", auto_groups: ["g"] }] as Awaited<ReturnType<typeof api.users>>);
  const review = await reviewGroupDeletion("g");
  expect(review.dependencies).toHaveLength(6);
  expect(review.dependencies.find(link => link.key === "route:relay-exit-denver-0")?.href).toBe("#/relays");
  expect(review.dependencies.map(link => link.label)).toContain("Automatic assignment: Operator");
});

test("a target-group grant and retained group binding block deletion", async () => {
  vi.mocked(api.policy).mockResolvedValue({ version: 1, document: JSON.stringify({ grants: [{ id: "target", name: "Target access", source_groups: ["other"], target_groups: ["g"] }], groupBindings: { "group:legacy": "g" } }) } as Awaited<ReturnType<typeof api.policy>>);
  const review = await reviewGroupDeletion("g");
  expect(review.dependencies.map(link => link.key)).toEqual(["binding:group:legacy", "grant:target"]);
});

test("malformed policy or unavailable inventory fails the review", async () => {
  vi.mocked(api.policy).mockResolvedValue({ version: 1, document: "malformed" } as Awaited<ReturnType<typeof api.policy>>);
  await expect(reviewGroupDeletion("g")).rejects.toThrow();
  vi.mocked(api.policy).mockResolvedValue({ version: 1, document: "{}" } as Awaited<ReturnType<typeof api.policy>>);
  vi.mocked(api.routes).mockRejectedValue(new Error("Gateway unavailable"));
  await expect(reviewGroupDeletion("g")).rejects.toThrow("Gateway unavailable");
});


test("only an explicit missing policy version is treated as no Karst grants", async () => {
  vi.mocked(api.policy).mockRejectedValue(new ApiError("no Karst policy version", 404, {}));
  await expect(reviewGroupDeletion("g")).resolves.toMatchObject({ dependencies: [] });
  vi.mocked(api.policy).mockRejectedValue(new ApiError("API route missing", 404, {}));
  await expect(reviewGroupDeletion("g")).rejects.toThrow("API route missing");
});
