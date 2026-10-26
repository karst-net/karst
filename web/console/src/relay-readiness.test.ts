// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { expect, test } from "vitest";
import type { GatewayInventory } from "@karst-net/api-client";
import { admissionObservation, exitObservations } from "./relay-readiness";

const service = { id: "denver", ponor_id: "backend", gateway_handle: "bound-key", exit_ipv4: true, exit_ipv6: true };
const inventory = (): GatewayInventory => ({ schema_version: 1, unresolved_routes: [], unsupported_routes: [], gateways: [{ node_id: "native-id", node_handle: "bound-key", name: "Denver host", control_connected: true, forwarding_readiness: "ready", offers: [
  { id: "relay-exit-denver-0", network_id: "denver", prefix: "0.0.0.0/0", kind: "default_ipv4", enabled: true, masquerade: true, metric: 9999, requires_client_consent: true, forwarding_readiness: "ready" },
  { id: "relay-exit-denver-1", network_id: "denver", prefix: "::/0", kind: "default_ipv6", enabled: true, masquerade: true, metric: 9999, requires_client_consent: true, forwarding_readiness: "degraded" },
] }] });

test("writer observations expire at the server lease boundary and reject unknown clock data", () => {
  const now = Date.parse("2026-10-25T12:00:00Z");
  expect(admissionObservation(new Date(now - 49_999).toISOString(), now).state).toBe("healthy");
  expect(admissionObservation(new Date(now - 50_000).toISOString(), now).label).toContain("expired");
  expect(admissionObservation(undefined, now).state).toBe("warning");
  expect(admissionObservation("bad timestamp", now).state).toBe("unknown");
  expect(admissionObservation(new Date(now + 1).toISOString(), now).state).toBe("unknown");
});

test("each family uses its owned offer on the explicitly bound Gateway", () => {
  const result = exitObservations(service, inventory());
  expect(result.map(offer => [offer.family, offer.label])).toEqual([["IPv4", "Forwarding reported ready"], ["IPv6", "Forwarding reported degraded"]]);
});

test("IPv6-only service owns index zero and cannot borrow another offer's readiness", () => {
  const data = inventory(); data.gateways[0].offers = [{ ...data.gateways[0].offers[1], id: "relay-exit-denver-0" }];
  expect(exitObservations({ ...service, exit_ipv4: false }, data)[0].label).toBe("Forwarding reported degraded");
  data.gateways[0].offers[0].id = "another-service";
  expect(exitObservations({ ...service, exit_ipv4: false }, data)[0].state).toBe("unknown");
});

test("a matching name or native node ID is not proof of the selected public identity", () => {
  const data = inventory(); data.gateways[0].node_handle = undefined; data.gateways[0].node_id = "bound-key";
  expect(exitObservations(service, data).every(offer => offer.state === "unknown")).toBe(true);
  data.gateways[0].node_handle = "other-key";
  expect(exitObservations(service, data).every(offer => offer.state === "unknown")).toBe(true);
});

test("offline, disabled and unreported offers cannot use aggregate ready status", () => {
  const data = inventory(); data.gateways[0].control_connected = false;
  expect(exitObservations(service, data)[0].label).toBe("Gateway disconnected");
  data.gateways[0].control_connected = true; data.gateways[0].offers[0].enabled = false;
  expect(exitObservations(service, data)[0].label).toBe("Exit offer disabled");
  data.gateways[0].offers[0].enabled = true; data.gateways[0].offers[0].forwarding_readiness = "unreported";
  expect(exitObservations(service, data)[0].label).toBe("Forwarding not reported");
});

test("missing sources, bindings and unresolved routes stay unknown", () => {
  expect(exitObservations(service)[0].state).toBe("unknown");
  expect(exitObservations({ ...service, gateway_handle: "" }, inventory())[0].label).toBe("Gateway not bound");
  const data = inventory(); data.gateways[0].offers = []; data.unresolved_routes.push("relay-exit-denver-0");
  expect(exitObservations(service, data)[0].label).toBe("Exit route unresolved");
  expect(exitObservations({ ...service, exit_ipv4: false, exit_ipv6: false }, data)).toEqual([]);
});
