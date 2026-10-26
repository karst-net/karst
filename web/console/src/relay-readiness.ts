// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import type { GatewayInventory } from "@karst-net/api-client";
import type { ManagedRelayService } from "./api";

export type Observation = { label: string; state: "healthy" | "warning" | "unknown" };
export function admissionObservation(refreshed: string | undefined, now: number): Observation {
  if (!refreshed) return { label: "No recent admission writer", state: "warning" };
  const age = now - Date.parse(refreshed);
  if (!Number.isFinite(age) || age < 0) return { label: "Admission writer time unknown", state: "unknown" };
  return age < 50_000 ? { label: "Admission writer recently refreshed", state: "healthy" } : { label: "Admission writer refresh expired", state: "warning" };
}

// Both the explicitly bound public handle and the resource-owned route must
// match. Another node's similarly named route or aggregate readiness is not
// evidence that this service's selected Gateway can forward either family.
export function exitObservations(service: ManagedRelayService, inventory?: GatewayInventory): Array<Observation & { family: string; gateway?: string }> {
  const families = [service.exit_ipv4 && { family: "IPv4", kind: "default_ipv4", prefix: "0.0.0.0/0" }, service.exit_ipv6 && { family: "IPv6", kind: "default_ipv6", prefix: "::/0" }].filter(Boolean) as Array<{ family: string; kind: string; prefix: string }>;
  return families.map((family, index) => {
    const base = { family: family.family, state: "unknown" as const };
    if (!service.gateway_handle) return { ...base, label: "Gateway not bound" };
    if (!inventory) return { ...base, label: "Gateway readiness unavailable" };
    const routeID = `relay-exit-${service.id}-${index}`;
    if (inventory.unresolved_routes.includes(routeID)) return { ...base, label: "Exit route unresolved" };
    if (inventory.unsupported_routes.includes(routeID)) return { ...base, label: "Managed exit declaration unsupported" };
    const matches = inventory.gateways.filter(node => node.node_handle === service.gateway_handle);
    if (matches.length !== 1) return { ...base, label: "Bound Gateway unavailable; refresh or upgrade control" };
    const gateway = matches[0];
    const offer = gateway.offers.find(offer => offer.id === routeID && offer.kind === family.kind && offer.prefix === family.prefix);
    if (!offer) return { ...base, gateway: gateway.name, label: "Managed exit offer missing" };
    if (!offer.enabled) return { ...base, gateway: gateway.name, label: "Exit offer disabled", state: "warning" };
    if (!gateway.control_connected) return { ...base, gateway: gateway.name, label: "Gateway disconnected", state: "warning" };
    if (offer.forwarding_readiness === "ready") return { ...base, gateway: gateway.name, label: "Forwarding reported ready", state: "healthy" };
    if (offer.forwarding_readiness === "degraded") return { ...base, gateway: gateway.name, label: "Forwarding reported degraded", state: "warning" };
    return { ...base, gateway: gateway.name, label: "Forwarding not reported" };
  });
}
