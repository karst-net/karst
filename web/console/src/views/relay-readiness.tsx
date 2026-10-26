// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { Observed, Status } from "@karst-net/ui";
import type { GatewayInventory } from "@karst-net/api-client";
import type { ManagedRelayService } from "../api";
import { admissionObservation, exitObservations } from "../relay-readiness";

export function RelayReadiness({ service, targets, inventory, targetError, gatewayError, now }: {
  service: ManagedRelayService; targets?: Array<{ relay_id: string; refreshed_at: string }>;
  inventory?: GatewayInventory; targetError?: string; gatewayError?: string; now: number;
}) {
  if (!service.access_managed) return <span>Legacy configuration; group-managed admission not configured.</span>;
  const refreshed = targets?.find(target => target.relay_id === service.ponor_id)?.refreshed_at;
  const writer = targetError || !targets ? { label: "Admission writer observation unavailable", state: "unknown" as const } : admissionObservation(refreshed, now);
  const offers = exitObservations(service, gatewayError ? undefined : inventory);
  return <>
    <p><Status state={writer.state} label={writer.label} />{!targetError && refreshed && <> · <Observed at={refreshed} /></>}</p>
    {offers.length ? <>{offers.map(offer => <p key={offer.family}>{offer.family} egress{offer.gateway && <> through <strong>{offer.gateway}</strong></>}: <Status state={offer.state} label={offer.label} /></p>)}<a href="#/gateways/metrics">Inspect Gateway observations</a></> : <p>Internet egress disabled</p>}
  </>;
}
