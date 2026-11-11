// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { Observed, Status } from "@karst-net/ui";
import type { AvenInventory } from "@karst-net/api-client";
import type { ManagedEstavelleService } from "../api";
import { admissionObservation, exitObservations } from "../estavelle-readiness";

export function EstavelleReadiness({ service, targets, inventory, targetError, gatewayError, now }: {
  service: ManagedEstavelleService; targets?: Array<{ estavelle_id: string; refreshed_at: string }>;
  inventory?: AvenInventory; targetError?: string; gatewayError?: string; now: number;
}) {
  if (!service.access_managed) return <span>Legacy configuration; group-managed admission not configured.</span>;
  const refreshed = targets?.find(target => target.estavelle_id === service.ponor_id)?.refreshed_at;
  const writer = targetError || !targets ? { label: "Admission writer observation unavailable", state: "unknown" as const } : admissionObservation(refreshed, now);
  const offers = exitObservations(service, gatewayError ? undefined : inventory);
  return <>
    <p><Status state={writer.state} label={writer.label} />{!targetError && refreshed && <> · <Observed at={refreshed} /></>}</p>
    {offers.length ? <>{offers.map(offer => <p key={offer.family}>{offer.family} egress{offer.gateway && <> through <strong>{offer.gateway}</strong></>}: <Status state={offer.state} label={offer.label} /></p>)}<a href="#/avens/metrics">Inspect Aven observations</a></> : <p>Internet egress disabled</p>}
  </>;
}
