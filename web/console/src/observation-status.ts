// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useEffect, useState } from "react";

export function observationStatus(at: string | null | undefined, now: number): "Unknown" | "Current" | "Stale" {
  const observed = at ? Date.parse(at) : NaN;
  if (!Number.isFinite(observed) || observed > now + 60_000) return "Unknown";
  return now - observed > 15 * 60_000 ? "Stale" : "Current";
}

// Reports must age even when a view stays open without a request or user
// interaction. Refreshing this clock never refreshes the observation itself.
export function useObservationStatus(at: string | null | undefined) {
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const interval = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(interval);
  }, []);
  return observationStatus(at, now);
}
