// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ClientVersionObservation, ControlCompatibility } from "./client-version";

describe("observed control compatibility", () => {
  afterEach(() => vi.useRealTimers());

  it("does not infer capability acceptance from an equal release", () => {
    const html = renderToStaticMarkup(<ClientVersionObservation software={{ version: "v1", observed_at: "2026-10-31T18:00:00Z" }} controlVersion="v1" />);
    expect(html).toContain("Last control check: Unknown");
    expect(html).toContain("Compatibility is unverified");
  });

  it.each(["relay_lifecycle_schema", "gateway_ingress_schema"] as const)("shows an actual %s rejection even for matching releases", (capability) => {
    vi.useFakeTimers().setSystemTime(new Date("2026-10-31T18:05:00Z"));
    const html = renderToStaticMarkup(<ClientVersionObservation software={{ version: "v1", observed_at: "2026-10-31T18:00:00Z" }} controlVersion="v1"
      controlCheck={{ status: "incompatible", capability, required_schema: 1, reported_schema: 0, observed_at: "2026-10-31T18:00:00Z" }} />);
    expect(html).toContain("Last control check: Incompatible");
    expect(html).toContain("reported: 0");
    expect(html).toContain("Upgrade the");
    expect(html).toContain("reconnect it to control");
    expect(html).not.toContain("Compatibility is unverified");
    expect(html).toContain(capability === "relay_lifecycle_schema" ? "live Relay service modes" : "destination-scoped ingress policy");
  });

  it("labels old acceptance stale without claiming working traffic", () => {
    vi.useFakeTimers().setSystemTime(new Date("2026-10-31T18:16:00Z"));
    const html = renderToStaticMarkup(<ControlCompatibility check={{ status: "accepted", observed_at: "2026-10-31T18:00:00Z" }} />);
    expect(html).toContain("Last control check: Accepted");
    expect(html).toContain("Observation status: Stale");
    expect(html).toContain("does not establish that the agent applied it");
  });

  it.each(["invalid", "2026-11-01T00:00:00Z"])("keeps an invalid/future evaluation time unknown: %s", (observed_at) => {
    vi.useFakeTimers().setSystemTime(new Date("2026-10-31T18:05:00Z"));
    expect(renderToStaticMarkup(<ControlCompatibility check={{ status: "accepted", observed_at }} />)).toContain("Observation status: Unknown");
  });
});
