// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { NodeCompliance } from "@karst-net/api-client";
import { ClientVersionObservation } from "./client-version";

const report: NodeCompliance = { status: "reported", client_version_status: "collected", client_version: "v0.1.0-rc.31", received_at: "2026-10-31T18:00:00Z" };
const render = (evidence = report, controlVersion = report.client_version!) => renderToStaticMarkup(<ClientVersionObservation evidence={evidence} controlVersion={controlVersion} />);

describe("client version observations", () => {
  afterEach(() => vi.useRealTimers());

  it("labels recent reports and keeps unavailable build identities explicit", () => {
    vi.useFakeTimers().setSystemTime(new Date("2026-10-31T18:05:00Z"));
    const html = render();
    expect(html).toContain("Observation status: Current");
    expect(html).toContain(report.client_version);
    expect(html).toContain("Build revision: Unknown");
    expect(html).toContain("Artifact identity: Unknown");
    expect(html).not.toContain("releases differ");
    expect(html).toContain("Compatibility is unverified");
  });

  it("warns about release drift even for stale observations", () => {
    vi.useFakeTimers().setSystemTime(new Date("2026-10-31T18:16:00Z"));
    const html = render(report, "v0.1.0-rc.32");
    expect(html).toContain("Observation status: Stale");
    expect(html).toContain("Client and control releases differ");
    expect(html).toContain("restart the device agent");
  });

  it.each([null, "invalid", "2026-11-01T00:00:00Z"])("treats missing or invalid observation %s as unknown", (received_at) => {
    vi.useFakeTimers().setSystemTime(new Date("2026-10-31T18:05:00Z"));
    expect(render({ ...report, received_at })).toContain("Observation status: Unknown");
  });

  it.each(["unconfigured", "unreported"] as const)("does not claim a running version for %s evidence", (status) => {
    const html = render({ ...report, status }, "v0.1.0-rc.32");
    expect(html).toContain("Reported release: <code>Unknown</code>");
    expect(html).not.toContain("releases differ");
  });

  it.each(["unsupported", "collection-error"] as const)("does not trust a version when collection is %s", (client_version_status) => {
    const html = render({ ...report, client_version_status });
    expect(html).toContain("Reported release: <code>Unknown</code>");
    expect(html).toContain(client_version_status.replaceAll("-", " "));
  });
});
