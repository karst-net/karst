// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { NodeSoftware } from "@karst-net/api-client";
import { ClientVersionObservation } from "./client-version";

const report: NodeSoftware = { version: "v0.1.0-rc.31", observed_at: "2026-10-31T18:00:00Z" };
const render = (software: NodeSoftware | undefined = report, controlVersion = report.version!) => renderToStaticMarkup(<ClientVersionObservation software={software} controlVersion={controlVersion} />);

describe("client version observations", () => {
  afterEach(() => vi.useRealTimers());

  it("labels recent reports and keeps unavailable build identities explicit", () => {
    vi.useFakeTimers().setSystemTime(new Date("2026-10-31T18:05:00Z"));
    const html = render();
    expect(html).toContain("Observation status: Current");
    expect(html).toContain(report.version);
    expect(html).toContain("Build revision: <code>Unknown</code>");
    expect(html).toContain("Artifact identity: <code>Unknown</code>");
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

  it.each(["invalid", "2026-11-01T00:00:00Z"])("treats missing or invalid observation %s as unknown", (observed_at) => {
    vi.useFakeTimers().setSystemTime(new Date("2026-10-31T18:05:00Z"));
    expect(render({ ...report, observed_at })).toContain("Observation status: Unknown");
  });

  it("shows unknown software when a legacy agent has never reported", () => {
    const html = renderToStaticMarkup(<ClientVersionObservation controlVersion="v0.1.0-rc.32" />);
    expect(html).toContain("Reported release: <code>Unknown</code>");
    expect(html).toContain("Observation status: Unknown");
    expect(html).not.toContain("releases differ");
  });

  it("shows independently reported revision and artifact identity", () => {
    const html = render({ ...report, revision: "source-commit", artifact_id: "sha256:artifact" });
    expect(html).toContain("source-commit");
    expect(html).toContain("sha256:artifact");
    expect(html).toContain("independently of compliance collection");
  });

  it.each([null, "", "unknown", "dev"])("does not claim a known release for %s", (version) => {
    const html = render({ ...report, version }, "v0.1.0-rc.32");
    expect(html).toContain("Reported release: <code>Unknown</code>");
    expect(html).not.toContain("releases differ");
  });
});
