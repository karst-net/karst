// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type { SoftwareVersions as VersionData } from "../api";
import { SoftwareVersions } from "./software-versions";

const resource = vi.hoisted(() => ({ value: undefined as VersionData | undefined, loading: false, error: undefined as string | undefined, reload: vi.fn() }));
vi.mock("../common", async (original) => ({ ...await original<typeof import("../common")>(), useResource: () => resource }));
vi.stubGlobal("__KARST_UI_BUILD__", { version: "v0.1.0-rc.25", revision: "ui-commit" });

describe("software versions", () => {
  it("keeps UI and server identities separate and labels deployment observations", () => {
    resource.value = { control: { version: "v0.1.0-rc.24", revision: "server-commit" }, deployment_status: "available", deployment: {
      observed_at: "2026-10-20T12:00:00Z", components: [{ name: "relay", image: "relay@sha256:123", image_id: "sha256:456", tags: [], state: "running" }],
    } };
    const html = renderToStaticMarkup(<SoftwareVersions />);
    expect(html).toContain("v0.1.0-rc.25");
    expect(html).toContain("v0.1.0-rc.24");
    expect(html).toContain("server-commit");
    expect(html).toContain("Deployment snapshot observed");
    expect(html).toContain("No release tag reported");
    expect(html).toContain("sha256:456");
  });
  it("does not substitute the UI version when the server is unavailable", () => {
    resource.value = undefined;
    resource.error = "Server unavailable";
    const html = renderToStaticMarkup(<SoftwareVersions />);
    expect(html).toContain("Unknown");
    expect(html).toContain("Server unavailable");
    expect(html.match(/v0.1.0-rc.25/g)).toHaveLength(1);
  });
});
