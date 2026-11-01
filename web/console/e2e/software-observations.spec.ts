// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { expect, test } from "@playwright/test";

const observed = "2026-10-31T18:00:00Z";

test("control and retained deployment observations age while settings stays open", async ({ page }) => {
  await page.clock.install({ time: new Date(observed) });
  // The empty-state suite clears the shared mock's users concurrently. Keep
  // this admin-only view's signed-in identity local to this browser test.
  await page.route("**/api/users/current", route => route.fulfill({ json: {
    id: "software-observer", name: "Software observer", email: "observer@example.test",
    role: "admin", status: "active", is_current: true, is_blocked: false, auto_groups: [],
  } }));
  let controlObserved = observed;
  let requests = 0;
  await page.route("**/api/karst/v1/versions", route => {
    requests++;
    return route.fulfill({ json: { observed_at: controlObserved, control: { version: "v1", revision: "control-commit" }, deployment_status: "available",
      deployment: { observed_at: observed, components: [{ name: "relay", image: "relay:v1", image_id: "sha256:image", tags: [], state: "running" }] } } });
  });
  await page.goto("/#/settings");
  const versions = page.getByRole("region", { name: "Software versions", exact: true });
  const control = page.getByRole("region", { name: "Control software observation" });
  await expect(control).toContainText("Observation status: Current");
  await expect(versions.getByText(/Observation status: Current. Snapshots older/)).toBeVisible();
  const before = requests;
  await page.clock.fastForward(16 * 60_000);
  await expect(control).toContainText("Observation status: Stale");
  await expect(versions.getByText(/Observation status: Stale. Snapshots older/)).toBeVisible();
  expect(requests).toBe(before);

  controlObserved = new Date(Date.parse(observed) + 16 * 60_000).toISOString();
  await page.getByRole("button", { name: "Refresh component versions" }).click();
  await expect(control).toContainText("Observation status: Current");
  await expect(versions.getByText(/Observation status: Stale. Snapshots older/)).toBeVisible();
  expect(requests).toBe(before + 1);
});

test("agent reports and actual compatibility checks age without changing the recorded rejection", async ({ page }) => {
  await page.clock.install({ time: new Date(observed) });
  await page.route("**/api/karst/v1/versions", route => route.fulfill({ json: { observed_at: observed, control: { version: "v1", revision: "commit" }, deployment_status: "not_configured" } }));
  await page.route("**/api/karst/v1/gateways", route => route.fulfill({ json: { schema_version: 1, unresolved_routes: [], unsupported_routes: [], gateways: [
    { node_id: "aging-gateway", node_handle: "aging-handle", name: "Aging gateway", control_connected: true, forwarding_readiness: "unreported", offers: [],
      software: { version: "v1", revision: "agent-commit", observed_at: observed },
      control_check: { status: "incompatible", capability: "gateway_ingress_schema", required_schema: 1, reported_schema: 0, observed_at: observed } },
  ] } }));
  await page.goto("/#/gateways/metrics");
  await page.getByRole("region", { name: "Configured Gateway nodes" }).locator("summary").click();
  const agent = page.getByRole("region", { name: "Agent software version" });
  const compatibility = page.getByRole("region", { name: "Control compatibility check" });
  await expect(agent.locator(":scope > p").first()).toContainText("Observation status: Current");
  await expect(compatibility).toContainText("Observation status: Current");
  await page.clock.fastForward(16 * 60_000);
  await expect(agent.locator(":scope > p").first()).toContainText("Observation status: Stale");
  await expect(compatibility).toContainText("Observation status: Stale");
  await expect(compatibility).toContainText("Last control check: Incompatible");
  await expect(compatibility).toContainText("Upgrade the gateway agent");
});
