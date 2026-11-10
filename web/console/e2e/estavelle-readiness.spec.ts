// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { expect, test, type Page } from "@playwright/test";
import { AxeBuilder } from "@axe-core/playwright";

async function fixture(page: Page) {
  const state = { failed: false, lease: new Date().toISOString(), connected: true, handle: "bound-key", exits: true };
  await page.route("**/api/groups", route => route.fulfill({ json: [{ id: "engineering", name: "Engineering" }] }));
  await page.route("**/api/karst/v1/estavelles", route => route.fulfill({ json: [{ id: "backend", address: "203.0.113.10:443", health: { admission_state: "confirmed" } }] }));
  await page.route("**/api/karst/v1/estavelle-services**", route => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("/publication")) return route.fulfill({ json: { mode: "services" } });
    if (path.endsWith("/admission-targets")) return state.failed ? route.fulfill({ status: 503, json: { message: "Roster source unavailable" } }) : route.fulfill({ json: [{ relay_id: "backend", refreshed_at: state.lease }] });
    return route.fulfill({ json: [{ id: "denver", ponor_id: "backend", ponor_present: true, access_managed: true, allowed_groups: ["engineering"], gateway_handle: "bound-key", exit_ipv4: state.exits, exit_ipv6: state.exits }] });
  });
  await page.route("**/api/karst/v1/avens", route => state.failed ? route.fulfill({ status: 503, json: { message: "Aven source unavailable" } }) : route.fulfill({ json: { schema_version: 1, unresolved_routes: [], unsupported_routes: [], avens: [{ node_id: "bound-key", node_handle: state.handle, name: "Selected host", control_connected: state.connected, forwarding_readiness: "ready", offers: [
    { id: "relay-exit-denver-0", kind: "default_ipv4", prefix: "0.0.0.0/0", enabled: true, forwarding_readiness: "ready" },
    { id: "relay-exit-denver-1", kind: "default_ipv6", prefix: "::/0", enabled: true, forwarding_readiness: "degraded" },
  ] }] } }));
  return state;
}

test("estavelle row shows named group access, writer observation and per-family Aven readiness", async ({ page }) => {
  await fixture(page); await page.goto("/#/estavelles");
  const row = page.locator("tbody tr");
  await expect(row).toContainText("Engineering");
  await expect(row).toContainText("Admission writer recently refreshed");
  await expect(row.locator("p").filter({ hasText: "IPv4 egress through Selected host:" })).toContainText("Forwarding reported ready");
  await expect(row.locator("p").filter({ hasText: "IPv6 egress through Selected host:" })).toContainText("Forwarding reported degraded");
  await expect(page.getByRole("link", { name: "Inspect Aven observations" })).toHaveAttribute("href", "#/avens/metrics");
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test("refresh shows an expired writer and a disconnected Aven even with ready telemetry", async ({ page }) => {
  const state = await fixture(page); await page.goto("/#/estavelles");
  await expect(page.locator("tbody tr")).toContainText("Forwarding reported ready");
  state.lease = new Date(Date.now() - 60_000).toISOString(); state.connected = false;
  await page.getByRole("button", { name: "Refresh estavelles" }).click();
  await expect(page.locator("tbody tr")).toContainText("Admission writer refresh expired");
  await expect(page.locator("tbody tr")).toContainText("Aven disconnected");
  await expect(page.locator("tbody tr")).not.toContainText("Forwarding reported ready");
});

test("failed refresh does not keep displaying healthy observations from cached data", async ({ page }) => {
  const state = await fixture(page); await page.goto("/#/estavelles");
  await expect(page.locator("tbody tr")).toContainText("Admission writer recently refreshed");
  await expect(page.locator("tbody tr")).toContainText("Forwarding reported ready");
  state.failed = true; await page.getByRole("button", { name: "Refresh estavelles" }).click();
  await expect(page.locator("tbody tr")).toContainText("Admission writer observation unavailable");
  await expect(page.locator("tbody tr")).toContainText("Aven readiness unavailable");
  await expect(page.locator("tbody tr")).not.toContainText("Forwarding reported ready");
  await expect(page.getByRole("button", { name: "Configure access to denver" })).toBeEnabled();
});

test("an older inventory without a public handle cannot match by native ID", async ({ page }) => {
  const state = await fixture(page); state.handle = ""; await page.goto("/#/estavelles");
  await expect(page.locator("tbody tr")).toContainText("Bound Aven unavailable");
  await expect(page.locator("tbody tr")).not.toContainText("Forwarding reported ready");
});

test("an estavelle-only configuration does not claim internet forwarding", async ({ page }) => {
  const state = await fixture(page); state.exits = false; await page.goto("/#/estavelles");
  await expect(page.locator("tbody tr")).toContainText("Internet egress disabled");
  await expect(page.getByRole("link", { name: "Inspect Aven observations" })).toHaveCount(0);
});
