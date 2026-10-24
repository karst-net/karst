// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { expect, test } from "@playwright/test";
import { AxeBuilder } from "@axe-core/playwright";

const inventory = {
  schema_version: 1,
  gateways: [{ node_id: "combined-node", name: "Combined Gateway", control_connected: true, forwarding_readiness: "unreported", offers: [
    { id: "office", network_id: "office", prefix: "10.20.0.0/16", kind: "subnet", enabled: true, masquerade: true, metric: 100, requires_client_consent: false, forwarding_readiness: "unreported" },
    { id: "internet", network_id: "internet", prefix: "0.0.0.0/0", kind: "default_ipv4", enabled: true, masquerade: true, metric: 100, requires_client_consent: true, forwarding_readiness: "unreported" },
    { id: "internet-v6", network_id: "internet-v6", prefix: "::/0", kind: "default_ipv6", enabled: false, masquerade: true, metric: 100, requires_client_consent: true, forwarding_readiness: "unreported" },
  ] }], unresolved_routes: [], unsupported_routes: [],
};

test("one Gateway shows both behaviors without claiming forwarding readiness", async ({ page }) => {
  await page.route("**/api/karst/v1/gateways", (route) => route.fulfill({ json: inventory }));
  await page.goto("/#/gateways");
  const section = page.getByRole("region", { name: "Configured Gateway nodes" });
  await expect(section.locator("tbody tr")).toHaveCount(1);
  await expect(section).toContainText("10.20.0.0/16 · Subnet · enabled");
  await expect(section).toContainText("IPv4 default · enabled · client consent required");
  await expect(section).toContainText("IPv6 default · disabled · client consent required");
  await expect(section).toContainText("Connected");
  await expect(section).toContainText("Unreported");
  await expect(section).toContainText("karst gateway status");
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test("legacy route links and canonical Gateway navigation remain usable", async ({ page }) => {
  await page.goto("/#/routes");
  await expect(page.getByRole("heading", { name: "Gateways", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Add subnet route" })).toBeVisible();
  await page.getByRole("link", { name: "Gateways", exact: true }).click();
  await expect(page).toHaveURL(/#\/gateways$/);
  await expect(page.getByRole("link", { name: "Gateways", exact: true })).toHaveAttribute("aria-current", "page");
});

test("older control inventory errors do not remove route administration", async ({ page }) => {
  await page.route("**/api/karst/v1/gateways", (route) => route.fulfill({ status: 404, json: { message: "not supported" } }));
  await page.goto("/#/gateways");
  await expect(page.getByText(/Gateway inventory unavailable:/)).toBeVisible();
  await page.getByRole("button", { name: "Add IPv4 exit route" }).click();
  await expect(page.getByLabel("Route network (CIDR)")).toHaveValue("0.0.0.0/0");
  await expect(page.getByText("karst gateway exit use <route-id>")).toBeVisible();
  await expect(page.getByText(/IPv4 and IPv6 consent are independent/)).toBeVisible();
});

test("unresolved and unsupported declarations remain visible", async ({ page }) => {
  await page.route("**/api/karst/v1/gateways", (route) => route.fulfill({ json: { ...inventory, gateways: [], unresolved_routes: ["empty-routing-group"], unsupported_routes: ["legacy-domain-route"] } }));
  await page.goto("/#/gateways");
  await expect(page.getByText(/Routes without a visible eligible node: empty-routing-group/)).toBeVisible();
  await expect(page.getByText(/Routes outside the CIDR Gateway model: legacy-domain-route/)).toBeVisible();
});

test("refresh preserves independent control connectivity and readiness", async ({ page }) => {
  let connected = true;
  await page.route("**/api/karst/v1/gateways", (route) => route.fulfill({ json: { ...inventory, gateways: inventory.gateways.map((node) => ({ ...node, control_connected: connected })) } }));
  await page.goto("/#/gateways");
  const section = page.getByRole("region", { name: "Configured Gateway nodes" });
  await expect(section).toContainText("Connected");
  connected = false;
  await page.getByRole("button", { name: "Refresh Gateway inventory" }).click();
  await expect(section).toContainText("Disconnected");
  await expect(section).toContainText("Unreported");
});


test("real forwarding readiness is shown per offer and aggregated per node", async ({ page }) => {
  await page.route("**/api/karst/v1/gateways", (route) => route.fulfill({ json: { ...inventory, gateways: [{
    ...inventory.gateways[0],
    forwarding_readiness: "degraded",
    offers: [
      { ...inventory.gateways[0].offers[0], forwarding_readiness: "ready" },
      { ...inventory.gateways[0].offers[1], forwarding_readiness: "degraded" },
      inventory.gateways[0].offers[2],
    ],
  }] } }));
  await page.goto("/#/gateways");
  const section = page.getByRole("region", { name: "Configured Gateway nodes" });
  await expect(section).toContainText("10.20.0.0/16 · Subnet · enabled · ready");
  await expect(section).toContainText("IPv4 default · enabled · client consent required · degraded");
  await expect(section).toContainText("IPv6 default · disabled · client consent required · unreported");
  await expect(section).toContainText("Degraded — check the node for an nftables apply failure.");
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test("an unknown inventory schema fails explicitly while routes remain available", async ({ page }) => {
  await page.route("**/api/karst/v1/gateways", (route) => route.fulfill({ json: { ...inventory, schema_version: 2 } }));
  await page.goto("/#/gateways");
  await expect(page.getByText(/Unsupported Gateway inventory schema/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Add subnet route" })).toBeVisible();
});

test("one Gateway behavior editor switches prefix and default-route behaviors", async ({ page }) => {
  await page.goto("/#/gateways");
  await page.getByRole("button", { name: "Add Gateway behavior", exact: true }).click();
  const behavior = page.getByLabel("Gateway behavior", { exact: true });
  await expect(behavior).toHaveValue("subnet");
  await behavior.selectOption("::/0");
  await expect(page.getByLabel("Route network (CIDR)")).toHaveValue("::/0");
  await expect(page.getByText("karst gateway exit use <route-id>")).toBeVisible();
  await behavior.selectOption("0.0.0.0/0");
  await expect(page.getByLabel("Route network (CIDR)")).toHaveValue("0.0.0.0/0");
  await behavior.selectOption("subnet");
  await expect(page.getByLabel("Route network (CIDR)")).toHaveValue("");
  await expect(page.getByText("karst gateway exit use <route-id>")).toHaveCount(0);
});

test("default behavior keeps explicit client consent and existing route writes", async ({ page }) => {
  let submitted: Record<string, unknown> | undefined;
  await page.route("**/api/routes", async (route) => {
    if (route.request().method() !== "POST") { await route.continue(); return; }
    submitted = route.request().postDataJSON() as Record<string, unknown>;
    await route.fulfill({ status: 201, json: { ...submitted, id: "new-default" } });
  });
  await page.goto("/#/gateways");
  await page.getByRole("button", { name: "Add Gateway behavior", exact: true }).click();
  await page.getByLabel("Gateway behavior", { exact: true }).selectOption("::/0");
  await page.getByLabel("Route identifier", { exact: true }).fill("ipv6-egress");
  await page.getByLabel("Routing groups", { exact: true }).selectOption(["group-gateways"]);
  await page.getByLabel("Distribution groups", { exact: true }).selectOption(["group-all"]);
  await page.getByLabel("Access-control groups", { exact: true }).selectOption(["group-sre"]);
  await page.getByRole("button", { name: "Add route", exact: true }).click();
  await expect.poll(() => submitted).toMatchObject({
    network: "::/0", network_id: "ipv6-egress", skip_auto_apply: true,
    peer_groups: ["group-gateways"], groups: ["group-all"], access_control_groups: ["group-sre"],
  });
});
