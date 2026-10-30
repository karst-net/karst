// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { expect, test } from "@playwright/test";
import { AxeBuilder } from "@axe-core/playwright";

test("acknowledged mode withdrawal keeps Ponor and backend records intact", async ({ page }) => {
  let service = { id: "primary", ponor_id: "ponor", ponor_present: true, ponor_disabled: false };
  let submitted: unknown;
  await page.route("**/api/karst/v1/relays", (route) => route.fulfill({ json: [{ id: "ponor", address: "203.0.113.1:443", health: { admission_state: "confirmed" } }] }));
  await page.route("**/api/karst/v1/relay-services**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("/publication")) { await route.fulfill({ json: { mode: "services" } }); return; }
    if (path.endsWith("/modes")) {
      const request = route.request().postDataJSON();
      submitted = request;
      service = { ...service, ponor_disabled: !request.ponor_enabled };
      await route.fulfill({ json: service }); return;
    }
    await route.fulfill({ json: [service] });
  });
  await page.goto("/#/relays");
  await page.getByRole("button", { name: "Change availability" }).click();
  await page.getByRole("checkbox", { name: "Enable relay", exact: true }).uncheck();
  await expect(page.getByRole("button", { name: "Apply availability" })).toBeDisabled();
  await page.getByRole("checkbox", { name: "I understand mode changes may interrupt client connectivity." }).check();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await page.getByRole("button", { name: "Apply availability" }).click();
  await expect(page.getByText("Relay disabled", { exact: false })).toBeVisible();
  expect(submitted).toEqual({ ponor_enabled: false, acknowledge_connectivity_change: true });
  await page.getByRole("button", { name: "Change availability" }).click();
  await expect(page.getByRole("checkbox", { name: "Enable relay", exact: true })).not.toBeChecked();
});

test("publication preview is read only and activation requires acknowledgment", async ({ page }) => {
  let mode = "legacy";
  let updates = 0;
  await page.route("**/api/karst/v1/relay-services**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("/preview")) { await route.fulfill({ json: [] }); return; }
    if (path.endsWith("/publication")) {
      if (route.request().method() === "PUT") {
        const body = route.request().postDataJSON();
        expect(body.acknowledge_connectivity_change).toBe(true);
        mode = body.mode;
        updates++;
      }
      await route.fulfill({ json: { mode } });
      return;
    }
    await route.fulfill({ json: [] });
  });
  await page.goto("/#/relays");
  await page.getByText("Advanced publication and legacy settings", { exact: true }).click();
  await page.getByRole("button", { name: "Preview service publication", exact: true }).click();
  await expect(page.getByText("No services: all Relay endpoints will be withdrawn from clients.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Publish services" })).toBeDisabled();
  expect(updates).toBe(0);
  await page.getByRole("checkbox", { name: "I understand this changes client connectivity." }).check();
  await page.getByRole("button", { name: "Publish services" }).click();
  await expect(page.getByText("Relay service publication enabled.")).toBeVisible();
  expect(updates).toBe(1);
  page.on("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", { name: "Restore legacy publication" }).click();
  await expect(page.getByText("Legacy registry publication restored.")).toBeVisible();
  expect(updates).toBe(2);
});

test("explicit Relay association preserves backend identity and supports removal", async ({ page }) => {
  // Other browser tests reset the shared mock, including its endpoint registry.
  // Own both sides of this association so a reset cannot remove our backend.
  const endpoint = { id: "association-ponor", address: "203.0.113.42:443", region: "West", health: { admission_state: "confirmed" } };
  await page.route("**/api/karst/v1/relays", route => route.fulfill({ json: [endpoint] }));
  let services: Record<string, unknown>[] = [];
  let submitted: Record<string, unknown> | undefined;
  await page.route("**/api/karst/v1/relay-services**", async (route) => {
    if (route.request().url().endsWith("/publication")) { await route.fulfill({ json: { mode: "legacy" } }); return; }
    if (route.request().method() === "POST") {
      submitted = route.request().postDataJSON();
      services = [{ ...submitted, ponor_present: true }];
      await route.fulfill({ status: 201, json: submitted });
    } else if (route.request().method() === "DELETE") {
      services = [];
      await route.fulfill({ status: 204 });
    } else await route.fulfill({ json: services });
  });
  await page.goto("/#/relays");
  await page.getByText("Advanced publication and legacy settings", { exact: true }).click();
  await page.getByRole("button", { name: "Add legacy association", exact: true }).click();
  await expect(page.getByLabel("Ponor endpoint")).toHaveValue("");
  await page.getByLabel("Service name").fill("primary");
  await page.getByLabel("Ponor endpoint").selectOption(endpoint.id);
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await page.getByRole("button", { name: "Create service" }).click();
  await expect(page.getByRole("cell", { name: "primary", exact: true })).toBeVisible();
  expect(submitted).toEqual({ id: "primary", ponor_id: endpoint.id });
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  page.on("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", { name: "Remove configuration" }).click();
  await expect(page.getByRole("cell", { name: "primary", exact: true })).toHaveCount(0);
  const backend = page.locator("tbody tr").filter({ hasText: endpoint.address });
  await expect(backend).toHaveCount(1);
  await expect(backend.getByRole("button", { name: "Configure relay", exact: true })).toBeVisible();
});

test("missing Ponor registration remains visible for diagnosis", async ({ page }) => {
  await page.route("**/api/karst/v1/relays", (route) => route.fulfill({ json: [] }));
  await page.route("**/api/karst/v1/relay-services", (route) => route.fulfill({ json: [{ id: "degraded", ponor_id: "missing-ponor", ponor_present: false }] }));
  await page.goto("/#/relays");
  await expect(page.getByText("Endpoint registration missing")).toBeVisible();
});

test("an unavailable service API reports failure instead of an empty healthy view", async ({ page }) => {
  await page.route("**/api/karst/v1/relay-services", (route) => route.fulfill({ status: 404, json: { message: "Service API unavailable; upgrade control" } }));
  await page.goto("/#/relays");
  await expect(page.getByRole("alert")).toContainText("upgrade control");
  await expect(page.getByRole("heading", { name: "No relays configured" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Add relay", exact: true })).toBeVisible();
});

test("relay group access and exit service are configured through one reviewed form", async ({page}) => {
  let submitted: Record<string, unknown> | undefined;
  let services: Record<string, unknown>[] = [];
  await page.route("**/api/groups",route => route.fulfill({json:[{id:"group-sre",name:"sre"}]}));
  await page.route("**/api/karst/v1/relays",route => route.fulfill({json:[{id:"ponor",address:"203.0.113.1:443",region:"Denver",health:{admission_state:"confirmed"}}]}));
  await page.route("**/api/karst/v1/nodes?**",route => route.fulfill({json:{items:[{handle:"gateway-key",name:"Gateway host",platform:"Linux"}],next_cursor:null}}));
  await page.route("**/api/karst/v1/relay-services**",async route => {
    const path=new URL(route.request().url()).pathname;
    if(path.endsWith("/publication")){await route.fulfill({json:{mode:"services"}});return;}
    if(path.endsWith("/admission-targets")){await route.fulfill({json:[{relay_id:"ponor",refreshed_at:new Date().toISOString()}]});return;}
    if(route.request().method()==="POST") {submitted=route.request().postDataJSON();services=[{...submitted,ponor_present:true,revision:1}];await route.fulfill({json:services[0]});return;}
    await route.fulfill({json:services});
  });
  await page.goto("/#/relays");
  await page.getByRole("button",{name:"Configure relay",exact:true}).click();
  await page.getByLabel("Relay name",{exact:true}).fill("denver");
  await page.getByLabel("Registered relay",{exact:true}).selectOption("ponor");
  await page.getByRole("group",{name:"Groups allowed to use this relay",exact:true}).getByRole("checkbox",{name:"sre",exact:true}).check();
  await page.getByRole("checkbox",{name:"Offer internet access over IPv4",exact:true}).check();
  await page.getByLabel("Enrolled Gateway machine",{exact:true}).selectOption("gateway-key");
  expect((await new AxeBuilder({page}).analyze()).violations).toEqual([]);
  await page.getByRole("button",{name:"Review relay configuration",exact:true}).click();
  await expect(page.getByRole("button",{name:"Apply relay configuration",exact:true})).toBeDisabled();
  await page.getByRole("checkbox",{name:"I reviewed the allowed groups and internet access.",exact:true}).check();
  await page.getByRole("button",{name:"Apply relay configuration",exact:true}).click();
  await expect(page.getByRole("status")).toContainText("Relay configuration saved");
  expect(submitted).toMatchObject({id:"denver",ponor_id:"ponor",access_managed:true,allowed_groups:["group-sre"],exit_ipv4:true,gateway_handle:"gateway-key",metric:9999});
});

test("relay group restriction cannot be applied without admission enforcement", async ({page}) => {
  await page.route("**/api/groups",route => route.fulfill({json:[{id:"group-sre",name:"sre"}]}));
  await page.route("**/api/karst/v1/relays",route => route.fulfill({json:[{id:"ponor",address:"203.0.113.1:443",region:"Denver",health:{admission_state:"confirmed"}}]}));
  await page.route("**/api/karst/v1/relay-services**",route => route.fulfill({json:new URL(route.request().url()).pathname.endsWith("/publication")?{mode:"services"}:[]}));
  await page.goto("/#/relays");
  await page.getByRole("button",{name:"Configure relay",exact:true}).click();
  await page.getByLabel("Relay name",{exact:true}).fill("denver");
  await page.getByLabel("Registered relay",{exact:true}).selectOption("ponor");
  await page.getByRole("group",{name:"Groups allowed to use this relay",exact:true}).getByRole("checkbox",{name:"sre",exact:true}).check();
  await expect(page.getByRole("alert")).toContainText("no live admission-management connection");
  await expect(page.getByRole("button",{name:"Review relay configuration",exact:true})).toBeDisabled();
});

test("one relay inventory joins configuration and endpoint health without duplicating the backend", async ({ page }) => {
  await page.route("**/api/karst/v1/relays", route => route.fulfill({ json: [
    { id: "used", address: "203.0.113.10:443", region: "West", health: { admission_state: "confirmed" } },
    { id: "unused", address: "203.0.113.11:443", region: "East", health: { admission_state: "stale" } },
  ] }));
  await page.route("**/api/karst/v1/relay-services**", route => route.fulfill({ json: route.request().url().endsWith("/publication") ? { mode: "services" } : [
    { id: "production", ponor_id: "used", ponor_present: true, access_managed: true, allowed_groups: ["group-sre"], exit_ipv4: true },
  ] }));
  await page.goto("/#/relays");
  await expect(page.locator("tbody tr")).toHaveCount(2);
  const configured = page.locator("tbody tr").filter({ hasText: "production" });
  await expect(configured).toContainText("203.0.113.10:443");
  await expect(configured).toContainText("Allowed groups: 1");
  await expect(configured).toContainText("Internet egress: IPv4");
  await expect(page.getByRole("button", { name: "Services", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Ponor endpoints", exact: true })).toHaveCount(0);
  await configured.getByRole("button", { name: "Endpoint details" }).click();
  await expect(page.getByRole("dialog")).toContainText("Remove all relay configurations");
  await expect(page.getByRole("button", { name: "Remove endpoint" })).toHaveCount(0);
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await page.getByRole("button", { name: "Close", exact: true }).click();
  const unconfigured = page.locator("tbody tr").filter({ hasText: "203.0.113.11:443" });
  await expect(unconfigured).toContainText("Not published");
  await unconfigured.getByRole("button", { name: "Configure relay", exact: true }).click();
  await expect(page.getByLabel("Registered relay", { exact: true })).toHaveValue("unused");
});

test("endpoint diagnosis stays available when relay configuration cannot be loaded", async ({ page }) => {
  await page.route("**/api/karst/v1/relays", route => route.fulfill({ json: [
    { id: "backend", address: "203.0.113.12:443", health: { admission_state: "stale" } },
  ] }));
  await page.route("**/api/karst/v1/relay-services", route => route.fulfill({ status: 503, json: { message: "Configuration unavailable" } }));
  await page.goto("/#/relays");
  await expect(page.getByRole("alert")).toContainText("Configuration unavailable");
  const row = page.locator("tbody tr").filter({ hasText: "203.0.113.12:443" });
  await expect(row.getByRole("button", { name: "Configure relay", exact: true })).toBeDisabled();
  await expect(row).toContainText("Unknown");
  await row.getByRole("button", { name: "Endpoint details" }).click();
  await expect(page.getByRole("dialog")).toContainText("203.0.113.12:443");
  await expect(page.getByRole("button", { name: "Remove endpoint" })).toBeDisabled();
});
