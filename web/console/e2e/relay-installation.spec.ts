// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { expect, test } from "@playwright/test";
import { AxeBuilder } from "@axe-core/playwright";
import { readFile } from "node:fs/promises";

const key = "A".repeat(3456);
const entry = { address: "203.0.113.7:443", tls_server_name: "relay.example.com", identity_key: key, region: "denver" };
const receipt = { schema_version: 1, kind: "karst-relay-installation", relay_id: "ab".repeat(32), entry };

async function fixture(page: import("@playwright/test").Page, existing = false) {
  let created = false;
  let requests = 0;
  await page.route("**/api/karst/v1/locations", route => route.fulfill({ json: [] }));
  await page.route("**/api/groups**", route => route.fulfill({ json: [{ id: "engineering", name: "Engineering" }] }));
  await page.route("**/api/karst/v1/relay-services**", route => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("/publication")) return route.fulfill({ json: { mode: "services" } });
    if (path.endsWith("/admission-targets")) return route.fulfill({ json: [{ relay_id: "installed", refreshed_at: new Date().toISOString() }] });
    return route.fulfill({ json: [] });
  });
  await page.route("**/api/karst/v1/relays", async route => {
    if (route.request().method() === "POST") { requests++; expect(route.request().postDataJSON()).toEqual(entry); created = true; return route.fulfill({ status: 201, json: { ...entry, id: "installed", health: { admission_state: "unknown" } } }); }
    await route.fulfill({ json: existing || created ? [{ ...entry, id: "installed", health: { admission_state: "unknown" } }] : [] });
  });
  return () => requests;
}

test("downloaded installation handoff contains settings without reporting deployment success", async ({ page }) => {
  const requests = await fixture(page);
  await page.goto("/#/relays");
  await page.getByRole("button", { name: "Install a local relay", exact: true }).click();
  await expect(page.getByRole("button", { name: "Download installation handoff" })).toBeDisabled();
  await page.getByLabel("Installation relay address").fill(entry.address);
  await page.getByLabel("TLS server name", { exact: true }).fill(entry.tls_server_name);
  await page.getByLabel("Region", { exact: true }).fill(entry.region);
  await page.getByRole("checkbox", { name: "I reviewed the deployment scope" }).check();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  const downloadEvent = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download installation handoff" }).click();
  const download = await downloadEvent;
  expect(download.suggestedFilename()).toBe("karst-relay-install.py");
  const script = await readFile((await download.path())!, "utf8");
  expect(script).toContain('"KARST_RELAY_REQUIRE_MANAGED": "true"');
  expect(script).not.toContain("SETTINGS = None");
  const encoded = script.match(/bytes.fromhex\("([a-f0-9]+)"\)/)![1];
  expect(JSON.parse(Buffer.from(encoded, "hex").toString("utf8")).address).toBe(entry.address);
  await expect(page.getByText("Handoff downloaded. Installation has not run.")).toBeVisible();
  expect(requests()).toBe(0);
});

test("receipt registration leads to named group configuration without key entry", async ({ page }) => {
  const requests = await fixture(page);
  await page.goto("/#/relays");
  await page.getByRole("button", { name: "Add relay", exact: true }).click();
  await page.getByLabel("Installation receipt").setInputFiles({ name: "receipt.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(receipt)) });
  await expect(page.getByText("Installation receipt loaded for", { exact: false })).toBeVisible();
  await expect(page.getByLabel("Relay identity key")).toBeHidden();
  expect(requests()).toBe(0);
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await page.getByRole("button", { name: "Register installed relay" }).click();
  await expect(page.getByRole("dialog", { name: "Configure a relay" })).toBeVisible();
  await expect(page.getByRole("checkbox", { name: "Engineering", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Review relay configuration" })).toBeDisabled();
  expect(requests()).toBe(1);
});

test("reimporting an installed identity reuses its registration", async ({ page }) => {
  const requests = await fixture(page, true);
  await page.goto("/#/relays");
  await page.getByRole("button", { name: "Add relay", exact: true }).click();
  await page.getByLabel("Installation receipt").setInputFiles({ name: "receipt.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(receipt)) });
  await page.getByRole("button", { name: "Register installed relay" }).click();
  await expect(page.getByRole("dialog", { name: "Configure a relay" })).toBeVisible();
  expect(requests()).toBe(0);
});

test("unrelated receipts show an error without registration or stale form data", async ({ page }) => {
  const requests = await fixture(page);
  await page.goto("/#/relays");
  await page.getByRole("button", { name: "Add relay", exact: true }).click();
  await page.getByLabel("Installation receipt").setInputFiles({ name: "receipt.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(receipt)) });
  await expect(page.getByRole("button", { name: "Register installed relay" })).toBeVisible();
  await page.getByLabel("Installation receipt").setInputFiles({ name: "wrong.json", mimeType: "application/json", buffer: Buffer.from("{}") });
  await expect(page.getByRole("alert")).toContainText("Choose a relay installation receipt");
  await expect(page.getByLabel("Relay address")).toHaveValue("");
  expect(requests()).toBe(0);
});
