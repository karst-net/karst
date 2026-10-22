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
  await page.getByRole("button", { name: "Change modes" }).click();
  await page.getByRole("checkbox", { name: "Enable Ponor", exact: true }).uncheck();
  await expect(page.getByRole("button", { name: "Apply modes" })).toBeDisabled();
  await page.getByRole("checkbox", { name: "I understand mode changes may interrupt client connectivity." }).check();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await page.getByRole("button", { name: "Apply modes" }).click();
  await expect(page.getByText("Ponor disabled", { exact: false })).toBeVisible();
  expect(submitted).toEqual({ ponor_enabled: false, acknowledge_connectivity_change: true });
  await page.getByRole("button", { name: "Change modes" }).click();
  await expect(page.getByRole("checkbox", { name: "Enable Ponor", exact: true })).not.toBeChecked();
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
  await page.getByRole("button", { name: "Add service", exact: true }).click();
  await expect(page.getByLabel("Ponor endpoint")).toHaveValue("");
  await page.getByLabel("Service name").fill("primary");
  await page.getByLabel("Ponor endpoint").selectOption({ index: 1 });
  const ponorID = await page.getByLabel("Ponor endpoint").inputValue();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await page.getByRole("button", { name: "Create service" }).click();
  await expect(page.getByRole("cell", { name: "primary", exact: true })).toBeVisible();
  expect(submitted).toEqual({ id: "primary", ponor_id: ponorID });
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  page.on("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", { name: "Remove association" }).click();
  await expect(page.getByRole("heading", { name: "No Relay services configured" })).toBeVisible();
});

test("missing Ponor registration remains visible for diagnosis", async ({ page }) => {
  await page.route("**/api/karst/v1/relays", (route) => route.fulfill({ json: [] }));
  await page.route("**/api/karst/v1/relay-services", (route) => route.fulfill({ json: [{ id: "degraded", ponor_id: "missing-ponor", ponor_present: false }] }));
  await page.goto("/#/relays");
  await expect(page.getByText("Ponor registration missing")).toBeVisible();
});

test("an unavailable service API reports failure instead of an empty healthy view", async ({ page }) => {
  await page.route("**/api/karst/v1/relay-services", (route) => route.fulfill({ status: 404, json: { message: "Service API unavailable; upgrade control" } }));
  await page.goto("/#/relays");
  await expect(page.getByRole("alert")).toContainText("upgrade control");
  await expect(page.getByRole("heading", { name: "No Relay services configured" })).toHaveCount(0);
  await page.getByRole("button", { name: "Ponor endpoints" }).click();
  await expect(page.getByRole("button", { name: "Add relay", exact: true })).toBeVisible();
});
