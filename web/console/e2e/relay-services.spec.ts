// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { expect, test } from "@playwright/test";
import { AxeBuilder } from "@axe-core/playwright";

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
      services = [{ ...submitted, ponor_present: true, turn_present: true }];
      await route.fulfill({ status: 201, json: submitted });
    } else if (route.request().method() === "DELETE") {
      services = [];
      await route.fulfill({ status: 204 });
    } else await route.fulfill({ json: services });
  });
  await page.goto("/#/relays");
  await page.getByRole("button", { name: "Add service", exact: true }).click();
  await expect(page.getByLabel("Ponor endpoint")).toHaveValue("");
  await expect(page.getByRole("combobox", { name: "TURN backend", exact: true })).toHaveValue("");
  await page.getByLabel("Service name").fill("primary");
  await page.getByLabel("Ponor endpoint").selectOption({ index: 1 });
  const ponorID = await page.getByLabel("Ponor endpoint").inputValue();
  await page.getByRole("combobox", { name: "TURN backend", exact: true }).selectOption({ index: 1 });
  const turnID = await page.getByRole("combobox", { name: "TURN backend", exact: true }).inputValue();
  await page.getByLabel("TURN deployment").selectOption("external");
  await page.getByLabel("TURN operator").fill("Remote provider");
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await page.getByRole("button", { name: "Create service" }).click();
  await expect(page.getByRole("cell", { name: "primary", exact: true })).toBeVisible();
  expect(submitted).toEqual({ id: "primary", ponor_id: ponorID, turn_id: turnID, backend_kind: "external", backend_operator: "Remote provider" });
  await expect(page.getByText("TURN allocation: not observed")).toBeVisible();
  await expect(page.getByText("Remote provider")).toBeVisible();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  page.on("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", { name: "Remove association" }).click();
  await expect(page.getByRole("heading", { name: "No Relay services configured" })).toBeVisible();
  await page.getByRole("button", { name: "TURN backends" }).click();
  await expect(page.getByRole("cell", { name: "turn:turn.example.test:3478" })).toBeVisible();
});

test("missing TURN remains visible alongside registered Ponor and legacy TURN links work", async ({ page }) => {
  await page.route("**/api/karst/v1/relays", (route) => route.fulfill({ json: [{ id: "ponor", address: "203.0.113.1:443", health: { admission_state: "confirmed" } }] }));
  await page.route("**/api/karst/v1/relay-services", (route) => route.fulfill({ json: [{ id: "degraded", ponor_id: "ponor", turn_id: "missing-turn", backend_kind: "external", backend_operator: "Remote", ponor_present: true, turn_present: false }] }));
  await page.goto("/#/relays");
  await expect(page.getByText("Ponor admission: confirmed")).toBeVisible();
  await expect(page.getByText("TURN registration missing")).toBeVisible();
  await page.goto("/#/turns");
  await expect(page.getByRole("heading", { name: "TURN servers" })).toBeVisible();
});

test("TURN allocation denial and stale evidence remain independent of Ponor admission", async ({ page }) => {
  await page.route("**/api/karst/v1/relays", (route) => route.fulfill({ json: [{ id: "ponor", address: "203.0.113.1:443", health: { admission_state: "confirmed" } }] }));
  let state = "denied";
  await page.route("**/api/karst/v1/relay-services", (route) => route.fulfill({ json: [{ id: "observed", ponor_id: "ponor", turn_id: "turn-fixture-1", backend_kind: "external", backend_operator: "Remote", ponor_present: true, turn_present: true, turn_health: { source: "control_allocation_probe", state, last_result: "denied", observed_at: "2026-10-21T00:00:00Z", duration_ms: 12 } }] }));
  await page.goto("/#/relays");
  await expect(page.getByText("Ponor admission: confirmed")).toBeVisible();
  await expect(page.getByText("TURN allocation: denied")).toBeVisible();
  state = "stale";
  await page.getByRole("button", { name: "Refresh services" }).click();
  await expect(page.getByText("TURN allocation: stale")).toBeVisible();
  await expect(page.getByText("Last result: denied")).toBeVisible();
  await expect(page.getByText("Ponor admission: confirmed")).toBeVisible();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test("an unavailable service API reports failure instead of an empty healthy view", async ({ page }) => {
  await page.route("**/api/karst/v1/relay-services", (route) => route.fulfill({ status: 404, json: { message: "Service API unavailable; upgrade control" } }));
  await page.goto("/#/relays");
  await expect(page.getByRole("alert")).toContainText("upgrade control");
  await expect(page.getByRole("heading", { name: "No Relay services configured" })).toHaveCount(0);
  await page.getByRole("button", { name: "Ponor endpoints" }).click();
  await expect(page.getByRole("button", { name: "Add relay", exact: true })).toBeVisible();
});
