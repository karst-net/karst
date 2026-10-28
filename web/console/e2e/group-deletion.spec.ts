// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { expect, test, type Page } from "@playwright/test";
import { AxeBuilder } from "@axe-core/playwright";

async function fixture(page: Page) {
  const state = { members: [{ id: "peer-1", name: "Engineering laptop" }], deleted: 0, document: {} as Record<string, unknown>, relays: [] as Record<string, unknown>[], invitations: [] as Record<string, unknown>[] };
  const group = () => ({ id: "engineering", name: "Engineering", issued: "api", peers_count: state.members.length, peers: state.members, resources_count: 0, resources: [] });
  await page.route("**/api/groups", route => route.fulfill({ json: state.deleted ? [] : [group()] }));
  await page.route("**/api/groups/engineering", async route => {
    if (route.request().method() === "DELETE") { state.deleted++; await route.fulfill({ json: {} }); }
    else await route.fulfill({ json: group() });
  });
  await page.route("**/api/karst/v1/policy", route => route.fulfill({ json: { version: 1, document: JSON.stringify(state.document) } }));
  await page.route("**/api/karst/v1/relay-services", route => route.fulfill({ json: state.relays }));
  await page.route("**/api/karst/v1/invitations", route => route.fulfill({ json: state.invitations }));
  await page.route("**/api/routes", route => route.fulfill({ json: [] }));
  await page.route("**/api/dns/nameservers", route => route.fulfill({ json: [] }));
  await page.route("**/api/dns/settings", route => route.fulfill({ json: { disabled_management_groups: [] } }));
  await page.route("**/api/users", route => route.fulfill({ json: [] }));
  return state;
}

async function openReview(page: Page) {
  await page.goto("/#/groups");
  await page.getByRole("button", { name: "Delete", exact: true }).click();
  await expect(page.getByRole("dialog")).toBeVisible();
}

test("group deletion names access and relay dependencies and provides owning-form links", async ({ page }) => {
  const state = await fixture(page);
  state.document = { grants: [{ id: "web", name: "Production HTTPS", source_groups: ["engineering"], target_groups: ["servers"], ports: "443" }], groupBindings: { "group:staff": "engineering" } };
  state.relays = [{ id: "Denver", ponor_id: "backend", access_managed: true, allowed_groups: ["engineering"] }];
  await openReview(page);
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByRole("link", { name: "Access grant: Production HTTPS" })).toHaveAttribute("href", "#/groups/access");
  await expect(dialog.getByRole("link", { name: "Relay: Denver" })).toHaveAttribute("href", "#/relays");
  await expect(dialog.getByRole("link", { name: "Legacy membership mapping: staff" })).toBeVisible();
  await expect(dialog.getByRole("button", { name: "Delete group", exact: true })).toBeDisabled();
  expect(state.deleted).toBe(0);
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test("deletion requires acknowledgment and rechecks changed membership before deleting", async ({ page }) => {
  const state = await fixture(page);
  await openReview(page);
  const dialog = page.getByRole("dialog");
  const submit = dialog.getByRole("button", { name: "Delete group", exact: true });
  const acknowledge = dialog.getByRole("checkbox", { name: "I reviewed the impact and want to delete this group." });
  await expect(submit).toBeDisabled();
  await acknowledge.check();
  state.members.push({ id: "peer-2", name: "Second laptop" });
  await submit.click();
  await expect(dialog.getByRole("alert")).toContainText("access changed");
  await expect(dialog).toContainText("2 machines");
  await expect(acknowledge).not.toBeChecked();
  expect(state.deleted).toBe(0);
  await acknowledge.check();
  await submit.focus(); await page.keyboard.press("Enter");
  await expect(page.getByRole("status")).toContainText("Group Engineering was deleted");
  await expect(page.getByRole("status")).toContainText("Group Engineering was deleted");
  expect(state.deleted).toBe(1);
});

test("a new dependency added after review prevents deletion", async ({ page }) => {
  const state = await fixture(page);
  await openReview(page);
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("checkbox").check();
  state.relays = [{ id: "New relay", allowed_groups: ["engineering"] }];
  await dialog.getByRole("button", { name: "Delete group", exact: true }).click();
  await expect(dialog.getByRole("link", { name: "Relay: New relay" })).toBeVisible();
  await expect(dialog.getByRole("button", { name: "Delete group", exact: true })).toBeDisabled();
  expect(state.deleted).toBe(0);
});

test("unavailable dependency data blocks deletion and a fresh review can recover", async ({ page }) => {
  const state = await fixture(page);
  await page.route("**/api/karst/v1/relay-services", route => route.fulfill({ status: 503, json: { message: "Relay configuration unavailable" } }));
  await openReview(page);
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByRole("alert")).toContainText("Relay configuration unavailable");
  await expect(dialog.getByRole("button", { name: "Delete group", exact: true })).toBeDisabled();
  await page.unroute("**/api/karst/v1/relay-services");
  await page.route("**/api/karst/v1/relay-services", route => route.fulfill({ json: [] }));
  await dialog.getByRole("button", { name: "Refresh review" }).click();
  await expect(dialog).toContainText("No dependencies found");
  expect(state.deleted).toBe(0);
});

test("active invitations block deletion while terminal invitations remain history", async ({ page }) => {
  const state = await fixture(page);
  state.invitations = [{ id: "active", name: "Fleet enrollment", groups: ["engineering"], state: "pending" }, { id: "old", name: "Old laptop", groups: ["engineering"], state: "revoked" }];
  await openReview(page);
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByRole("link", { name: "Active device invitation: Fleet enrollment" })).toHaveAttribute("href", "#/machines/add");
  await expect(dialog).toContainText("Old laptop (revoked)");
  state.invitations[0].state = "expired";
  await dialog.getByRole("button", { name: "Refresh review" }).click();
  await expect(dialog).toContainText("No dependencies found");
  await dialog.getByRole("checkbox").check();
  await dialog.getByRole("button", { name: "Delete group", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("Group Engineering was deleted");
  expect(state.deleted).toBe(1);
});

test("an account with no policy version can still review and delete an unused group", async ({ page }) => {
  const state = await fixture(page);
  await page.route("**/api/karst/v1/policy", route => route.fulfill({ status: 404, json: { message: "no Karst policy version" } }));
  await openReview(page);
  const dialog = page.getByRole("dialog");
  await expect(dialog).toContainText("No dependencies found");
  await dialog.getByRole("checkbox").check();
  await dialog.getByRole("button", { name: "Delete group", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("Group Engineering was deleted");
  expect(state.deleted).toBe(1);
});
