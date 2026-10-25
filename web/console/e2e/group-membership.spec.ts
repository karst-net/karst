// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { expect, test, type Page } from "@playwright/test";
import { AxeBuilder } from "@axe-core/playwright";

async function fixture(page: Page) {
  const state = { revision: 1, puts: 0, reject: false, header: true, resources: [{ id: "network", type: "subnet" }], members: ["laptop"], name: "Engineering", grants: [] as Record<string, unknown>[] };
  const group = () => ({ id: "engineering", name: state.name, issued: "api", peers_count: state.members.length, peers: state.members.map(id => ({ id, name: id === "laptop" ? "Old laptop" : "New laptop" })), resources_count: 1, resources: state.resources });
  await page.route("**/api/groups", route => route.fulfill({ json: [group()] }));
  await page.route("**/api/groups/engineering", async route => {
    if (route.request().method() === "PUT") {
      state.puts++;
      expect(route.request().headers()["if-match"]).toBe(`"group-${String(state.revision).padStart(64,"0")}"`);
      if (state.reject) { await route.fulfill({ status: 412, json: { message: "group changed; reload before saving" } }); return; }
      const body = route.request().postDataJSON();
      expect(body.resources).toEqual(state.resources);
      state.members = body.peers; state.name = body.name; state.revision++;
      await route.fulfill({ json: group() });
    } else await route.fulfill({ json: group(), headers: state.header ? { ETag: `"group-${String(state.revision).padStart(64,"0")}"` } : {} });
  });
  await page.route("**/api/peers", route => route.fulfill({ json: [{ id: "laptop", name: "Old laptop" }, { id: "new", name: "New laptop" }] }));
  await page.route("**/api/karst/v1/policy", route => route.fulfill({ json: { version: 1, document: JSON.stringify({ grants: state.grants }) } }));
  await page.route("**/api/karst/v1/relay-services", route => route.fulfill({ json: [{ id: "Denver", allowed_groups: ["engineering"] }] }));
  await page.route("**/api/karst/v1/invitations", route => route.fulfill({ json: [] }));
  await page.route("**/api/routes", route => route.fulfill({ json: [] }));
  await page.route("**/api/dns/nameservers", route => route.fulfill({ json: [] }));
  await page.route("**/api/dns/settings", route => route.fulfill({ json: { disabled_management_groups: [] } }));
  await page.route("**/api/users", route => route.fulfill({ json: [] }));
  return state;
}
async function edit(page: Page) {
  await page.goto("/#/groups");
  await page.getByRole("button", { name: "Members of Engineering", exact: true }).click();
  await page.getByRole("checkbox", { name: "Old laptop", exact: true }).uncheck();
  await page.getByRole("checkbox", { name: "New laptop", exact: true }).check();
  await page.getByRole("button", { name: "Review membership changes" }).click();
}

test("membership review names added and removed machines, resource assignments and requires acknowledgment", async ({ page }) => {
  const state = await fixture(page);
  state.grants = [{ id: "web", name: "Production web", source_groups: ["engineering"], target_groups: ["servers"], ports: "443" }];
  await edit(page);
  const dialog = page.getByRole("dialog");
  await expect(dialog).toContainText("Machines gaining group accessNew laptop");
  await expect(dialog).toContainText("Machines losing group accessOld laptop");
  await expect(dialog.getByRole("link", { name: "Relay: Denver" })).toBeVisible();
  await expect(dialog.getByRole("link", { name: "Access grant: Production web" })).toBeVisible();
  const apply = dialog.getByRole("button", { name: "Apply membership changes" });
  await expect(apply).toBeDisabled(); expect(state.puts).toBe(0);
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await dialog.getByRole("checkbox", { name: "I reviewed the machines and group assignments.", exact: true }).check();
  await apply.focus(); await page.keyboard.press("Enter");
  await expect(page.getByRole("status")).toContainText("Group membership saved");
  expect(state.members).toEqual(["new"]); expect(state.puts).toBe(1);
});

test("a changed group snapshot blocks submission until explicit reload", async ({ page }) => {
  const state = await fixture(page); await edit(page);
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("checkbox", { name: "I reviewed the machines and group assignments.", exact: true }).check(); state.revision++;
  await dialog.getByRole("button", { name: "Apply membership changes" }).click();
  await expect(dialog.getByRole("alert")).toContainText("group changed since you opened");
  expect(state.puts).toBe(0);
  await expect(dialog.getByRole("button", { name: "Apply membership changes" })).toBeDisabled();
  await dialog.getByRole("button", { name: "Reload latest group" }).click();
  await expect(dialog.getByRole("checkbox", { name: "Old laptop", exact: true })).toBeChecked();
});

test("a write-time conflict keeps the draft and never retries automatically", async ({ page }) => {
  const state = await fixture(page); await edit(page); state.reject = true;
  const dialog = page.getByRole("dialog"); await dialog.getByRole("checkbox", { name: "I reviewed the machines and group assignments.", exact: true }).check();
  await dialog.getByRole("button", { name: "Apply membership changes" }).click();
  await expect(dialog.getByRole("alert")).toContainText("group changed; reload before saving");
  await expect(dialog.getByRole("button", { name: "Apply membership changes" })).toBeDisabled();
  expect(state.puts).toBe(1); expect(state.members).toEqual(["laptop"]);
});

test("changed assignments require another review and dependency failures cannot apply", async ({ page }) => {
  const state = await fixture(page); await edit(page);
  const dialog = page.getByRole("dialog"); await dialog.getByRole("checkbox", { name: "I reviewed the machines and group assignments.", exact: true }).check();
  state.grants = [{ id: "new", name: "New access", source_groups: ["engineering"], target_groups: ["servers"], ports: "*" }];
  // A policy edit increments its version in production; alter the dependency
  // list here to exercise the independently loaded impact snapshot.
  await dialog.getByRole("button", { name: "Apply membership changes" }).click();
  await expect(dialog.getByRole("alert")).toContainText("assignments changed");
  await expect(dialog.getByRole("checkbox", { name: "I reviewed the machines and group assignments.", exact: true })).not.toBeChecked(); expect(state.puts).toBe(0);
  await page.route("**/api/karst/v1/relay-services", route => route.fulfill({ status: 503, json: { message: "Relay inventory unavailable" } }));
  await dialog.getByRole("checkbox", { name: "I reviewed the machines and group assignments.", exact: true }).check();
  await dialog.getByRole("button", { name: "Apply membership changes" }).click();
  await expect(dialog.getByRole("alert")).toContainText("Relay inventory unavailable"); expect(state.puts).toBe(0);
});

test("rename preserves the opened assignments and handles a conflict", async ({ page }) => {
  const state = await fixture(page); await page.goto("/#/groups");
  await page.getByRole("button", { name: "Rename", exact: true }).click();
  await page.getByLabel("New group name").fill("Infrastructure"); state.reject = true;
  await page.getByRole("button", { name: "Save name" }).click();
  await expect(page.getByRole("dialog").getByRole("alert")).toContainText("group changed");
  await expect(page.getByRole("button", { name: "Save name" })).toBeDisabled();
  state.reject = false;
  await page.getByRole("button", { name: "Reload latest group" }).click();
  await page.getByLabel("New group name").fill("Infrastructure");
  await page.getByRole("button", { name: "Save name" }).click();
  await expect(page.getByRole("status")).toContainText("now named Infrastructure"); expect(state.members).toEqual(["laptop"]);
});

test("older servers without revisions cannot silently accept unsafe group edits", async ({ page }) => {
  const state = await fixture(page); state.header = false; await page.goto("/#/groups");
  await page.getByRole("button", { name: "Members of Engineering", exact: true }).click();
  await expect(page.getByRole("dialog").getByRole("alert")).toContainText("Upgrade the control server"); expect(state.puts).toBe(0);
});
