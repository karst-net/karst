// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { expect, test } from "@playwright/test";
import { AxeBuilder } from "@axe-core/playwright";

const gatewayInventory = { schema_version: 1, gateways: [], unresolved_routes: [], unsupported_routes: [] };
const connection = { id: "conn-aws", type: "aws", mode: "read_write", label: "Primary AWS", created_at: "2026-01-01T00:00:00Z" };
const resources = [{ code: "us-west-2", name: "US West (Oregon)", kind: "region", lat: 45.84, lon: -119.7 }];
const group = { id: "group-engineering", name: "engineering", peers_count: 32, resources_count: 0 };

async function mockRelayServicesPage(page: import("@playwright/test").Page) {
  await page.route("**/api/karst/v1/relays", (route) => route.fulfill({ json: [] }));
  await page.route("**/api/karst/v1/gateways", (route) => route.fulfill({ json: gatewayInventory }));
  await page.route("**/api/groups", (route) => route.fulfill({ json: [group] }));
  await page.route("**/api/karst/v1/relay-services**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("/publication")) { await route.fulfill({ json: { mode: "legacy" } }); return; }
    if (path.endsWith("/admission-targets")) { await route.fulfill({ json: [] }); return; }
    await route.fulfill({ json: [] });
  });
  await page.route("**/api/karst/v1/infrastructure-connections", (route) => route.fulfill({ json: [connection] }));
  await page.route(`**/api/karst/v1/infrastructure-connections/${connection.id}/resources`, (route) => route.fulfill({ json: resources }));
}

test("allocating a relay walks discovery, reviews, and posts the expected request", async ({ page }) => {
  const created: unknown[] = [];
  const stored: unknown[] = [];
  await mockRelayServicesPage(page);
  await page.route("**/api/karst/v1/relay-allocations", async (route) => {
    if (route.request().method() === "GET") { await route.fulfill({ json: stored }); return; }
    const body = route.request().postDataJSON();
    created.push(body);
    const allocation = { id: "alloc-1", ...body, state: "requested", revision: 1, created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" };
    stored.push(allocation);
    await route.fulfill({ status: 201, json: allocation });
  });

  await page.goto("/#/relays");
  await page.getByRole("button", { name: "Allocate a relay" }).click();
  await expect(page.getByRole("heading", { name: "Allocate a relay" })).toBeVisible();

  await page.getByLabel("Name", { exact: true }).fill("denver");
  await page.getByLabel("Infrastructure connection", { exact: true }).selectOption(connection.id);
  await page.getByLabel("Location", { exact: true }).selectOption("us-west-2");
  await page.getByRole("checkbox", { name: "engineering" }).check();

  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);

  await page.getByRole("button", { name: "Review allocation" }).click();
  await expect(page.getByText("Permitted groups: engineering.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Apply allocation" })).toBeDisabled();
  await page.getByRole("checkbox", { name: "I reviewed this allocation." }).check();
  await page.getByRole("button", { name: "Apply allocation" }).click();

  await expect(page.getByText("Relay allocation requested.", { exact: false })).toBeVisible();
  expect(created).toEqual([{ name: "denver", infra_connection_id: connection.id, location: "us-west-2", relay_transport: true, permitted_groups: [group.id] }]);
  await expect(page.getByRole("cell", { name: "denver" })).toBeVisible();
});

test("a ready allocation offers deprovision; a requested one offers remove instead", async ({ page }) => {
  const ready = { id: "alloc-ready", name: "ready-host", infra_connection_id: connection.id, location: "us-west-2", permitted_groups: [group.id], state: "ready", revision: 4 };
  const requested = { id: "alloc-requested", name: "pending-host", infra_connection_id: connection.id, location: "us-west-2", permitted_groups: [group.id], state: "requested", revision: 1 };
  await mockRelayServicesPage(page);
  await page.route("**/api/karst/v1/relay-allocations", (route) => route.fulfill({ json: [ready, requested] }));

  let deprovisionBody: unknown;
  await page.route(`**/api/karst/v1/relay-allocations/${ready.id}/deprovision`, async (route) => {
    deprovisionBody = route.request().postDataJSON();
    await route.fulfill({ json: { ...ready, state: "revoking", revision: 5 } });
  });
  let deletedId: string | undefined;
  await page.route(`**/api/karst/v1/relay-allocations/${requested.id}**`, async (route) => {
    if (route.request().method() === "DELETE") { deletedId = requested.id; await route.fulfill({ status: 204 }); return; }
    await route.continue();
  });

  page.on("dialog", (dialog) => dialog.accept());
  await page.goto("/#/relays");

  const readyRow = page.getByRole("row", { name: /ready-host/ });
  // Scoped by Status's own class, not plain text: its label sits right
  // next to an aria-hidden icon glyph with no separator ("●Ready"), and
  // "ready-host" itself contains "ready" case-insensitively.
  await expect(readyRow.locator(".status-healthy")).toContainText("Ready");
  await expect(readyRow.getByRole("button", { name: "Deprovision" })).toBeVisible();
  await expect(readyRow.getByRole("button", { name: "Remove" })).toHaveCount(0);
  await readyRow.getByRole("button", { name: "Deprovision" }).click();
  await expect.poll(() => deprovisionBody).toEqual({ revision: 4, acknowledge_deprovision: true });

  const requestedRow = page.getByRole("row", { name: /pending-host/ });
  await expect(requestedRow.locator(".status-unknown")).toContainText("Requested");
  await expect(requestedRow.getByRole("button", { name: "Deprovision" })).toHaveCount(0);
  await requestedRow.getByRole("button", { name: "Remove" }).click();
  await expect.poll(() => deletedId).toBe(requested.id);
});

test("no infrastructure connections configured is explained, not a dead end", async ({ page }) => {
  await mockRelayServicesPage(page);
  await page.route("**/api/karst/v1/relay-allocations", (route) => route.fulfill({ json: [] }));
  await page.route("**/api/karst/v1/infrastructure-connections", (route) => route.fulfill({ json: [] }));
  await page.goto("/#/relays");
  await page.getByRole("button", { name: "Allocate a relay" }).click();
  await expect(page.getByText("Add an infrastructure connection in Settings first.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Review allocation" })).toBeDisabled();
});
