// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { expect, test } from "@playwright/test";
import { AxeBuilder } from "@axe-core/playwright";

const avenInventory = { schema_version: 1, avens: [], unresolved_routes: [], unsupported_routes: [] };
const connection = { id: "conn-aws", type: "aws", mode: "read_write", label: "Primary AWS", created_at: "2026-01-01T00:00:00Z", supports_allocation: true };
const resources = [{ code: "us-west-2", name: "US West (Oregon)", kind: "region", lat: 45.84, lon: -119.7 }];
const group = { id: "group-engineering", name: "engineering", peers_count: 32, resources_count: 0 };
// requireAuthorizedLocation (server) and AllocateEstavelle's own picker (console)
// both require the target already be in Authorized Locations -- matches
// resources[0]'s coordinates exactly, the same way a real admin would have
// added it from the discovered region before allocating against it.
const authorizedLocations = [{ id: "location-us-west-2", lat: 45.84, lon: -119.7, label: "US West (Oregon)" }];

async function mockEstavelleServicesPage(page: import("@playwright/test").Page) {
  await page.route("**/api/karst/v1/estavelles", (route) => route.fulfill({ json: [] }));
  await page.route("**/api/karst/v1/avens", (route) => route.fulfill({ json: avenInventory }));
  await page.route("**/api/groups", (route) => route.fulfill({ json: [group] }));
  await page.route("**/api/karst/v1/estavelle-services**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("/publication")) { await route.fulfill({ json: { mode: "legacy" } }); return; }
    if (path.endsWith("/admission-targets")) { await route.fulfill({ json: [] }); return; }
    await route.fulfill({ json: [] });
  });
  await page.route("**/api/karst/v1/infrastructure-connections", (route) => route.fulfill({ json: [connection] }));
  await page.route(`**/api/karst/v1/infrastructure-connections/${connection.id}/resources`, (route) => route.fulfill({ json: resources }));
  await page.route("**/api/karst/v1/locations", (route) => route.fulfill({ json: authorizedLocations }));
}

test("allocating a relay walks discovery, reviews, and posts the expected request", async ({ page }) => {
  const created: unknown[] = [];
  const stored: unknown[] = [];
  await mockEstavelleServicesPage(page);
  await page.route("**/api/karst/v1/estavelle-allocations", async (route) => {
    if (route.request().method() === "GET") { await route.fulfill({ json: stored }); return; }
    const body = route.request().postDataJSON();
    created.push(body);
    const allocation = { id: "alloc-1", ...body, state: "requested", revision: 1, created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" };
    stored.push(allocation);
    await route.fulfill({ status: 201, json: allocation });
  });

  await page.goto("/#/estavelles");
  await page.getByRole("button", { name: "Add estavelle" }).click();
  await page.getByRole("button", { name: "No, provision one for me" }).click();
  await expect(page.getByRole("heading", { name: "Allocate an estavelle" })).toBeVisible();

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

  await expect(page.getByText("Estavelle allocation requested.", { exact: false })).toBeVisible();
  expect(created).toEqual([{ name: "denver", infra_connection_id: connection.id, location: "us-west-2", relay_transport: true, permitted_groups: [group.id] }]);
  await expect(page.getByRole("cell", { name: "denver" })).toBeVisible();
});

test("a ready allocation offers deprovision; a requested one offers remove instead", async ({ page }) => {
  const ready = { id: "alloc-ready", name: "ready-host", infra_connection_id: connection.id, location: "us-west-2", permitted_groups: [group.id], state: "ready", revision: 4 };
  const requested = { id: "alloc-requested", name: "pending-host", infra_connection_id: connection.id, location: "us-west-2", permitted_groups: [group.id], state: "requested", revision: 1 };
  await mockEstavelleServicesPage(page);
  await page.route("**/api/karst/v1/estavelle-allocations", (route) => route.fulfill({ json: [ready, requested] }));

  let deprovisionBody: unknown;
  await page.route(`**/api/karst/v1/estavelle-allocations/${ready.id}/deprovision`, async (route) => {
    deprovisionBody = route.request().postDataJSON();
    await route.fulfill({ json: { ...ready, state: "revoking", revision: 5 } });
  });
  let deletedId: string | undefined;
  await page.route(`**/api/karst/v1/estavelle-allocations/${requested.id}**`, async (route) => {
    if (route.request().method() === "DELETE") { deletedId = requested.id; await route.fulfill({ status: 204 }); return; }
    await route.continue();
  });

  page.on("dialog", (dialog) => dialog.accept());
  await page.goto("/#/estavelles");

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

test("only resources already in Authorized Locations are offered", async ({ page }) => {
  const unauthorized = { code: "eu-west-1", name: "Europe (Ireland)", kind: "region", lat: 53.3498, lon: -6.2603 };
  await page.route("**/api/karst/v1/estavelles", (route) => route.fulfill({ json: [] }));
  await page.route("**/api/karst/v1/avens", (route) => route.fulfill({ json: avenInventory }));
  await page.route("**/api/groups", (route) => route.fulfill({ json: [group] }));
  await page.route("**/api/karst/v1/estavelle-services**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("/publication")) { await route.fulfill({ json: { mode: "legacy" } }); return; }
    if (path.endsWith("/admission-targets")) { await route.fulfill({ json: [] }); return; }
    await route.fulfill({ json: [] });
  });
  await page.route("**/api/karst/v1/estavelle-allocations", (route) => route.fulfill({ json: [] }));
  await page.route("**/api/karst/v1/infrastructure-connections", (route) => route.fulfill({ json: [connection] }));
  // Two discovered regions; only one (resources[0]) is in Authorized Locations.
  await page.route(`**/api/karst/v1/infrastructure-connections/${connection.id}/resources`, (route) => route.fulfill({ json: [...resources, unauthorized] }));
  await page.route("**/api/karst/v1/locations", (route) => route.fulfill({ json: authorizedLocations }));

  await page.goto("/#/estavelles");
  await page.getByRole("button", { name: "Add estavelle" }).click();
  await page.getByRole("button", { name: "No, provision one for me" }).click();
  await page.getByLabel("Infrastructure connection", { exact: true }).selectOption(connection.id);

  const location = page.getByLabel("Location", { exact: true });
  await expect(location.locator("option", { hasText: "US West (Oregon)" })).toHaveCount(1);
  await expect(location.locator("option", { hasText: "Europe (Ireland)" })).toHaveCount(0);
  await expect(page.getByText("Only locations already in Authorized Locations are offered.", { exact: false })).toBeVisible();
});

test("no infrastructure connections configured is explained, not a dead end", async ({ page }) => {
  await mockEstavelleServicesPage(page);
  await page.route("**/api/karst/v1/estavelle-allocations", (route) => route.fulfill({ json: [] }));
  await page.route("**/api/karst/v1/infrastructure-connections", (route) => route.fulfill({ json: [] }));
  await page.goto("/#/estavelles");
  await page.getByRole("button", { name: "Add estavelle" }).click();
  await page.getByRole("button", { name: "No, provision one for me" }).click();
  await expect(page.getByText("Add an infrastructure connection in Settings first.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Review allocation" })).toBeDisabled();
});
