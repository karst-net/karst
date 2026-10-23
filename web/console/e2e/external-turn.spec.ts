// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { expect, test, type Page } from "@playwright/test";

type Row = { id: string; position: number; uri: string; username: string; created_at: string; updated_at: string };

/** Stubs the whole /external-turn-servers surface against an in-memory
 *  fixture scoped to this test -- the real karst-api-mock.mjs process is
 *  shared across the whole run, so relying on it here would leak state
 *  between tests (see gateways.spec.ts for the same reasoning). */
async function stubExternalTurnServers(page: Page) {
  let rows: Row[] = [];
  let nextId = 1;
  // One handler for the whole surface, dispatching on the parsed path --
  // registering "/reorder" and "/*" as two separate page.route() globs
  // left them racing for the same request (Playwright gives the
  // most-recently-registered matching route priority, and "/*" matches
  // "/reorder" too), so "/reorder" never actually ran.
  await page.route("**/api/karst/v1/external-turn-servers**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const suffix = path.replace(/^.*\/external-turn-servers/, "");
    if (suffix === "" && request.method() === "GET") return route.fulfill({ json: rows });
    if (suffix === "" && request.method() === "POST") {
      const body = request.postDataJSON() as { uri: string; username: string; credential: string };
      const now = new Date().toISOString();
      const row: Row = { id: `turn-${nextId++}`, position: rows.length, uri: body.uri, username: body.username, created_at: now, updated_at: now };
      rows.push(row);
      return route.fulfill({ status: 201, json: row });
    }
    if (suffix === "/reorder" && request.method() === "PUT") {
      const body = request.postDataJSON() as { ids: string[] };
      rows = body.ids.map((id, position) => ({ ...rows.find((row) => row.id === id)!, position }));
      return route.fulfill({ json: rows });
    }
    const id = suffix.slice(1);
    if (id && request.method() === "PUT") {
      const body = request.postDataJSON() as { uri: string; username: string; credential?: string };
      const row = rows.find((item) => item.id === id);
      if (!row) return route.fulfill({ status: 404, json: { message: "not found", code: 404 } });
      row.uri = body.uri;
      row.username = body.username;
      row.updated_at = new Date().toISOString();
      return route.fulfill({ json: row });
    }
    if (id && request.method() === "DELETE") {
      rows = rows.filter((row) => row.id !== id).map((row, position) => ({ ...row, position }));
      return route.fulfill({ status: 204, body: "" });
    }
    return route.continue();
  });
}

test("adding an external TURN server never shows the credential back", async ({ page }) => {
  await stubExternalTurnServers(page);
  await page.goto("/#/external-turn");
  await expect(page.getByText("No external TURN servers configured")).toBeVisible();

  await page.getByRole("button", { name: "Add external TURN server" }).click();
  await page.getByLabel("Server URI", { exact: true }).fill("turns:turn.example.com:5349");
  await page.getByLabel("Server username", { exact: true }).fill("node");
  await page.getByLabel("Server credential", { exact: true }).fill("s3cret-password");
  await page.getByRole("button", { name: "Add server" }).click();

  const section = page.locator("section", { has: page.getByRole("heading", { name: "External TURN servers", exact: true }) });
  await expect(section).toContainText("turns:turn.example.com:5349");
  await expect(section).toContainText("node");
  await expect(page.locator("body")).not.toContainText("s3cret-password");
});

test("a plain turn: uri is rejected before any request is made", async ({ page }) => {
  await stubExternalTurnServers(page);
  let created = false;
  await page.route("**/api/karst/v1/external-turn-servers", (route) => {
    if (route.request().method() === "POST") created = true;
    return route.continue();
  });
  await page.goto("/#/external-turn");
  await page.getByRole("button", { name: "Add external TURN server" }).click();
  await page.getByLabel("Server URI", { exact: true }).fill("turn:turn.example.com:3478");
  await page.getByLabel("Server username", { exact: true }).fill("node");
  await page.getByLabel("Server credential", { exact: true }).fill("s3cret");
  await page.getByRole("button", { name: "Add server" }).click();
  await expect(page.getByText("The URI must use the turns: scheme.")).toBeVisible();
  expect(created).toBe(false);
});

test("editing leaves the stored credential untouched when the field is left blank", async ({ page }) => {
  await stubExternalTurnServers(page);
  await page.goto("/#/external-turn");
  await page.getByRole("button", { name: "Add external TURN server" }).click();
  await page.getByLabel("Server URI", { exact: true }).fill("turns:turn.example.com:5349");
  await page.getByLabel("Server username", { exact: true }).fill("node");
  await page.getByLabel("Server credential", { exact: true }).fill("original-secret");
  await page.getByRole("button", { name: "Add server" }).click();

  let sentCredential: unknown = "unset";
  // fallback(), not continue() -- continue() would send straight to the
  // real network, bypassing stubExternalTurnServers' own handler
  // registered above; fallback() hands off to it instead.
  await page.route("**/api/karst/v1/external-turn-servers/*", async (route) => {
    const request = route.request();
    if (request.method() === "PUT") sentCredential = (request.postDataJSON() as { credential?: unknown }).credential;
    return route.fallback();
  });
  await page.getByRole("button", { name: "Edit" }).click();
  await page.getByLabel("Edit server username").fill("renamed-node");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.locator("section", { has: page.getByRole("heading", { name: "External TURN servers", exact: true }) })).toContainText("renamed-node");
  expect(sentCredential).toBeUndefined();
});

test("reordering moves an entry without touching the others", async ({ page }) => {
  await stubExternalTurnServers(page);
  await page.goto("/#/external-turn");
  for (const uri of ["turns:a.example:5349", "turns:b.example:5349"]) {
    await page.getByRole("button", { name: "Add external TURN server" }).click();
    await page.getByLabel("Server URI", { exact: true }).fill(uri);
    await page.getByLabel("Server username", { exact: true }).fill("node");
    await page.getByLabel("Server credential", { exact: true }).fill("s3cret");
    await page.getByRole("button", { name: "Add server" }).click();
  }
  const rows = page.locator("tbody tr");
  await expect(rows).toHaveCount(2);
  await expect(rows.nth(0)).toContainText("turns:a.example:5349");
  await page.getByRole("button", { name: "Move turns:b.example:5349 up" }).click();
  await expect(rows.nth(0)).toContainText("turns:b.example:5349");
  await expect(rows.nth(1)).toContainText("turns:a.example:5349");
});

test("removing a server asks for confirmation", async ({ page }) => {
  await stubExternalTurnServers(page);
  await page.goto("/#/external-turn");
  await page.getByRole("button", { name: "Add external TURN server" }).click();
  await page.getByLabel("Server URI", { exact: true }).fill("turns:turn.example.com:5349");
  await page.getByLabel("Server username", { exact: true }).fill("node");
  await page.getByLabel("Server credential", { exact: true }).fill("s3cret");
  await page.getByRole("button", { name: "Add server" }).click();

  page.once("dialog", (dialog) => dialog.dismiss());
  await page.getByRole("button", { name: "Remove" }).click();
  await expect(page.getByText("turns:turn.example.com:5349")).toBeVisible();

  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", { name: "Remove" }).click();
  await expect(page.getByText("No external TURN servers configured")).toBeVisible();
});
