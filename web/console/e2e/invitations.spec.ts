// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { expect, test } from "@playwright/test";

test("administrator creates one complete invitation, dismisses its secret, and revokes it", async ({ page }) => {
  // Exercise browser HTTPS-origin behavior while serving local app fixtures.
  // Server-side permission and redemption tests use the real account manager.
  // Keep invitation state local to this browser: other suites deliberately
  // reset the shared mock to exercise empty accounts.
  const invitations: Record<string, unknown>[] = [];
  await page.route("https://console.example.test/**", async route => {
    const url = new URL(route.request().url());
    if (url.pathname === "/api/groups") {
      await route.fulfill({ json: [{ id: "group-sre", name: "sre" }] }); return;
    }
    if (url.pathname === "/api/karst/v1/invitations") {
      if (route.request().method() === "POST") {
        expect(route.request().postDataJSON()).toEqual({ name: "invitation-browser-laptop", groups: ["group-sre"] });
        const item = { id: "invitation-browser", name: "invitation-browser-laptop", groups: ["group-sre"], state: "pending", created_at: new Date().toISOString(), expires_at: new Date(Date.now() + 86400000).toISOString() };
        invitations.push(item);
        await route.fulfill({ json: { ...item, credential: "invitation-fixture-secret" } }); return;
      }
      await route.fulfill({ json: invitations }); return;
    }
    if (url.pathname === "/api/karst/v1/invitations/invitation-browser/revoke") {
      invitations[0].state = "revoked";
      await route.fulfill({ json: invitations[0] }); return;
    }
    const response = await route.fetch({ url: `http://127.0.0.1:4173${url.pathname}${url.search}` });
    await route.fulfill({ response });
  });
  await page.goto("https://console.example.test/#/setup");
  await page.getByLabel("Device label").fill("invitation-browser-laptop");
  await page.getByRole("checkbox", { name: "sre", exact: true }).check();
  await page.getByRole("button", { name: "Create invitation", exact: true }).click();
  const value = await page.getByLabel("Enrollment invitation", { exact: true }).inputValue();
  expect(value).toMatch(/^karst-invite-v1:/);
  const payload = JSON.parse(Buffer.from(value.slice("karst-invite-v1:".length), "base64url").toString("utf8"));
  expect(payload).toEqual({ server: "https://console.example.test", server_kem_pin: "ab".repeat(1184), server_verify_pin: "cd".repeat(2592), control_minimum_version: 1, setup_key: "invitation-fixture-secret" });
  const storage = await page.evaluate(() => JSON.stringify({ local: { ...localStorage }, session: { ...sessionStorage } }));
  expect(storage).not.toContain(payload.setup_key);
  expect(storage).not.toContain(value);
  await page.getByRole("button", { name: "Dismiss invitation" }).click();
  await expect(page.getByLabel("Enrollment invitation", { exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Revoke invitation-browser-laptop", exact: true }).click();
  await expect(page.locator("li").filter({ hasText: "invitation-browser-laptop" })).toContainText("revoked");
  await page.reload();
  await expect(page.locator("li").filter({ hasText: "invitation-browser-laptop" })).toContainText("revoked");
  await expect(page.getByLabel("Enrollment invitation", { exact: true })).toHaveCount(0);
});
