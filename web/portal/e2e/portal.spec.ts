// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { AxeBuilder } from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
for (const route of ["devices", "download", "access", "sessions"]) test(`${route} is accessible`, async ({ page }) => { await page.goto(`/#/${route}`); expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]); });
test("member can rename and revoke a device using the keyboard", async ({ page }) => {
 await page.goto("/#/devices");
 await page.getByRole("button", { name: "Rename" }).first().press("Enter");
 await page.getByLabel("New device name").fill("renamed laptop");
 await page.getByRole("button", { name: "Save name" }).press("Enter");
 await expect(page.getByRole("status")).toContainText("renamed");
 page.on("dialog", dialog => dialog.accept());
 await page.getByRole("button", { name: "Revoke" }).first().press("Enter");
 await expect(page.getByRole("status")).toContainText("revoked");
});
test("enrollment refuses plaintext origins before issuing a credential", async ({ page }) => {
 let issued = false;
 page.on("request", req => { if(req.url().endsWith("/devices/enroll")) issued = true; });
 await page.goto("/#/devices");
 await page.getByRole("checkbox").check();
 await page.getByRole("button", { name: "Create enrollment bundle" }).click();
 await expect(page.getByRole("alert")).toContainText("trusted HTTPS");
 expect(issued).toBe(false);
});
test("enrollment bundle includes real pins and a usable command", async ({ page }) => {
 await page.route("https://enroll.test/**", async route => {
   const url = new URL(route.request().url());
   const response = await route.fetch({ url: `http://127.0.0.1:4174${url.pathname}${url.search}` });
   await route.fulfill({ response });
 });
 await page.goto("https://enroll.test/#/devices");
 await expect(page.getByRole("button", { name: "Create enrollment bundle" })).toBeDisabled();
 await page.getByRole("checkbox").check();
 await page.getByRole("button", { name: "Create enrollment bundle" }).click();
 const link = page.getByRole("link", { name: "Download enrollment bundle" });
 await expect(link).toBeVisible();
 const content = await link.evaluate(async el => fetch((el as HTMLAnchorElement).href).then(r => r.text()));
 expect(content).toContain('server = "https://enroll.test"');
 expect(content).toContain('server_kem_pin = "' + "ab".repeat(1184) + '"');
 expect(content).toContain('server_verify_pin = "' + "cd".repeat(2592) + '"');
 expect(content).toContain('setup_key = "member-one-time-key"');
 await expect(page.getByRole("status")).toContainText("sudo karst enroll --bundle");
});

test("download lists every build for the platform with its checksum", async ({ page }) => { await page.goto("/#/download"); const rows = page.getByRole("row").filter({ hasText: /karst-client/ }); await expect(rows).toHaveCount(4); await expect(page.getByRole("cell", { name: "arm64", exact: true }).first()).toBeVisible(); await expect(page.getByRole("link", { name: /karst-client-linux_0\.1\.0-1_amd64\.deb/ })).toBeVisible(); await expect(page.getByText(/sha256sum/)).toBeVisible(); });
test("a platform Karst does not build for is not offered one", async ({ page }) => { await page.goto("/#/download"); await expect(page.getByText(/\.msi/)).toHaveCount(0); });
