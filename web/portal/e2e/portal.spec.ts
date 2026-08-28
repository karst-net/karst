// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { AxeBuilder } from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
for (const route of ["devices", "download", "access", "sessions"]) test(`${route} is accessible`, async ({ page }) => { await page.goto(`/#/${route}`); expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]); });
test("member can add, rename, and revoke a device using the keyboard", async ({ page }) => { await page.goto("/#/devices"); await page.getByRole("button", { name: "Add a device" }).press("Enter"); await expect(page.getByRole("status")).toContainText("[control] setup_key"); await expect(page.getByRole("status")).toContainText("start karstd"); await page.getByRole("button", { name: "Rename" }).first().press("Enter"); await page.getByLabel("New device name").fill("renamed laptop"); await page.getByRole("button", { name: "Save name" }).press("Enter"); await expect(page.getByRole("status")).toContainText("renamed"); page.on("dialog", (dialog) => dialog.accept()); await page.getByRole("button", { name: "Revoke" }).press("Enter"); await expect(page.getByRole("status")).toContainText("revoked"); });
test("download selects an installer and explains checksum verification", async ({ page }) => { await page.goto("/#/download"); await expect(page.getByRole("link", { name: /Download karst/ })).toBeVisible(); await expect(page.getByText(/sha256sum|Get-FileHash/)).toBeVisible(); });
