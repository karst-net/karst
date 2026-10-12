// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { expect, test } from "@playwright/test";

const apiPort = process.env.KARST_API_MOCK_PORT ?? "4010";

test("owners can inspect coverage and opt into an acknowledged relay cap", async ({ page }) => {
  await page.request.put(`http://127.0.0.1:${apiPort}/__mock__/fixture`, { data: {} });
  await page.goto("/#/billing");

  await expect(page.getByRole("heading", { name: "Billing", level: 2 })).toBeVisible();
  await expect(page.getByText("Incomplete coverage").first()).toBeVisible();
  await expect(page.getByText("Relay usage coverage is incomplete; threshold amounts are lower bounds.")).toBeVisible();
  await expect(page.getByRole("row").filter({ hasText: "75%" })).toBeVisible();
  await expect(page.getByText("No cap is configured")).toBeVisible();

  await page.getByLabel("Monthly overage limit in USD").fill("15.25");
  await page.getByLabel(/I understand managed-relay connections/).check();
  await page.getByRole("button", { name: "Save cap" }).click();

  await expect(page.getByRole("status")).toContainText("Relay spending cap saved");
  await expect(page.getByText("Cap is enabled: $15.25 USD")).toBeVisible();
});
