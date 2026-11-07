// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { expect, test } from "@playwright/test";

// KARST_SCALER_ADVISOR_URL unset is a configured-but-absent state, not a
// broken page -- the view must say so plainly rather than showing its
// generic Failure/retry banner, which would tell an operator to retry
// something that can never succeed without a server-side configuration
// change. See karst-control's own scalerRecommendations doc comment.
test("an unconfigured Scaler Advisor explains itself instead of erroring", async ({ page }) => {
  await page.route("**/api/karst/v1/scaler/recommendations*", (route) => route.fulfill({ status: 412, json: { message: "KARST_SCALER_ADVISOR_URL is not configured" } }));
  await page.goto("/#/scaler");

  await expect(page.getByRole("heading", { name: "Scaler Advisor", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Scaler Advisor is not configured" })).toBeVisible();
  await expect(page.getByText("This deployment has not set KARST_SCALER_ADVISOR_URL", { exact: false })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Could not load this view" })).toHaveCount(0);
  // Allowed regions is independent data and must still work.
  await expect(page.getByRole("heading", { name: "Allowed regions" })).toBeVisible();
});
