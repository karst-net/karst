// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { expect, test } from "@playwright/test";

const apiPort = process.env.KARST_API_MOCK_PORT ?? "4010";

test("owners can inspect coverage and opt into an acknowledged relay cap", async ({ page }) => {
  await page.request.put(`http://127.0.0.1:${apiPort}/__mock__/billing/fixture`, { data: {} });
  await page.goto("/#/billing");

  await expect(page.getByRole("heading", { name: "Billing", level: 2 })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Invoice and payment" })).toBeVisible();
  await expect(page.getByText(/before tax/)).toBeVisible();
  await page.getByRole("button", { name: "Prepare Paddle checkout" }).click();
  const checkout = page.getByRole("link", { name: "Continue to Paddle checkout" });
  await expect(checkout).toHaveAttribute("href", "https://sandbox-buy.paddle.com/checkout/mock");
  await expect(checkout).toHaveAttribute("target", "_blank");
  const period = await page.getByLabel("Usage month").inputValue();
  await page.request.put(`http://127.0.0.1:${apiPort}/__mock__/billing/payment-state`, { data: { period, state: "past_due" } });
  await page.getByRole("button", { name: "Refresh payment status" }).click();
  await expect(page.getByRole("alert").filter({ hasText: "Payment failed." })).toContainText("Your service remains active during the 14-day grace period");
  await expect(page.getByRole("heading", { name: "Payment notices" })).toBeVisible();
  await expect(page.getByRole("list", { name: "Payment failure notices" })).toContainText(`Payment failed for ${period}`);
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

// Both endpoints answer 412 when the feature is configured-but-absent for
// this account (no Paddle, no billing schedule yet) -- an expected account
// state, not a broken page. The billing view must say so plainly rather
// than showing its generic Failure/retry banner, which would tell an
// operator to retry something that can never succeed without a
// server-side configuration change.
test("an unconfigured account sees plain explanations instead of billing errors", async ({ page }) => {
  await page.route(`**/api/karst/v1/billing/payments*`, (route) => route.fulfill({ status: 412, json: { message: "Paddle billing is not enabled for this account" } }));
  await page.route(`**/api/karst/v1/usage/relay-alerts*`, (route) => route.fulfill({ status: 412, json: { message: "no billing schedule is assigned for this period" } }));
  await page.goto("/#/billing");

  await expect(page.getByText("Paddle billing is not enabled for this account.")).toBeVisible();
  await expect(page.getByText(/No billing schedule is assigned for .+; relay usage alerts are unavailable\./)).toBeVisible();
  await expect(page.getByRole("heading", { name: "Could not load this view" })).toHaveCount(0);
});
