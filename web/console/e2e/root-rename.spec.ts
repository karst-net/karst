// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { expect, test } from "@playwright/test";

test("root rename requires a fresh preview, discloses convergence, and rolls back through confirmation", async ({ page }) => {
  // Local state keeps the rename isolated from other suites' fixture resets.
  let suffix = "karst";
  let revision = 0;
  let rejectStale = true;
  await page.route("**/api/karst/v1/domains**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("/domains")) {
      await route.fulfill({ json: [{ id: "root-stable-id", label: "", path: "", is_root: true, dns_suffix: suffix }] });
      return;
    }
    const request = route.request().postDataJSON();
    const preview = { root_id: "root-stable-id", old_suffix: suffix, new_suffix: request.dns_suffix, revision: `revision-${revision}`, naming_revision: revision, device_count: 1, domain_count: 2, examples: [{ before: `laptop.engineering.${suffix}`, after: `laptop.engineering.${request.dns_suffix}` }], committed: false, convergence: "unobserved" };
    if (path.endsWith("/commit")) {
      expect(request.confirm_no_aliases).toBe(true);
      expect(request.revision).toBe(`revision-${revision}`);
      if (rejectStale) {
        rejectStale = false;
        revision++;
        await route.fulfill({ status: 412, json: { message: "naming state changed; preview the rename again" } });
        return;
      }
      suffix = request.dns_suffix;
      preview.committed = true;
      preview.naming_revision = ++revision;
    }
    await route.fulfill({ json: preview });
  });
  await page.goto("/#/domains");
  await page.getByRole("button", { name: "Rename root", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await page.getByLabel("New root suffix").fill("corp.example");
  await page.getByRole("button", { name: "Preview rename", exact: true }).click();
  await expect(dialog).toContainText("laptop.engineering.corp.example");
  await expect(dialog).toContainText("no automatic aliases");
  const confirm = page.getByRole("button", { name: "Confirm root rename", exact: true });
  await expect(confirm).toBeDisabled();
  await page.getByLabel("I understand old DNS names will stop resolving").check();
  await confirm.click();
  await expect(page.getByRole("alert")).toContainText("preview the rename again");
  await expect(confirm).toHaveCount(0);
  await page.getByRole("button", { name: "Preview rename", exact: true }).click();
  await page.getByLabel("I understand old DNS names will stop resolving").check();
  await confirm.click();
  await expect(dialog).toHaveCount(0);
  await expect(page.getByRole("status")).toContainText("Client convergence is unobserved");
  await expect(page.getByText("corp.example (root)")).toBeVisible();
  await page.getByRole("button", { name: "Preview rollback", exact: true }).click();
  await expect(page.getByLabel("New root suffix")).toHaveValue("karst");
  await page.getByRole("button", { name: "Preview rename", exact: true }).click();
  await expect(dialog).toContainText("laptop.engineering.karst");
  await expect(confirm).toBeDisabled();
  await page.getByLabel("I understand old DNS names will stop resolving").check();
  await confirm.click();
  await expect(page.getByText("karst (root)")).toBeVisible();
  await expect(page.getByRole("status")).toContainText("Committed naming revision 3");
});
