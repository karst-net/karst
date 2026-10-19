// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { expect, test } from "@playwright/test";

for (const delegated of [false, true]) {
  test(`${delegated ? "delegated" : "account-wide"} views show complete names after root rename`, async ({ page }) => {
    const root = { id: "root", label: "", path: "", is_root: true, dns_suffix: "corp.example", dns_name: "corp.example" };
    const child = { id: "build", parent_id: "engineering", label: "build", path: "build.engineering", dns_name: "build.engineering.corp.example" };
    await page.route("**/api/karst/v1/domains", route => route.fulfill({ json: delegated ? [child] : [root, child] }));
    await page.route("**/api/karst/v1/nodes?**", route => route.fulfill({ json: { items: [{ handle: "stable-device", name: "builder", domain_id: child.id, dns_label: "builder-100-64-0-3.build.engineering", user_id: "user-it", tags: [], enabled: true, created_at: "2026-01-01T00:00:00Z", last_seen_at: null, expires_at: null, posture: { status: "unknown", suite: null, psk_epoch: null, lattice_only: false, observed_at: null } }], next_cursor: null } }));
    await page.goto("/#/machines");
    const row = page.locator("tbody tr").filter({ hasText: "builder" });
    await expect(row.locator("code").first()).toHaveText("builder-100-64-0-3.build.engineering.corp.example");
    await row.getByRole("button", { name: "Move", exact: true }).click();
    await expect(page.getByRole("dialog").locator("code")).toHaveText("builder.build.engineering.corp.example");
    await page.getByRole("button", { name: "Cancel", exact: true }).click();

    await page.goto("/#/enroll");
    await page.getByLabel("Device name").fill("new-device");
    if (!delegated) await expect(page.getByText("It will resolve as")).toContainText("new-device.corp.example");
    await page.getByLabel("Domain", { exact: true }).selectOption(child.id);
    await expect(page.getByText("It will resolve as")).toContainText("new-device.build.engineering.corp.example");

    await page.goto("/#/domains");
    await expect(page.locator("tbody tr").filter({ hasText: "build" })).toContainText("build.engineering.corp.example");
    if (delegated) {
      await expect(page.getByRole("button", { name: "Rename root", exact: true })).toHaveCount(0);
      await expect(page.getByText("corp.example (root)")).toHaveCount(0);
    }
  });
}
