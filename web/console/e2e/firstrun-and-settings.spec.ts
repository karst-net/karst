// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { expect, test } from "@playwright/test";

test("a brand-new account sees only the first-run wizard, with no sidebar nav", async ({ page }) => {
  // A per-request header override, not a mutation of the mock's shared
  // firstRunCompleted flag -- that flag gates the entire app for every
  // request, so flipping it globally would race whichever other spec file
  // Playwright happens to run concurrently against this same mock process.
  await page.setExtraHTTPHeaders({ "x-mock-firstrun-completed": "false" });
  await page.goto("/#/domains");

  await expect(page.getByRole("heading", { name: "Welcome to Karst" })).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Primary" })).toHaveCount(0);

  // Finishing the wizard calls POST /firstrun/complete, which the mock
  // reports truthfully regardless of this header -- but the header would
  // otherwise keep forcing GET /firstrun back to false on every refetch
  // afterwards, including the one `onComplete` triggers. Clearing it here
  // is what lets that refetch see the real (completed) state.
  await page.setExtraHTTPHeaders({});
  await page.getByRole("button", { name: "Skip for now" }).first().click();
  await expect(page.getByRole("heading", { name: "2. Initial groups" })).toBeVisible();
  await page.getByRole("button", { name: "Skip for now" }).click();
  await page.getByRole("button", { name: "Finish setup" }).click();

  await expect(page.getByRole("navigation", { name: "Primary" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Domains" })).toBeVisible();
});

test("guidance text can be toggled off and on from Settings", async ({ page }) => {
  await page.goto("/#/locations");
  await expect(page.getByText("The NOC map draws every one of these as a hollow marker", { exact: false })).toBeVisible();

  await page.goto("/#/settings");
  const toggle = page.getByRole("checkbox", { name: "Show guidance text on each page" });
  await expect(toggle).toBeChecked();
  await toggle.uncheck();

  await page.goto("/#/locations");
  await expect(page.getByText("The NOC map draws every one of these as a hollow marker", { exact: false })).toHaveCount(0);

  await page.goto("/#/settings");
  await page.getByRole("checkbox", { name: "Show guidance text on each page" }).check();
});

test("an infrastructure connection feeds the Authorized Locations region picker", async ({ page }) => {
  await page.goto("/#/settings");
  await page.getByRole("button", { name: "Add infrastructure connection" }).click();
  await expect(page.getByRole("heading", { name: "Add infrastructure connection" })).toBeVisible();
  await page.getByLabel("Connection type").selectOption("aws");
  await page.getByLabel("Access key ID").fill("AKIAEXAMPLE");
  await page.getByLabel("AWS secret access key").fill("shh-it-is-a-secret");
  await page.getByLabel("Connection label").fill("e2e-aws");
  await page.getByRole("button", { name: "Add connection" }).click();
  await expect(page.getByText("e2e-aws was added.")).toBeVisible();
  await expect(page.getByRole("cell", { name: "e2e-aws" })).toBeVisible();

  await page.goto("/#/locations");
  await page.getByRole("button", { name: "Add authorized location" }).click();
  await page.getByRole("radio", { name: "From an infrastructure connection" }).check();
  await page.getByRole("combobox", { name: "Infrastructure connection" }).selectOption({ label: "e2e-aws (AWS)" });
  await page.getByRole("combobox", { name: "Region, zone, or namespace" }).selectOption({ label: "US East (N. Virginia) (us-east-1)" });
  await page.getByRole("button", { name: "Add location" }).click();
  await expect(page.getByText("was added to the authorized locations registry.", { exact: false })).toBeVisible();
  await expect(page.getByRole("cell", { name: "US East (N. Virginia) (us-east-1)" })).toBeVisible();

  // Clean up so this fixture-mutating test can be re-run against the shared
  // mock process without accumulating rows across runs.
  page.on("dialog", (dialog) => void dialog.accept());
  await page.getByRole("row", { name: /US East \(N\. Virginia\)/ }).getByRole("button", { name: "Remove" }).click();
  await page.goto("/#/settings");
  await page.getByRole("row", { name: /e2e-aws/ }).getByRole("button", { name: "Remove" }).click();
});

test("a Kubernetes connection's namespaces feed the Authorized Locations picker as resources with no coordinates", async ({ page }) => {
  await page.goto("/#/settings");
  await page.getByRole("button", { name: "Add infrastructure connection" }).click();
  await page.getByLabel("Connection type").selectOption("kubernetes");
  await page.getByLabel("Kubeconfig").fill("apiVersion: v1\nkind: Config\ncurrent-context: test\nclusters: []\nusers: []\ncontexts: []\n");
  await page.getByLabel("Connection label").fill("e2e-k8s");
  await page.getByRole("button", { name: "Add connection" }).click();
  await expect(page.getByText("e2e-k8s was added.")).toBeVisible();
  await expect(page.getByRole("cell", { name: "e2e-k8s" })).toBeVisible();

  await page.goto("/#/locations");
  await page.getByRole("button", { name: "Add authorized location" }).click();
  await page.getByRole("radio", { name: "From an infrastructure connection" }).check();
  await page.getByRole("combobox", { name: "Infrastructure connection" }).selectOption({ label: "e2e-k8s (KUBERNETES)" });
  const namespaceSelect = page.getByRole("combobox", { name: "Region, zone, or namespace" });
  await expect(namespaceSelect.locator("option", { hasText: "default — no coordinates yet" })).toHaveCount(1);
  await namespaceSelect.selectOption({ label: "default — no coordinates yet" });
  // No declared location on this connection and no catalog entry for a
  // namespace -- the "Add location" submit should surface that rather than
  // silently adding a coordinate-less row.
  await page.getByRole("button", { name: "Add location" }).click();
  await expect(page.getByText("no known coordinates yet", { exact: false })).toBeVisible();

  await page.goto("/#/settings");
  page.on("dialog", (dialog) => void dialog.accept());
  await page.getByRole("row", { name: /e2e-k8s/ }).getByRole("button", { name: "Remove" }).click();
});
