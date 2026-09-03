// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { AxeBuilder } from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

const routes = ["setup", "machines", "access", "keys", "users", "groups", "bedrock", "posture", "dns", "routes", "audit", "relays", "settings"];

for (const route of routes) {
  test(`${route} has no accessibility violations`, async ({ page }) => {
    await page.goto(`/#/${route}`);
    const result = await new AxeBuilder({ page }).analyze();
    expect(result.violations).toEqual([]);
  });
}

const background = (page: Page) => page.evaluate(() => getComputedStyle(document.body).backgroundColor);

// Assert the page actually went dark before running axe against it. The
// previous version clicked a button that toggled a class no stylesheet
// matched, under Playwright's default light color scheme, and graded a white
// page as a passing dark mode.
for (const route of ["posture", "machines", "access"]) {
  test(`${route} renders dark and has no accessibility violations`, async ({ page }) => {
    await page.goto(`/#/${route}`);
    const light = await background(page);
    await page.getByLabel("Theme").selectOption("dark");
    await expect.poll(() => background(page)).not.toBe(light);
    expect(await background(page)).toBe("rgb(16, 24, 32)");
    const result = await new AxeBuilder({ page }).analyze();
    expect(result.violations).toEqual([]);
  });
}

test("an explicit light choice overrides a dark system preference", async ({ page }) => {
  // The toggle has to win in both directions, or an admin on a dark desktop
  // cannot get a light console.
  await page.emulateMedia({ colorScheme: "dark" });
  await page.goto("/#/posture");
  expect(await background(page)).toBe("rgb(16, 24, 32)");
  await page.getByLabel("Theme").selectOption("light");
  expect(await background(page)).toBe("rgb(255, 255, 255)");
});

test("the theme choice survives a reload", async ({ page }) => {
  await page.goto("/#/posture");
  await page.getByLabel("Theme").selectOption("dark");
  await page.reload();
  await expect(page.getByLabel("Theme")).toHaveValue("dark");
  expect(await background(page)).toBe("rgb(16, 24, 32)");
});

test("posture opens on exceptions, worst first", async ({ page }) => {
  await page.goto("/#/posture");
  await expect(page.getByLabel("Show")).toHaveValue("exceptions");
  // Every non-compliant category, not just lattice-only: 2 stale + 4
  // lattice-only in the fixture, and no compliant sessions at all.
  await expect(page.locator("tbody tr")).toHaveCount(6);
  // innerText reflects text-transform: capitalize, so compare case-insensitively.
  const statuses = (await page.locator("tbody tr td:nth-child(3)").allInnerTexts()).map((text) => text.toLowerCase());
  expect(statuses.filter((text) => text.includes("stale"))).toHaveLength(2);
  expect(statuses.filter((text) => text.includes("lattice only"))).toHaveLength(4);
  expect(statuses.some((text) => text.includes("pq"))).toBe(false);
  expect(statuses[0]).toContain("stale");
});

test("policy validation and save are keyboard accessible", async ({ page }) => {
  await page.goto("/#/access");
  await page.getByLabel("Policy document").focus();
  await page.keyboard.press("Control+A");
  await page.keyboard.type('{ "acls": [] }');
  await page.getByRole("button", { name: "Validate policy" }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("status")).toContainText("Policy is valid");
  await page.getByRole("button", { name: "Save policy" }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("status")).toContainText("Policy saved");
});

test("policy syntax errors surface their line number", async ({ page }) => {
  await page.goto("/#/access");
  await page.getByLabel("Policy document").fill('{\n  "acls": [],\n}');
  await page.getByRole("button", { name: "Validate policy" }).click();
  await expect(page.getByLabel("Policy diagnostics")).toContainText("line 3");
});

test("first-run setup produces a copyable daemon configuration", async ({ page }) => {
  await page.goto("/#/setup");
  await page.getByLabel("Server URL").fill("https://control.example.test");
  await page.getByRole("button", { name: "Create enrollment key" }).click();
  await expect(page.getByLabel("Control configuration")).toHaveValue('[control]\nserver = "https://control.example.test"\nserver_kem_pin = "…"\nserver_verify_pin = "…"\nsetup_key = "setup-fixture-secret"');
  await expect(page.getByText("sudo systemctl enable --now karstd")).toBeVisible();
});

test("setup cannot mint a key before it knows the server URL", async ({ page }) => {
  await page.goto("/#/setup");
  await page.getByLabel("Server URL").fill("");
  // A key issued without a URL produces an enrollment command that cannot work,
  // and the key is one-time — the admin burns it discovering that.
  await expect(page.getByRole("button", { name: "Create enrollment key" })).toBeDisabled();
  await page.getByLabel("Server URL").fill("https://control.example.test");
  await expect(page.getByRole("button", { name: "Create enrollment key" })).toBeEnabled();
});

test("setup progress and server URL survive leaving the page", async ({ page }) => {
  await page.goto("/#/setup");
  await page.getByLabel("Server URL").fill("https://persisted.example.test");
  await page.getByRole("listitem").filter({ hasText: "Configure the coordination server" }).getByRole("button", { name: "Mark complete" }).click();
  // Setup spans a restart and a walk to another machine. Component state lost
  // both on the first navigation, which made step 1 configure nothing.
  await page.goto("/#/machines");
  await page.goto("/#/setup");
  await expect(page.getByLabel("Server URL")).toHaveValue("https://persisted.example.test");
  await expect(page.getByRole("listitem").filter({ hasText: "Configure the coordination server" }).getByRole("button")).toHaveText("Complete");
});

test("quickstart documents the daemon configuration enrollment flow", async ({ page }) => {
  await page.goto("/#/setup");
  await page.getByRole("link", { name: "Read the quickstart" }).click();
  await expect(page.getByText("There is no")).toContainText("karst up");
});

test("auth-key creation is keyboard accessible", async ({ page }) => {
  await page.goto("/#/keys");
  await page.getByRole("button", { name: "Create auth key" }).focus();
  await page.keyboard.press("Enter");
  // showModal() puts focus inside the dialog, so the form is reachable by
  // typing alone from here — no pointer, and no tabbing back out to find it.
  await page.getByLabel("Key name").fill("laptop-alice");
  await page.getByRole("button", { name: "Issue auth key" }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("status")).toContainText("Copy this key now");
  await expect(page.getByLabel("New auth key")).toHaveValue("setup-fixture-secret");
});

test("a created auth key appears in the list with its state and usage", async ({ page }) => {
  await page.goto("/#/keys");
  await page.getByRole("button", { name: "Create auth key" }).click();
  await page.getByLabel("Key name").fill("ci-runners");
  await page.getByLabel("Key type").selectOption("reusable");
  // Usage limit only exists for a reusable key: a one-off with a limit of 5
  // would be a contradiction the server has to reject.
  await page.getByLabel("Usage limit (0 for unlimited)").fill("5");
  await page.getByRole("button", { name: "Issue auth key" }).click();
  await page.getByRole("button", { name: "Done" }).click();
  const row = page.locator("tbody tr").filter({ hasText: "ci-runners" });
  await expect(row).toContainText("reusable");
  await expect(row).toContainText("0 / 5");
  await expect(row).toContainText("valid");
});

test("an auth key can be revoked without being deleted", async ({ page }) => {
  await page.goto("/#/keys");
  await page.getByRole("button", { name: "Create auth key" }).click();
  await page.getByLabel("Key name").fill("temporary");
  await page.getByRole("button", { name: "Issue auth key" }).click();
  await page.getByRole("button", { name: "Done" }).click();
  page.on("dialog", (dialog) => dialog.accept());
  await page.locator("tbody tr").filter({ hasText: "temporary" }).getByRole("button", { name: "Revoke" }).click();
  await expect(page.getByRole("status")).toContainText("was revoked");
  // Still listed, and still says what happened to it. A key that vanished on
  // revocation would leave nothing to answer "was this one ever used?".
  await expect(page.locator("tbody tr").filter({ hasText: "temporary" })).toContainText("revoked");
});

test("a machine can be renamed", async ({ page }) => {
  await page.goto("/#/machines");
  await page.locator("tbody tr").filter({ hasText: "sre-laptop" }).getByRole("button", { name: "Rename" }).click();
  await page.getByLabel("Machine name", { exact: true }).fill("alice-laptop");
  await page.getByRole("button", { name: "Save name" }).click();
  await expect(page.getByRole("status")).toContainText("is now named alice-laptop");
  await expect(page.locator("tbody tr").filter({ hasText: "alice-laptop" })).toBeVisible();
});

test("adding a machine issues a key and explains where it goes", async ({ page }) => {
  await page.goto("/#/machines");
  await page.getByRole("button", { name: "Add machine" }).click();
  await page.getByLabel("New machine name").fill("laptop-bob");
  await page.getByRole("button", { name: "Issue auth key" }).click();
  await expect(page.getByLabel("Enrollment key")).toHaveValue("setup-fixture-secret");
  // A machine is not created by an admin; it enrolls itself. The dialog has to
  // say what to do with the key or the flow stops here.
  await expect(page.getByText("setup_key")).toBeVisible();
});

test("the machine filter narrows the list without hiding the count", async ({ page }) => {
  await page.goto("/#/machines");
  await page.getByLabel("Filter machines").fill("prod-db-01");
  await expect(page.locator("tbody tr")).toHaveCount(1);
  await page.getByLabel("Filter machines").fill("no-such-machine");
  await expect(page.getByRole("heading", { name: "No machines match that filter" })).toBeVisible();
});

test("a user can be invited, edited and blocked", async ({ page }) => {
  await page.goto("/#/users");
  await page.getByRole("button", { name: "Invite user" }).click();
  await page.getByLabel("Email", { exact: true }).fill("new@example.test");
  await page.getByLabel("Full name", { exact: true }).fill("New Operator");
  await page.getByLabel("Role", { exact: true }).selectOption("user");
  await page.getByRole("button", { name: "Invite user" }).nth(1).click();
  await expect(page.getByRole("status")).toContainText("was invited as user");
  const row = page.locator("tbody tr").filter({ hasText: "new@example.test" });
  await expect(row).toContainText("invited");

  await row.getByRole("button", { name: "Edit" }).click();
  await page.getByLabel("Edit role").selectOption("admin");
  await page.getByRole("button", { name: "Save user" }).click();
  await expect(row).toContainText("admin");

  await row.getByRole("button", { name: "Block" }).click();
  await expect(page.getByRole("status")).toContainText("was blocked");
  await expect(row).toContainText("blocked");
  await expect(row.getByRole("button", { name: "Unblock" })).toBeVisible();
});

test("the signed-in user cannot deprovision themselves", async ({ page }) => {
  await page.goto("/#/users");
  // Not a disabled button: a disabled control invites a second attempt. The row
  // says why there is nothing to press.
  const self = page.locator("tbody tr").filter({ hasText: "(you)" });
  await expect(self).toContainText("Current user");
  await expect(self.getByRole("button", { name: "Deprovision" })).toHaveCount(0);
});

test("groups can be created and renamed, and provider groups cannot", async ({ page }) => {
  await page.goto("/#/groups");
  await page.getByRole("button", { name: "Create group" }).click();
  await page.getByLabel("Group name", { exact: true }).fill("contractors");
  await page.getByRole("button", { name: "Create group" }).nth(1).click();
  await expect(page.getByRole("status")).toContainText("was created");
  const row = page.locator("tbody tr").filter({ hasText: "contractors" });
  await row.getByRole("button", { name: "Rename" }).click();
  await page.getByLabel("New group name").fill("contractors-2026");
  await page.getByRole("button", { name: "Save name" }).click();
  await expect(page.locator("tbody tr").filter({ hasText: "contractors-2026" })).toBeVisible();
  // A group synchronised from an identity provider is a copy. Offering an edit
  // button for it would produce a rejection the admin cannot act on.
  const provider = page.locator("tbody tr").filter({ hasText: "engineering" });
  await expect(provider).toContainText("Managed by the identity provider");
  await expect(provider.getByRole("button")).toHaveCount(0);
  // Neither is the built-in All group editable.
  await expect(page.locator("tbody tr").filter({ hasText: "All" }).first()).toContainText("Built in");
});

test("a relay with a DNS name for an address is refused before it is sent", async ({ page }) => {
  await page.goto("/#/relays");
  await page.getByRole("button", { name: "Add relay" }).click();
  await page.getByLabel("Relay address").fill("relay.example.com:443");
  await page.getByLabel("TLS server name").fill("relay.example.com");
  await page.getByLabel("Relay identity key").fill("fixture-public-key");
  await page.getByRole("button", { name: "Add relay" }).nth(1).click();
  // karstd parses this with SocketAddr, which does not resolve. A name here is
  // not one bad relay — it is a netmap every node rejects in full.
  await expect(page.getByRole("status")).toContainText("must be an IP address and port");
  await expect(page.locator("tbody tr")).toHaveCount(2);
});

test("a relay can be added and removed", async ({ page }) => {
  await page.goto("/#/relays");
  await page.getByRole("button", { name: "Add relay" }).click();
  await page.getByLabel("Relay address").fill("203.0.113.9:443");
  await page.getByLabel("TLS server name").fill("relay-new.example.test");
  await page.getByLabel("Relay identity key").fill("fixture-public-key-new");
  await page.getByLabel("Relay region").fill("ap-south");
  await page.getByRole("button", { name: "Add relay" }).nth(1).click();
  await expect(page.getByRole("status")).toContainText("was added");
  const row = page.locator("tbody tr").filter({ hasText: "203.0.113.9:443" });
  await expect(row).toBeVisible();
  page.on("dialog", (dialog) => dialog.accept());
  await row.getByRole("button", { name: "Remove" }).click();
  await expect(page.getByRole("status")).toContainText("was removed");
  await expect(page.locator("tbody tr").filter({ hasText: "203.0.113.9:443" })).toHaveCount(0);
});

test("a network route can be added, disabled and deleted", async ({ page }) => {
  await page.goto("/#/routes");
  await page.getByRole("button", { name: "Add subnet route" }).click();
  await page.getByLabel("Route identifier").fill("branch-office");
  await page.getByLabel("Route network (CIDR)").fill("192.168.40.0/24");
  await page.getByLabel("Routing groups").selectOption(["group-gateways"]);
  await page.getByLabel("Distribution groups").selectOption(["group-engineering"]);
  await page.getByLabel("Access-control groups").selectOption(["group-engineering"]);
  await page.getByRole("button", { name: "Add route" }).click();
  await expect(page.getByRole("status")).toContainText("was created");
  const row = page.locator("tbody tr").filter({ hasText: "branch-office" });
  await row.getByRole("button", { name: "Disable" }).click();
  await expect(row).toContainText("disabled");
  page.on("dialog", (dialog) => dialog.accept());
  await row.getByRole("button", { name: "Delete" }).click();
  await expect(page.getByRole("status")).toContainText("was deleted");
});

test("a route without a routing group is refused with the reason", async ({ page }) => {
  await page.goto("/#/routes");
  await page.getByRole("button", { name: "Add subnet route" }).click();
  await page.getByLabel("Route identifier").fill("nowhere");
  await page.getByLabel("Route network (CIDR)").fill("10.9.0.0/16");
  await page.getByLabel("Distribution groups").selectOption(["group-engineering"]);
  await page.getByRole("button", { name: "Add route" }).click();
  await expect(page.getByRole("status")).toContainText("at least one routing group");
});

test("a nameserver group cannot be both primary and domain-scoped", async ({ page }) => {
  await page.goto("/#/dns");
  await page.getByRole("button", { name: "Add nameserver group" }).click();
  await page.getByLabel("Nameserver group name").fill("split-brain");
  await page.getByLabel("Nameserver 1 IP").fill("10.0.0.53");
  await page.getByRole("button", { name: "Add group" }).click();
  // Not primary and no match domains: the group would never apply to anything.
  await expect(page.getByRole("status")).toContainText("at least one match domain");
  await page.getByLabel("Match domains").fill("corp.example.test");
  await page.getByRole("button", { name: "Add group" }).click();
  await expect(page.getByRole("status")).toContainText("was created");
  await expect(page.locator("tbody tr").filter({ hasText: "split-brain" })).toContainText("corp.example.test");
});

test("network lock can be lowered to advisory without an acknowledgment", async ({ page }) => {
  await page.goto("/#/bedrock");
  // Only enforcing can cut a machine off, so only enforcing needs the list
  // acknowledged. Requiring it to stand down would make the safe direction the
  // harder one, which is backwards during an incident.
  await page.getByRole("button", { name: "Turn off" }).click();
  await expect(page.getByRole("status")).toContainText("is off");
  await page.getByRole("button", { name: "Set advisory" }).click();
  await expect(page.getByRole("status")).toContainText("is advisory");
});

test("the network lock view shows the signed log and pending coverage", async ({ page }) => {
  await page.goto("/#/bedrock");
  await expect(page.getByRole("heading", { name: "Signed log" })).toBeVisible();
  await expect(page.getByRole("row").filter({ hasText: "node.sign" }).first()).toBeVisible();
  // The fixture has a signed authority entry and separately identifies the
  // uncovered node in the acknowledgment list; do not infer coverage from a
  // signing-row count.
  await expect(page.getByRole("row").filter({ hasText: "node-0002-karst-fixture-handle" })).toContainText("authority");
  await expect(page.getByText("node-0001-karst-fixture-handle")).toBeVisible();
});

test("Bedrock can export an offline audit-anchor request", async ({ page }) => {
  await page.goto("/#/bedrock");
  const exported = page.waitForRequest((request) => request.url().includes("/bedrock/audit-anchor/export"));
  await page.getByRole("button", { name: "Create and export audit-anchor request" }).click();
  await exported;
  await expect(page.getByRole("status")).toContainText("audit-anchor request");
});

test("the audit log filters, verifies and reports a broken chain", async ({ page }) => {
  await page.goto("/#/audit");
  await expect(page.locator("tbody tr")).toHaveCount(2);
  await page.getByLabel("Filter by actor").fill("user-sre");
  await page.getByRole("button", { name: "Apply filters" }).click();
  await expect(page.locator("tbody tr")).toHaveCount(1);
  await page.getByRole("button", { name: "Clear" }).click();
  await expect(page.locator("tbody tr")).toHaveCount(2);
  await page.getByRole("button", { name: "Verify chain" }).click();
  // The fixture's chain is deliberately broken. A console that rendered that as
  // anything less than an alarm would be worse than one with no verify button.
  await expect(page.getByRole("status")).toContainText("FAILED at sequence 42");
});

test("audit exports select the required server format", async ({ page }) => {
  await page.goto("/#/audit");
  const jsonExport = page.waitForRequest((request) => request.url().includes("/audit/export?format=json"));
  await page.getByRole("button", { name: "Export JSON" }).click();
  await jsonExport;
  await expect(page.getByRole("status")).toContainText("as JSON");
  const csvExport = page.waitForRequest((request) => request.url().includes("/audit/export?format=csv"));
  await page.getByRole("button", { name: "Export CSV" }).click();
  await csvExport;
  await expect(page.getByRole("status")).toContainText("as CSV");
});

test("a personal access token is shown once and can be revoked", async ({ page }) => {
  await page.goto("/#/settings");
  await page.getByRole("button", { name: "Create token" }).click();
  await page.getByLabel("Token name").fill("ci-deploy-2");
  await page.getByRole("button", { name: "Create token" }).nth(1).click();
  await expect(page.getByLabel("New personal access token")).toHaveValue("pat-fixture-secret");
  await expect(page.getByRole("status")).toContainText("not stored and will not be shown again");
  page.on("dialog", (dialog) => dialog.accept());
  await page.locator("tbody tr").filter({ hasText: "ci-deploy-2" }).getByRole("button", { name: "Revoke" }).click();
  await expect(page.getByRole("status")).toContainText("was revoked");
});

test("policy tests report which expectation failed", async ({ page }) => {
  await page.goto("/#/access");
  await page.getByRole("button", { name: "Test policy" }).click();
  await expect(page.getByRole("status")).toContainText("Access tests failed");
  await expect(page.getByLabel("Policy tests")).toContainText("expected deny, got allow");
});

test("Escape closes a create dialog without submitting it", async ({ page }) => {
  await page.goto("/#/groups");
  await page.getByRole("button", { name: "Create group" }).click();
  await page.getByLabel("Group name", { exact: true }).fill("abandoned");
  await page.keyboard.press("Escape");
  await expect(page.getByLabel("Group name", { exact: true })).toBeHidden();
  await expect(page.locator("tbody tr").filter({ hasText: "abandoned" })).toHaveCount(0);
});

test("machine deprovisioning is keyboard accessible", async ({ page }) => {
  await page.goto("/#/machines");
  page.on("dialog", (dialog) => dialog.accept());
  const action = page.getByRole("button", { name: "Deprovision" }).first();
  await action.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("status")).toContainText("deprovisioned");
});

test("user deprovisioning surfaces the console result without a timing assertion", async ({ page }) => {
  // The console's responsibility is to issue the deprovision request and make
  // its result visible. Server-initiated session teardown and its 60-second
  // timed proof are owned by Phase 5 plan 08, not this mock-backed UI suite.
  await page.goto("/#/users");
  page.on("dialog", (dialog) => dialog.accept());
  const action = page.getByRole("button", { name: "Deprovision" }).first();
  await action.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("status")).toContainText("deprovisioned");
});

test("policy history can be viewed and restored", async ({ page }) => {
  await page.goto("/#/access");
  await expect(page.getByRole("heading", { name: "Version history" })).toBeVisible();
  const oldVersion = page.locator("tbody tr").filter({ hasText: "user-sre" });
  await oldVersion.getByRole("button", { name: "View" }).click();
  await expect(page.getByRole("status")).toContainText("Viewing version 6");
  page.on("dialog", (dialog) => dialog.accept());
  await oldVersion.getByRole("button", { name: "Restore" }).click();
  await expect(page.getByRole("status")).toContainText("version 6 restored");
});

const uncovered = ["node-0001-karst-fixture-handle", "node-0049-karst-fixture-handle"];
const setUncovered = (page: Page, handles: string[]) =>
  page.request.put("http://127.0.0.1:4010/__mock__/bedrock/uncovered", { data: { uncovered_handles: handles } });
const setFixture = (page: Page, empty: boolean) =>
  page.request.put("http://127.0.0.1:4010/__mock__/fixture", { data: { empty } });

test.afterEach(async ({ page }) => { await setUncovered(page, uncovered); await setFixture(page, false); });

test("empty-account list views explain what happens next", async ({ page }) => {
  await setFixture(page, true);
  for (const [route, title] of [["machines", "No machines yet"], ["keys", "No auth keys"], ["users", "No users"], ["audit", "No audit events"], ["groups", "No groups"], ["relays", "No relays configured"]]) {
    await page.goto(`/#/${route}`);
    await expect(page.getByRole("heading", { name: title })).toBeVisible();
  }
});

test("network lock acknowledgment is keyboard accessible", async ({ page }) => {
  await page.goto("/#/bedrock");
  // The acknowledgment must be the server's uncovered set. sre-laptop is
  // healthy and online and uncovered; the stale nodes are covered. A console
  // deriving this list from posture would list the wrong machines here.
  await expect(page.getByRole("listitem").filter({ hasText: "sre-laptop" })).toBeVisible();
  await expect(page.getByRole("listitem")).toHaveCount(2);
  await page.getByLabel("I understand these machines may be cut off.").focus();
  await page.keyboard.press("Space");
  const action = page.getByRole("button", { name: "Enable network lock" });
  await action.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("status")).toContainText("enforcing");
});

test("network lock re-acknowledges when the cut-off set moves under it", async ({ page }) => {
  await page.goto("/#/bedrock");
  await page.getByLabel("I understand these machines may be cut off.").check();
  // A node enrolls, or a signature lands, after the admin read the list.
  await setUncovered(page, [...uncovered, "node-0017-karst-fixture-handle"]);
  await page.getByRole("button", { name: "Enable network lock" }).click();
  await expect(page.getByRole("status")).toContainText("changed while you were reviewing it");
  await expect(page.getByLabel("I understand these machines may be cut off.")).not.toBeChecked();
  await expect(page.getByRole("listitem")).toHaveCount(3);
  // Acknowledging the updated list succeeds without a reload.
  await page.getByLabel("I understand these machines may be cut off.").check();
  await page.getByRole("button", { name: "Enable network lock" }).click();
  await expect(page.getByRole("status")).toContainText("enforcing");
});

test("DNS settings save is keyboard accessible", async ({ page }) => {
  await page.goto("/#/dns");
  await page.getByLabel("Groups excluded from DNS management").focus();
  await page.keyboard.type("group-ops");
  await page.getByRole("button", { name: "Save DNS settings" }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("status")).toContainText("saved");
});
