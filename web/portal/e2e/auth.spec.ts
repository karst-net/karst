// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.
import { createHash } from "node:crypto";
import { expect, test } from "@playwright/test";

test("portal completes PKCE login, sends bearer auth, and keeps tokens out of browser storage", async ({ page }) => {
  const origin = "https://enroll.test";
  const issuer = origin + "/auth";
  let challenge = "";
  let nonce: string | null = null;
  let exchanged = false;
  let authenticated = false;
  let signedIn = false;
  await page.route(origin + "/**", async route => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.pathname === "/config.json") return route.fulfill({ json: { oidcAuthority: issuer, oidcClientId: "portal-test" } });
    if (url.pathname === "/auth/.well-known/openid-configuration") return route.fulfill({ json: {
      issuer, authorization_endpoint: issuer + "/authorize", token_endpoint: issuer + "/token",
      end_session_endpoint: issuer + "/logout", response_types_supported: ["code"],
      subject_types_supported: ["public"], id_token_signing_alg_values_supported: ["RS256"],
      code_challenge_methods_supported: ["S256"],
    } });
    if (url.pathname === "/auth/authorize") {
      const callback = new URL(url.searchParams.get("redirect_uri")!);
      expect(callback.pathname).toMatch(/^\/portal\/(oidc\/callback|silent-renew.html)$/);
      callback.searchParams.set("state", url.searchParams.get("state")!);
      if (url.searchParams.get("prompt") === "none" && !signedIn) callback.searchParams.set("error", "login_required");
      else {
        expect(url.searchParams.get("code_challenge_method")).toBe("S256");
        challenge = url.searchParams.get("code_challenge")!;
        nonce = url.searchParams.get("nonce");
        callback.searchParams.set("code", "test-code");
      }
      return route.fulfill({ contentType: "text/html", body: `<script>location.replace(${JSON.stringify(callback.toString())})</script>` });
    }
    if (url.pathname === "/auth/logout") {
      expect(url.searchParams.get("post_logout_redirect_uri")).toBe(origin + "/portal/");
      signedIn = false;
      return route.fulfill({ contentType: "text/html", body: `<script>location.replace(${JSON.stringify(origin + "/portal/")})</script>` });
    }
    if (url.pathname === "/auth/token") {
      const form = new URLSearchParams(request.postData()!);
      expect(form.get("grant_type")).toBe("authorization_code");
      expect(createHash("sha256").update(form.get("code_verifier")!).digest("base64url")).toBe(challenge);
      const now = Math.floor(Date.now() / 1000);
      const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
      const idToken = `${encode({ alg: "RS256" })}.${encode({ iss: issuer, aud: "portal-test", sub: "member", iat: now, exp: now + 300, ...(nonce ? { nonce } : {}) })}.fixture`;
      exchanged = true; signedIn = true;
      return route.fulfill({ json: { access_token: "portal-access-secret", id_token: idToken, token_type: "Bearer", expires_in: 300, scope: "openid profile email" } });
    }
    if (url.pathname.startsWith("/api/")) {
      expect(request.headers().authorization).toBe("Bearer portal-access-secret");
      authenticated = true;
    }
    const pathname = url.pathname === "/portal/silent-renew.html" ? "/silent-renew.html" : url.pathname;
    return route.fulfill({ response: await route.fetch({ url: `http://127.0.0.1:4174${pathname}${url.search}` }) });
  });
  await page.goto(origin + "/portal/#/devices");
  await page.getByRole("button", { name: "Log in" }).click();
  await expect(page.getByRole("heading", { name: "My devices", exact: true })).toBeVisible();
  expect(exchanged).toBe(true);
  expect(authenticated).toBe(true);
  const storage = await page.evaluate(() => JSON.stringify({ local: { ...localStorage }, session: { ...sessionStorage } }));
  expect(storage).not.toContain("portal-access-secret");
  expect(storage).not.toContain("id_token");
  // Reload recovers through the IdP session, not a persisted browser token.
  await page.reload();
  await expect(page.getByRole("heading", { name: "My devices", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Log out" }).click();
  await expect(page.getByRole("button", { name: "Log in" })).toBeVisible();
});
