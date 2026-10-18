// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { createAuth } from "@karst-net/auth";

const oidc = vi.hoisted(() => ({
  signinSilent: vi.fn(),
  signinRedirect: vi.fn(),
  expired: undefined as (() => void) | undefined,
}));
vi.mock("oidc-client-ts", () => ({
  UserManager: class {
    signinSilent = oidc.signinSilent;
    signinRedirect = oidc.signinRedirect;
    events = {
      addUserLoaded: vi.fn(), addUserUnloaded: vi.fn(), addSilentRenewError: vi.fn(),
      addAccessTokenExpired: (callback: () => void) => { oidc.expired = callback; },
    };
  },
  InMemoryWebStorage: class {},
  WebStorageStateStore: class {},
}));

const config = { oidcAuthority: "https://identity.test", oidcClientId: "console" };
const user = (expired = false) => ({ expired, access_token: expired ? "expired" : "valid" });
let apiFetch: ReturnType<typeof vi.fn>;

beforeEach(() => {
  vi.clearAllMocks();
  oidc.expired = undefined;
  oidc.signinRedirect.mockResolvedValue(undefined);
  vi.stubGlobal("location", { origin: "https://console.test", pathname: "/", hash: "#/machines" });
  vi.stubGlobal("sessionStorage", { setItem: vi.fn() });
  apiFetch = vi.fn().mockResolvedValue(new Response("{}"));
  vi.stubGlobal("fetch", vi.fn((url: string, init?: RequestInit) => url === "/config.json"
    ? Promise.resolve(Response.json(config)) : apiFetch(url, init)));
});
afterEach(() => vi.unstubAllGlobals());

test("failed renewal redirects once without sending anonymous API requests", async () => {
  const auth = createAuth();
  oidc.signinSilent.mockRejectedValue(new Error("login_required"));
  const results = await Promise.allSettled([
    auth.authenticatedFetch("/api/accounts"), auth.authenticatedFetch("/api/machines"),
  ]);
  expect(results.map((result) => result.status)).toEqual(["rejected", "rejected"]);
  expect(apiFetch).not.toHaveBeenCalled();
  expect(oidc.signinSilent).toHaveBeenCalledTimes(1);
  expect(oidc.signinRedirect).toHaveBeenCalledTimes(1);
  expect(sessionStorage.setItem).toHaveBeenCalledWith("karst.postLoginHash:/", "#/machines");
});

test("an already expired renewal result cannot authorize a request", async () => {
  const auth = createAuth();
  oidc.signinSilent.mockResolvedValue(user(true));
  await expect(auth.authenticatedFetch("/api/accounts")).rejects.toThrow("session has expired");
  expect(apiFetch).not.toHaveBeenCalled();
  expect(oidc.signinRedirect).toHaveBeenCalledTimes(1);
});

test("renewal happens before the request and preserves request headers and body", async () => {
  const auth = createAuth();
  oidc.signinSilent.mockResolvedValue(user());
  await auth.authenticatedFetch("/api/machines", { method: "POST", body: "{}", headers: { accept: "text/csv" } });
  const init = apiFetch.mock.calls[0][1] as RequestInit;
  expect(new Headers(init.headers).get("authorization")).toBe("Bearer valid");
  expect(new Headers(init.headers).get("accept")).toBe("text/csv");
  expect(init.method).toBe("POST");
  expect(init.body).toBe("{}");
});

test("a rejected renewed token forces login after one retry", async () => {
  const auth = createAuth();
  oidc.signinSilent.mockResolvedValue(user());
  await auth.bootstrap(config);
  apiFetch.mockImplementation(() => Promise.resolve(new Response(null, { status: 401 })));
  await expect(auth.authenticatedFetch("/api/accounts")).rejects.toThrow("session has expired");
  expect(apiFetch).toHaveBeenCalledTimes(2);
  expect(oidc.signinSilent).toHaveBeenCalledTimes(2);
  expect(oidc.signinRedirect).toHaveBeenCalledTimes(1);
  expect(auth.accessToken()).toBeUndefined();
});

test("a 401 recovers with a renewed token while permission errors do not trigger login", async () => {
  const auth = createAuth();
  oidc.signinSilent.mockResolvedValueOnce(user()).mockResolvedValue({ expired: false, access_token: "renewed" });
  await auth.bootstrap(config);
  apiFetch.mockResolvedValueOnce(new Response(null, { status: 401 }))
    .mockResolvedValueOnce(new Response("{}"));
  expect((await auth.authenticatedFetch("/api/accounts")).ok).toBe(true);
  expect(new Headers((apiFetch.mock.calls[1][1] as RequestInit).headers).get("authorization")).toBe("Bearer renewed");
  apiFetch.mockResolvedValueOnce(new Response(null, { status: 403 }));
  expect((await auth.authenticatedFetch("/api/accounts")).status).toBe(403);
  expect(oidc.signinSilent).toHaveBeenCalledTimes(2);
  expect(oidc.signinRedirect).not.toHaveBeenCalled();
});

test("expiry while idle forces login when the identity session has ended", async () => {
  const auth = createAuth();
  oidc.signinSilent.mockResolvedValueOnce(user());
  await auth.bootstrap(config);
  oidc.signinSilent.mockRejectedValue(new Error("login_required"));
  oidc.expired!();
  await vi.waitFor(() => expect(oidc.signinRedirect).toHaveBeenCalledTimes(1));
  expect(apiFetch).not.toHaveBeenCalled();
});

test("unconfigured development requests still reach the mock API", async () => {
  const auth = createAuth();
  vi.stubGlobal("fetch", vi.fn((url: string, init?: RequestInit) => url === "/config.json"
    ? Promise.resolve(Response.json({ oidcAuthority: "", oidcClientId: "" })) : apiFetch(url, init)));
  await auth.authenticatedFetch("/api/accounts");
  expect(apiFetch).toHaveBeenCalledTimes(1);
  expect(oidc.signinSilent).not.toHaveBeenCalled();
});
