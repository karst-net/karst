// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { UserManager, InMemoryWebStorage, WebStorageStateStore, type User } from "oidc-client-ts";

export type AuthConfig = { oidcAuthority: string; oidcClientId: string };
export type AuthState = "authenticated" | "anonymous" | "disabled";

/** Thrown by `authenticatedFetch` when it has already redirected to login --
 *  callers can tell this apart from an ordinary request failure (a 403, a
 *  500, a network blip) rather than treating every rejection the same way. */
export class SessionExpiredError extends Error {}

export function createAuth(basePath = "/") {


  let configPromise: Promise<AuthConfig> | undefined;

  /** Memoized: every caller (main.tsx, api.ts, the silent-renew page) shares one fetch. */
  function loadConfig(): Promise<AuthConfig> {
    configPromise ??= fetch("/config.json")
      .then((response) => (response.ok ? (response.json() as Promise<AuthConfig>) : { oidcAuthority: "", oidcClientId: "" }))
      .catch(() => ({ oidcAuthority: "", oidcClientId: "" }));
    return configPromise;
  }

  let manager: UserManager | undefined;
  let currentUser: User | undefined;
  let renewal: Promise<boolean> | undefined;
  let redirecting = false;

  function getManager(config: AuthConfig): UserManager {
    if (manager) return manager;
    manager = new UserManager({
      authority: config.oidcAuthority,
      client_id: config.oidcClientId,
      redirect_uri: `${location.origin}${basePath}oidc/callback`,
      silent_redirect_uri: `${location.origin}${basePath}silent-renew.html`,
      response_type: "code",
      scope: "openid profile email",
      automaticSilentRenew: true,
      userStore: new WebStorageStateStore({ store: new InMemoryWebStorage() }),
      post_logout_redirect_uri: `${location.origin}${basePath}`,
    });
    manager.events.addUserLoaded((user) => { currentUser = user; });
    manager.events.addUserUnloaded(() => { currentUser = undefined; });
    manager.events.addSilentRenewError((error) => { console.error("karst: silent renew failed", error); });
    manager.events.addAccessTokenExpired(() => {
      void renewOnce(config).then((renewed) => { if (!renewed) login(config); });
    });
    return manager;
  }

  function accessToken(): string | undefined {
    return currentUser?.expired === false ? currentUser.access_token : undefined;
  }

  const postLoginHashKey = `karst.postLoginHash:${basePath}`;

  /** Call once at startup. Handles the redirect-callback path itself. */
  async function bootstrap(config: AuthConfig): Promise<AuthState> {
    if (!config.oidcAuthority || !config.oidcClientId) return "disabled";
    const userManager = getManager(config);

    if (location.pathname === `${basePath}oidc/callback`) {
      currentUser = await userManager.signinRedirectCallback();
      const hash = sessionStorage.getItem(postLoginHashKey) ?? "";
      sessionStorage.removeItem(postLoginHashKey);
      history.replaceState(null, "", basePath + hash);
      return accessToken() ? "authenticated" : "anonymous";
    }

    try {
      currentUser = (await userManager.signinSilent()) ?? undefined;
    } catch {
      currentUser = undefined;
    }
    return accessToken() ? "authenticated" : "anonymous";
  }

  function login(config: AuthConfig): void {
    if (redirecting) return;
    redirecting = true;
    currentUser = undefined;
    sessionStorage.setItem(postLoginHashKey, location.hash);
    void getManager(config).signinRedirect().catch((error) => {
      redirecting = false;
      console.error("karst: login redirect failed", error);
    });
  }

  function logout(config: AuthConfig): void {
    currentUser = undefined;
    void getManager(config).signoutRedirect();
  }

  /** One retry after a fresh silent renew; the caller treats a second 401 as real. */
  function renewOnce(config: AuthConfig): Promise<boolean> {
    renewal ??= (async () => {
      try {
        currentUser = (await getManager(config).signinSilent()) ?? undefined;
      } catch {
        currentUser = undefined;
      }
      return !!accessToken();
    })().finally(() => { renewal = undefined; });
    return renewal;
  }

  /** Never send an anonymous API request after an authenticated session expires. */
  async function authenticatedFetch(url: string, init?: RequestInit): Promise<Response> {
    const config = await loadConfig();
    if (!config.oidcAuthority || !config.oidcClientId) return fetch(url, init);
    const expired = () => {
      login(config);
      return new SessionExpiredError("Your session has expired. Please sign in again.");
    };
    if (redirecting) throw expired();
    // A missing token must be renewed before the request, even if the server
    // would accept an anonymous request and return a default account.
    if (!accessToken() && !await renewOnce(config)) throw expired();
    const send = () => {
      const token = accessToken();
      if (!token || redirecting) throw expired();
      const headers = new Headers(init?.headers);
      headers.set("authorization", `Bearer ${token}`);
      return fetch(url, { ...init, headers });
    };
    let response = await send();
    if (response.status === 401) {
      if (!await renewOnce(config)) throw expired();
      response = await send();
      if (response.status === 401) throw expired();
    }
    return response;
  }

  async function silentCallback(config: AuthConfig): Promise<void> {
    await getManager(config).signinSilentCallback();
  }
  return { loadConfig, accessToken, authenticatedFetch, bootstrap, login, logout, renewOnce, silentCallback };

}
