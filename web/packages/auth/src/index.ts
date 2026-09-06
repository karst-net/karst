// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { UserManager, InMemoryWebStorage, WebStorageStateStore, type User } from "oidc-client-ts";

export type AuthConfig = { oidcAuthority: string; oidcClientId: string };
export type AuthState = "authenticated" | "anonymous" | "disabled";

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
      return "authenticated";
    }

    try {
      currentUser = (await userManager.signinSilent()) ?? undefined;
    } catch {
      currentUser = undefined;
    }
    return currentUser ? "authenticated" : "anonymous";
  }

  function login(config: AuthConfig): void {
    sessionStorage.setItem(postLoginHashKey, location.hash);
    void getManager(config).signinRedirect();
  }

  function logout(config: AuthConfig): void {
    currentUser = undefined;
    void getManager(config).signoutRedirect();
  }

  /** One retry after a fresh silent renew; the caller treats a second 401 as real. */
  async function renewOnce(config: AuthConfig): Promise<boolean> {
    try {
      currentUser = (await getManager(config).signinSilent()) ?? undefined;
    } catch {
      currentUser = undefined;
    }
    return currentUser !== undefined;
  }

  async function silentCallback(config: AuthConfig): Promise<void> {
    await getManager(config).signinSilentCallback();
  }
  return { loadConfig, accessToken, bootstrap, login, logout, renewOnce, silentCallback };

}
