// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "@karst-net/tokens/theme.css";
import "./styles.css";
import { applyTheme, storedTheme, writePref, type Theme } from "./prefs";
import { bootstrap, loadConfig, login, logout, type AuthConfig, type AuthState } from "./auth";
import { api, getActiveAccountOverride, setActiveAccountOverride } from "./api";
import { Setup } from "./views/setup";
import { Domains } from "./views/domains";
import { Machines } from "./views/machines";
import { Access } from "./views/access";
import { Keys } from "./views/keys";
import { Users } from "./views/users";
import { Groups } from "./views/groups";
import { Bedrock } from "./views/bedrock";
import { Posture } from "./views/posture";
import { Dns } from "./views/dns";
import { Routes } from "./views/routes";
import { Audit } from "./views/audit";
import { Relays } from "./views/relays";
import { Turns } from "./views/turns";
import { Settings } from "./views/settings";

type Route = "setup" | "domains" | "machines" | "access" | "keys" | "users" | "groups" | "bedrock" | "posture" | "dns" | "routes" | "audit" | "relays" | "turns" | "settings";

const nav: Array<[Route, string]> = [
  ["setup", "First-run setup"], ["domains", "Domains"], ["machines", "Machines"], ["access", "Access controls"], ["keys", "Auth keys"],
  ["users", "Users"], ["groups", "Groups"], ["bedrock", "Network lock"], ["posture", "Crypto posture"],
  ["dns", "DNS"], ["routes", "Network routes"], ["audit", "Audit log"], ["relays", "Relays"], ["turns", "TURN servers"], ["settings", "Settings"],
];

const routeFromHash = (): Route => (nav.find(([route]) => `#/${route}` === location.hash)?.[0] ?? "setup");

function App({ auth, config }: { auth: AuthState; config: AuthConfig }) {
  const [route, setRoute] = useState<Route>(routeFromHash());
  useEffect(() => { const change = () => setRoute(routeFromHash()); addEventListener("hashchange", change); return () => removeEventListener("hashchange", change); }, []);
  const navigate = (next: string) => { location.hash = `/${next}`; };
  return <div className="shell">
    <a className="skip" href="#main">Skip to content</a>
    <aside>
      <h1>Karst</h1>
      <p>Administration console</p>
      <nav aria-label="Primary">{nav.map(([key, label]) => <a key={key} aria-current={route === key ? "page" : undefined} href={`#/${key}`}>{label}</a>)}</nav>
    </aside>
    <main id="main">
      <header><AccountSwitcher />{auth === "authenticated" && <button onClick={() => logout(config)}>Log out</button>}<ThemeChooser /></header>
      {route === "setup" && <Setup go={navigate} />}
      {route === "domains" && <Domains />}
      {route === "machines" && <Machines />}
      {route === "access" && <Access />}
      {route === "keys" && <Keys />}
      {route === "users" && <Users />}
      {route === "groups" && <Groups />}
      {route === "bedrock" && <Bedrock />}
      {route === "posture" && <Posture />}
      {route === "dns" && <Dns />}
      {route === "routes" && <Routes />}
      {route === "audit" && <Audit />}
      {route === "relays" && <Relays />}
      {route === "turns" && <Turns />}
      {route === "settings" && <Settings />}
    </main>
  </div>;
}

// Only the switcher needs to remember the true home account across a
// switched-into reload -- see AccountSwitcher's own comment for why.
const homeAccountKey = "karst.homeAccount";

/** ADR-0037: the header's account line, upgraded to a real switcher only
 *  when the caller has operator-granted access to another account.
 *  Switching reloads the page rather than trying to invalidate every view's
 *  own useResource cache -- every view already fetches on mount, so a
 *  reload is the simplest thing that is actually correct. */
function AccountSwitcher() {
  const [home, setHome] = useState<string>();
  const [accessible, setAccessible] = useState<string[]>([]);
  useEffect(() => {
    // api.account() answers for whichever account is currently in effect --
    // while no override is active that IS the true home, and this is the
    // only moment it can be told apart from a switched-into one. Cached so
    // a reload while switched still knows what "yours" means.
    if (!getActiveAccountOverride()) {
      api.account().then((account) => {
        setHome(account.id);
        try { sessionStorage.setItem(homeAccountKey, account.id); } catch { /* per-viewer convenience only */ }
      }).catch(() => {});
    } else {
      try { setHome(sessionStorage.getItem(homeAccountKey) ?? undefined); } catch { setHome(undefined); }
    }
    api.accessibleAccounts().then((rows) => setAccessible(rows.map((row) => row.account_id))).catch(() => {});
  }, []);

  if (accessible.length === 0) return <p>Account: <strong>{home ?? "…"}</strong></p>;
  const current = getActiveAccountOverride() ?? home ?? "";
  return <label>Account <select value={current} onChange={(event) => {
    const next = event.target.value;
    setActiveAccountOverride(next === home ? null : next);
    location.reload();
  }}>
    {home && <option value={home}>{home} (yours)</option>}
    {accessible.map((id) => <option key={id} value={id}>{id}</option>)}
  </select></label>;
}

/** A three-state chooser, not a toggle: "system" has to remain reachable, or an
 *  admin who follows their OS preference cannot get back to it. */
function ThemeChooser() {
  const [theme, setTheme] = useState<Theme>(storedTheme);
  useEffect(() => { applyTheme(theme, document.documentElement); writePref("theme", theme); }, [theme]);
  return <label htmlFor="theme">Theme <select id="theme" value={theme} onChange={(event) => setTheme(event.target.value as Theme)}>
    <option value="system">System</option>
    <option value="light">Light</option>
    <option value="dark">Dark</option>
  </select></label>;
}

/** Shown when `bootstrap` finds no active session. `disabled` (no OIDC
 *  configured — the `just api-mock` dev flow) skips this and renders the app
 *  directly, matching the console's pre-auth behavior. Signing in is a full
 *  redirect to the IdP, so there is nothing to wire up for success here —
 *  `bootstrap` completes the flow on the next load, at `/auth/callback`. */
function LoginGate({ config }: { config: AuthConfig }) {
  return <div className="shell"><main><h1>Karst</h1><p>Sign in to administer this deployment.</p>
    <button onClick={() => login(config)}>Log in</button>
  </main></div>;
}

async function boot() {
  const config = await loadConfig();
  const auth = await bootstrap(config);
  const root = createRoot(document.getElementById("root")!);
  root.render(<StrictMode>{auth === "anonymous" ? <LoginGate config={config} /> : <App auth={auth} config={config} />}</StrictMode>);
}

void boot();
