// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { Fragment, StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "@karst-net/tokens/theme.css";
import "./styles.css";
import { applyTheme, storedTheme, writePref, type Theme } from "./prefs";
import { bootstrap, loadConfig, login, logout, SessionExpiredError, type AuthConfig, type AuthState } from "./auth";
import { api, getActiveAccountOverride, setActiveAccountOverride } from "./api";
import { FirstRunWizard } from "./views/firstrun";
import { Domains } from "./views/domains";
import { Machines } from "./views/machines";
import { GroupsAccess } from "./views/groups-access";
import { Users } from "./views/users";
import { Bedrock } from "./views/bedrock";
import { Posture } from "./views/posture";
import { Dns } from "./views/dns";
import { Routes } from "./views/routes";
import { Audit } from "./views/audit";
import { RelayServices } from "./views/relay-services";
import { Locations } from "./views/locations";
import { InfrastructureConnections } from "./views/infrastructure-connections";
import { Settings } from "./views/settings";
import { Noc } from "./views/noc";
import { Scaler } from "./views/scaler";
import { Billing } from "./views/billing";

type Route = "domains" | "machines" | "access" | "users" | "groups" | "bedrock" | "posture" | "dns" | "routes" | "audit" | "relays" | "connections" | "locations" | "noc" | "scaler" | "billing" | "settings";
type Mode = "configure" | "observe";
type NavItem = { route: Route; label: string; hash: string; group?: string };

// Machines and Gateways are each both a config surface (enroll/edit) and a
// status surface (health/metrics) -- rather than duplicate the nav entry,
// each view itself splits into a "Manage"/"Status" (or "Metrics") tab (see
// machines.tsx, routes.tsx), and the two modes link to the same route at a
// different sub-path so each lands on the tab that mode actually wants.
//
// Grouped (and pre-sorted by group) so the sidebar can render a static
// section header whenever `group` changes between consecutive items --
// Observe's list stays flat (no `group`) since it's short enough on its own.
const navConfigure: NavItem[] = [
  { route: "machines", label: "Machines", hash: "/machines", group: "Identity & Access" },
  { route: "users", label: "Users", hash: "/users", group: "Identity & Access" },
  { route: "groups", label: "Groups & access", hash: "/groups", group: "Identity & Access" },
  { route: "bedrock", label: "Network lock", hash: "/bedrock", group: "Identity & Access" },
  { route: "domains", label: "Domains", hash: "/domains", group: "Network" },
  { route: "dns", label: "DNS", hash: "/dns", group: "Network" },
  { route: "routes", label: "Gateways", hash: "/gateways", group: "Network" },
  { route: "relays", label: "Relays", hash: "/relays", group: "Infrastructure" },
  { route: "connections", label: "Infrastructure connections", hash: "/connections", group: "Infrastructure" },
  { route: "locations", label: "Authorized locations", hash: "/locations", group: "Infrastructure" },
  { route: "scaler", label: "Scaler Advisor", hash: "/scaler", group: "Infrastructure" },
  { route: "settings", label: "Settings", hash: "/settings", group: "Account" },
  { route: "billing", label: "Billing", hash: "/billing", group: "Account" },
];

const navObserve: NavItem[] = [
  { route: "noc", label: "NOC view", hash: "/noc" },
  { route: "posture", label: "Crypto posture", hash: "/posture" },
  { route: "audit", label: "Audit log", hash: "/audit" },
  { route: "machines", label: "Machines", hash: "/machines/status" },
  { route: "routes", label: "Gateways", hash: "/gateways/metrics" },
];

const navByMode: Record<Mode, NavItem[]> = { configure: navConfigure, observe: navObserve };

/** Collapses consecutive same-`group` items into one section, and leaves
 *  ungrouped items (Observe's whole list) as a single ungrouped section --
 *  so only Configure, which actually has groups, renders as an accordion. */
function groupNav(items: NavItem[]): Array<{ group?: string; items: NavItem[] }> {
  const sections: Array<{ group?: string; items: NavItem[] }> = [];
  for (const item of items) {
    const last = sections[sections.length - 1];
    if (last && last.group === item.group) last.items.push(item);
    else sections.push({ group: item.group, items: [item] });
  }
  return sections;
}

/** Mode and route both come from one hash: each mode's `hash` strings are
 *  disjoint (even for the two routes they share), so matching the whole
 *  path against both lists recovers mode and route together, and an
 *  unrecognized path always falls back to Configure/Domains rather than a
 *  blank page. */
function parseHash(): { route: Route; mode: Mode; machineTab?: "add" } {
  const rawPath = (location.hash || "#/domains").slice(1);
  const path = rawPath === "/routes" ? "/gateways" : rawPath;
  // Preserve saved enrollment links inside the consolidated Machines surface.
  if (path === "/access" || path === "/groups/access") return { route: "access", mode: "configure" };
  if (path === "/enroll" || path === "/machines/add") return { route: "machines", mode: "configure", machineTab: "add" };
  for (const mode of ["configure", "observe"] as const) {
    const match = navByMode[mode].find((item) => item.hash === path);
    if (match) return { route: match.route, mode };
  }
  return { route: "domains", mode: "configure" };
}

/** True once GET /firstrun reports completed=true; undefined while that
 *  fetch is in flight. A deployment that fails to reach the endpoint (e.g.
 *  an older server without the route) is treated as complete rather than
 *  trapping the admin behind a wizard they cannot finish — see the catch
 *  below. */
function useFirstRunCompleted() {
  const [completed, setCompleted] = useState<boolean>();
  const reload = () => { api.firstRunState().then((state) => setCompleted(state.completed)).catch(() => setCompleted(true)); };
  useEffect(reload, []);
  return { completed, reload };
}

function App({ auth, config }: { auth: AuthState; config: AuthConfig }) {
  const [{ route, mode, machineTab }, setState] = useState(parseHash());
  useEffect(() => { const change = () => setState(parseHash()); addEventListener("hashchange", change); return () => removeEventListener("hashchange", change); }, []);
  const switchMode = (next: Mode) => { location.hash = navByMode[next][0].hash; };
  const firstRun = useFirstRunCompleted();

  // Everything else -- the sidebar included -- stays hidden until the
  // wizard reports done. Forcing this in the render tree (rather than only
  // redirecting routeFromHash) is what actually hides every other nav item,
  // not just whichever one happened to be in the URL hash.
  if (firstRun.completed === false) {
    return <div className="shell">
      <a className="skip" href="#main">Skip to content</a>
      <main id="main">
        <header><AccountSwitcher config={config} />{auth === "authenticated" && <button onClick={() => logout(config)}>Log out</button>}<ThemeChooser /></header>
        <FirstRunWizard onComplete={firstRun.reload} />
      </main>
    </div>;
  }
  // A real landmark/heading structure even while this is in flight --
  // returning null here left a window (GET /firstrun resolving) where
  // axe-core could inspect a document with no <main> and no <h1> at all,
  // which is exactly what it caught in CI.
  if (firstRun.completed === undefined) {
    return <div className="shell">
      <a className="skip" href="#main">Skip to content</a>
      <main id="main"><h1>Karst</h1><p>Loading…</p></main>
    </div>;
  }

  return <div className={`shell${route === "noc" ? " shell-noc" : ""}`}>
    <a className="skip" href="#main">Skip to content</a>
    <aside>
      <h1>Karst</h1>
      <p>Administration console</p>
      <nav aria-label="Mode" className="actions">
        <button aria-pressed={mode === "configure"} onClick={() => switchMode("configure")}>Configure</button>
        <button aria-pressed={mode === "observe"} onClick={() => switchMode("observe")}>Observe</button>
      </nav>
      <nav aria-label="Primary">{groupNav(navByMode[mode]).map((section, index) => {
        const links = section.items.map((item) => <a key={item.hash} aria-current={route === item.route || (route === "access" && item.route === "groups") ? "page" : undefined} href={`#${item.hash}`}>{item.label}</a>);
        // Collapsed by default; a section that already contains the active
        // route opens so navigating here never hides where you landed.
        return section.group
          ? <details key={section.group} open={section.items.some((item) => item.route === route || (route === "access" && item.route === "groups"))}>
            <summary>{section.group}</summary>
            {links}
          </details>
          : <Fragment key={`flat-${index}`}>{links}</Fragment>;
      })}</nav>
    </aside>
    <main id="main">
      <header><AccountSwitcher config={config} />{auth === "authenticated" && <button onClick={() => logout(config)}>Log out</button>}<ThemeChooser /></header>
      {route === "domains" && <Domains />}
      {route === "machines" && <Machines key={`${mode}:${machineTab ?? "list"}`} defaultTab={machineTab ?? (mode === "observe" ? "status" : "manage")} />}
      {route === "access" && <GroupsAccess tab="access" />}
      {route === "users" && <Users />}
      {route === "groups" && <GroupsAccess tab="groups" />}
      {route === "bedrock" && <Bedrock />}
      {route === "posture" && <Posture />}
      {route === "dns" && <Dns />}
      {route === "routes" && <Routes key={mode} defaultTab={mode === "observe" ? "metrics" : "manage"} />}
      {route === "audit" && <Audit />}
      {route === "relays" && <RelayServices />}
      {route === "connections" && <InfrastructureConnections />}
      {route === "locations" && <Locations />}
      {route === "noc" && <Noc />}
      {route === "scaler" && <Scaler />}
      {route === "billing" && <Billing />}
      {route === "settings" && <Settings />}
    </main>
  </div>;
}

// Only the switcher needs to remember the true home account (and the
// signed-in user's friendly label) across a switched-into reload -- see
// AccountSwitcher's own comment for why.
const homeAccountKey = "karst.homeAccount";
const homeUserLabelKey = "karst.homeUserLabel";

/** ADR-0037: the header's account line, upgraded to a real switcher only
 *  when the caller has operator-granted access to another account.
 *  Switching reloads the page rather than trying to invalidate every view's
 *  own useResource cache -- every view already fetches on mount, so a
 *  reload is the simplest thing that is actually correct. */
function AccountSwitcher({ config }: { config: AuthConfig }) {
  const [home, setHome] = useState<string>();
  const [homeLabel, setHomeLabel] = useState<string>();
  const [accessible, setAccessible] = useState<string[]>([]);
  // Distinct from homeLabel being merely unset (still loading): account() or
  // accessibleAccounts() rejected and it wasn't a session expiry (that case
  // redirects instead -- see below), so there is nothing to wait for.
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    // A SessionExpiredError means authenticatedFetch already called login()
    // as a side effect -- the page is mid-redirect. Calling it again here is
    // a harmless no-op (login() itself is idempotent while that redirect is
    // in flight) and makes the "an invalid session always reaches the login
    // screen" guarantee hold at this call site too, not just incidentally
    // through the shared transport.
    const onFailure = (error: unknown) => {
      if (error instanceof SessionExpiredError) login(config);
      else setFailed(true);
    };
    // api.account() answers for whichever account is currently in effect --
    // while no override is active that IS the true home, and this is the
    // only moment it can be told apart from a switched-into one. Cached so
    // a reload while switched still knows what "yours" means.
    if (!getActiveAccountOverride()) {
      api.account().then((account) => {
        setHome(account.id);
        try { sessionStorage.setItem(homeAccountKey, account.id); } catch { /* per-viewer convenience only */ }
        // The account id itself is meaningless to a human; show the
        // signed-in user's own name or email instead, falling back to the
        // id if neither claim came through from the IdP.
        api.currentUser().then((user) => {
          const label = user.name || user.email || account.id;
          setHomeLabel(label);
          try { sessionStorage.setItem(homeUserLabelKey, label); } catch { /* per-viewer convenience only */ }
        }).catch(() => setHomeLabel(account.id));
      }).catch(onFailure);
    } else {
      try {
        setHome(sessionStorage.getItem(homeAccountKey) ?? undefined);
        setHomeLabel(sessionStorage.getItem(homeUserLabelKey) ?? undefined);
      } catch { setHome(undefined); setHomeLabel(undefined); }
    }
    api.accessibleAccounts().then((rows) => setAccessible(rows.map((row) => row.account_id))).catch(onFailure);
  }, [config]);

  if (failed && homeLabel === undefined) return <p>Account: <strong>Unavailable</strong></p>;
  if (accessible.length === 0) return <p>Account: <strong>{homeLabel ?? home ?? "…"}</strong></p>;
  const current = getActiveAccountOverride() ?? home ?? "";
  return <label>Account <select value={current} onChange={(event) => {
    const next = event.target.value;
    setActiveAccountOverride(next === home ? null : next);
    location.reload();
  }}>
    {home && <option value={home}>{homeLabel ?? home} (yours)</option>}
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
