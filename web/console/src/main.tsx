// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "@karst-net/tokens/theme.css";
import "./styles.css";
import { applyTheme, storedTheme, writePref, type Theme } from "./prefs";
import { Setup } from "./views/setup";
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
import { Settings } from "./views/settings";

type Route = "setup" | "machines" | "access" | "keys" | "users" | "groups" | "bedrock" | "posture" | "dns" | "routes" | "audit" | "relays" | "settings";

const nav: Array<[Route, string]> = [
  ["setup", "First-run setup"], ["machines", "Machines"], ["access", "Access controls"], ["keys", "Auth keys"],
  ["users", "Users"], ["groups", "Groups"], ["bedrock", "Network lock"], ["posture", "Crypto posture"],
  ["dns", "DNS"], ["routes", "Network routes"], ["audit", "Audit log"], ["relays", "Relays"], ["settings", "Settings"],
];

const routeFromHash = (): Route => (nav.find(([route]) => `#/${route}` === location.hash)?.[0] ?? "setup");

function App() {
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
      <header><p>Account: <strong>Karst</strong></p><ThemeChooser /></header>
      {route === "setup" && <Setup go={navigate} />}
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
      {route === "settings" && <Settings />}
    </main>
  </div>;
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

createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);
