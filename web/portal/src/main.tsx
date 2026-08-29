// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { StrictMode, useEffect, useState, type ReactNode } from "react";
import { createRoot } from "react-dom/client";
import { EmptyState, Observed } from "@karst-net/ui";
import "@karst-net/tokens/theme.css";
import "./styles.css";
import { api, type Access, type Device, type ReleaseAsset, type Session } from "./api";

type Route = "devices" | "download" | "access" | "sessions";
const routes: Array<[Route, string]> = [["devices", "My devices"], ["download", "Download"], ["access", "My access"], ["sessions", "Sessions"]];
const current = (): Route => routes.find(([key]) => location.hash === `#/${key}`)?.[0] ?? "devices";
function Resource<T>({ load, children }: { load: () => Promise<T>; children: (value: T, reload: () => void) => ReactNode }) { const [value, setValue] = useState<T>(); const [error, setError] = useState<string>(); const reload = () => { setError(undefined); load().then(setValue).catch((e: Error) => setError(e.message)); }; useEffect(reload, []); if (error) return <p role="alert">{error} <button onClick={reload}>Retry</button></p>; return value === undefined ? <p>Loading…</p> : children(value, reload); }
function Devices() { const [notice, setNotice] = useState(""); const [renaming, setRenaming] = useState<Device>(); const [name, setName] = useState(""); return <Resource load={api.devices}>{(devices, reload) => <section><h2>My devices</h2><p className="lede">Only devices signed in as you appear here.</p>{notice && <p role="status">{notice}</p>}<button className="primary" onClick={() => void api.enrol().then(({ key, expires_at }) => setNotice(`Add this key to [control] setup_key in /etc/karst/karstd.toml before ${new Date(expires_at).toLocaleString()}, then start karstd: ${key}`)).catch((e: Error) => setNotice(e.message))}>Add a device</button>{renaming && <form onSubmit={(event) => { event.preventDefault(); void api.rename(renaming.handle, name).then(() => { setNotice("Device renamed."); setRenaming(undefined); reload(); }).catch((e: Error) => setNotice(e.message)); }}><label>New device name <input autoFocus value={name} onChange={(event) => setName(event.target.value)} /></label><button type="submit">Save name</button><button type="button" onClick={() => setRenaming(undefined)}>Cancel</button></form>}{devices.length ? <table><thead><tr><th>Name</th><th>Platform</th><th>Last seen</th><th>Actions</th></tr></thead><tbody>{devices.map((device) => <tr key={device.handle}><td><strong>{device.name}</strong></td><td>{device.platform}</td><td><Observed at={device.last_seen_at} /></td><td><button onClick={() => { setRenaming(device); setName(device.name); }}>Rename</button> <button className="danger" onClick={() => { if (confirm(`Revoke ${device.name}? Its live session will be disconnected.`)) void api.revoke(device.handle).then(() => { setNotice("Device revoked."); reload(); }); }}>Revoke</button></td></tr>)}</tbody></table> : <EmptyState title="No devices">Add a device to connect to Karst.</EmptyState>}</section>}</Resource>; }
function Download() {
  // The browser will not tell a page its CPU architecture — `navigator.platform`
  // is deprecated and lies, and userAgentData.getHighEntropyValues is
  // Chromium-only and asynchronous. So the platform is guessed and the
  // architecture is *asked*: every build for the detected platform is listed
  // with its architecture, format and checksum, and the user picks. Guessing
  // wrong here hands somebody a package that will not install, which is worse
  // than one extra decision.
  const platform = navigator.userAgent.includes("Win") ? "windows" : navigator.userAgent.includes("Mac") ? "macos" : "linux";
  return <Resource load={api.releases}>{(assets: ReleaseAsset[]) => {
    const mine = assets.filter((item) => item.platform === platform);
    const others = assets.filter((item) => item.platform !== platform);
    return <section>
      <h2>Download Karst</h2>
      <p>Your browser appears to be running <strong>{platform}</strong>.</p>
      {mine.length ? <table><thead><tr><th>Package</th><th>Architecture</th><th>SHA-256</th></tr></thead><tbody>{mine.map((asset) => <tr key={asset.name}><td><a className="download" href={asset.url} download>{asset.format === "pkg" ? "Installer" : asset.format} — {asset.name}</a></td><td>{asset.arch}</td><td><code>{asset.sha256}</code></td></tr>)}</tbody></table>
        : <p role="alert">No installer is published for {platform} yet.</p>}
      <p>Verify the file before installing: <code>{platform === "windows" ? "Get-FileHash <file> -Algorithm SHA256" : "sha256sum <file>"}</code>. Compare the output with the checksum above. <a href="/docs/install.html">Installation and verification guide</a></p>
      {others.length > 0 && <details><summary>Other platforms</summary><ul>{others.map((asset) => <li key={asset.name}><a href={asset.url} download>{asset.name}</a> — {asset.platform} {asset.arch}</li>)}</ul></details>}
    </section>;
  }}</Resource>;
}
function AccessView() { return <Resource load={api.access}>{(items: Access[]) => <section><h2>What I can reach</h2><p className="lede">Each destination includes the policy rule and your group that grant access.</p>{items.length ? <ul className="access">{items.map((item) => <li key={item.destination}><strong>{item.destination}</strong> — because you are in <strong>{item.group}</strong>, via rule {item.rule} of the access policy (last changed <Observed at={item.changed_at} /> by {item.changed_by}).</li>)}</ul> : <EmptyState title="No reachable destinations">Your current policy does not grant access to a named destination.</EmptyState>}</section>}</Resource>; }
function Sessions() { return <Resource load={api.sessions}>{(items: Session[]) => <section><h2>My session history</h2>{items.length ? <table><thead><tr><th>Device</th><th>Started</th><th>Ended</th><th>IP</th></tr></thead><tbody>{items.map((item, i) => <tr key={i}><td>{item.device}</td><td><Observed at={item.started_at} /></td><td><Observed at={item.ended_at} /></td><td><code>{item.ip}</code></td></tr>)}</tbody></table> : <EmptyState title="No sessions">Your sign-in history will appear here.</EmptyState>}</section>}</Resource>; }
function App() { const [route, setRoute] = useState(current()); useEffect(() => { const handler = () => setRoute(current()); addEventListener("hashchange", handler); return () => removeEventListener("hashchange", handler); }, []); return <div className="shell"><a className="skip" href="#main">Skip to content</a><aside><h1>Karst</h1><p>Your network</p><nav aria-label="Primary">{routes.map(([key, label]) => <a key={key} href={`#/${key}`} aria-current={route === key ? "page" : undefined}>{label}</a>)}</nav></aside><main id="main">{route === "devices" && <Devices />}{route === "download" && <Download />}{route === "access" && <AccessView />}{route === "sessions" && <Sessions />}</main></div>; }
createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);
