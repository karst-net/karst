// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useEffect, useState } from "react";
import { api } from "../api";
import { readPref, writePref } from "../prefs";

const steps: Array<[string, string]> = [
  ["Configure the coordination server", "Open the installation guide and enter its public URL."],
  ["Create an enrollment key", "Create a short-lived auth key for the first node."],
  ["Connect a node", "Install Karst, add the key to its daemon configuration, then start the service."],
  ["Confirm the node", "Return to Machines and confirm the node reports a current posture."],
];

export function Setup({ go }: { go: (route: string) => void }) {
  // Setup spans a restart and a trip to another machine to run the enrollment
  // command. Progress and the server URL live in the browser rather than in
  // component state, which used to lose both on the first navigation and left
  // step 1 configuring nothing at all.
  const [done, setDone] = useState(() => Number.parseInt(readPref("setup.done") ?? "0", 10) || 0);
  const [serverUrl, setServerUrl] = useState(() => readPref("setup.serverUrl") ?? "");
  const [key, setKey] = useState<string>();
  const [error, setError] = useState<string>();
  useEffect(() => { writePref("setup.done", String(done)); }, [done]);
  useEffect(() => { writePref("setup.serverUrl", serverUrl); }, [serverUrl]);
  const create = async () => {
    try {
      const created = await api.createSetupKey({ name: "First node", type: "one-off", expires_in: 86_400, usage_limit: 1, auto_groups: [], ephemeral: false });
      setKey(created.key); setError(undefined); setDone((current) => Math.max(current, 2));
    } catch (failure) { setError((failure as Error).message); }
  };
  return <section>
    <h2>Set up your Karst network</h2>
    <p className="lede">Follow these steps in order. Nothing is hidden behind source code or a terminal-only configuration.</p>
    <ol className="steps">{steps.map(([title, description], index) => <li key={title}>
      <div>
        <strong>{title}</strong><p>{description}</p>
        {index === 0 && <label>Server URL<input aria-label="Server URL" placeholder="https://karst.example.com" value={serverUrl} onChange={(event) => setServerUrl(event.target.value)} /></label>}
        {index === 1 && <><button disabled={!serverUrl} onClick={() => void create()}>Create enrollment key</button>{!serverUrl && <p>Enter the server URL in step 1 first — the enrollment command needs it.</p>}{error && <p role="alert">{error}</p>}</>}
        {index === 2 && (key
          ? <><p>On the machine you are adding, put this one-time key in <code>/etc/karst/karstd.toml</code>. Keep the server pins from the installation guide; the key is shown only once.</p><label>Control configuration<textarea aria-label="Control configuration" readOnly rows={5} value={`[control]\nserver = "${serverUrl}"\nserver_kem_pin = "…"\nserver_verify_pin = "…"\nsetup_key = "${key}"`} /></label><p>Then validate and start the daemon: <code>sudo karstd check --config /etc/karst/karstd.toml</code> followed by <code>sudo systemctl enable --now karstd</code>.</p></>
          : <p>The configuration snippet appears here once you have created a key.</p>)}
      </div>
      <button onClick={() => setDone((current) => Math.max(current, index + 1))}>{done > index ? "Complete" : "Mark complete"}</button>
    </li>)}</ol>
    <p><a href="/docs/quickstart.html">Read the quickstart</a> · <button className="link" onClick={() => go("keys")}>Create an auth key</button> · <button className="link" onClick={() => go("machines")}>View machines</button></p>
  </section>;
}
