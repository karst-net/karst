// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useState } from "react";
import { Dialog } from "@karst-net/ui";
import { api } from "../api";
import { Failure, useResource } from "../common";
import { downloadInstaller, type InstallationSettings } from "../relay-installation";

export function RelayInstallation({ onClose }: { onClose: () => void }) {
  const locations = useResource(api.locations);
  const [settings, setSettings] = useState<InstallationSettings>({ schema_version: 1, address: "", tls_server_name: "", region: "default", image: "ghcr.io/karst-net/karst-relay:dev", control_image: "ghcr.io/karst-net/karst-control:dev", location: null });
  const [acknowledged, setAcknowledged] = useState(false);
  const [downloaded, setDownloaded] = useState(false);
  const [message, setMessage] = useState<string>();
  const change = (value: Partial<InstallationSettings>) => { setSettings({ ...settings, ...value }); setDownloaded(false); setAcknowledged(false); };
  return <Dialog open title="Install a local relay" onClose={onClose}>
    <p>This handoff supports one relay beside an existing reference Docker Compose control service on Linux. Python 3.11+, Docker Compose v2 and OpenSSL are required. It reuses the deployment's existing trusted relay certificate and identity; the control image must support managed-only admission.</p>
    <p>Infrastructure connections currently discover locations; they cannot deploy workloads. Remote hosts and cloud or cluster provisioning are not supported by this handoff. Internet egress uses a separately enrolled Linux Gateway, selected after registration.</p>
    {message && <p role="alert">{message}</p>}
    {locations.error && <Failure message={locations.error} retry={locations.reload} />}
    <form onSubmit={event => { event.preventDefault(); setMessage(undefined); try { downloadInstaller(settings); setDownloaded(true); } catch (error) { setMessage((error as Error).message); } }}>
      <label>Public IP address and port<input required aria-label="Installation relay address" placeholder="203.0.113.7:443" pattern="(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}|\[[0-9a-fA-F:]+\]):[0-9]{1,5}" value={settings.address} onChange={event => change({ address: event.target.value.trim() })} /></label>
      <label>TLS server name<input required maxLength={253} pattern="[a-zA-Z0-9.-]+" value={settings.tls_server_name} onChange={event => change({ tls_server_name: event.target.value.trim() })} /></label>
      <p>Use the existing relay's endpoint, TLS name and region when adopting it. Its certificate must match this TLS name; trust is preserved.</p>
      <label>Region<input required maxLength={64} pattern="[a-zA-Z0-9][a-zA-Z0-9_-]*" value={settings.region} onChange={event => change({ region: event.target.value.trim() })} /></label>
      <label>Declared location<select aria-label="Installation location" defaultValue="" onChange={event => { const location = locations.value?.find(item => item.id === event.target.value); change({ location: location ? { lat: location.lat, lon: location.lon, label: location.label || undefined } : null }); }}><option value="">No declared location</option>{locations.value?.map(location => <option key={location.id} value={location.id}>{location.label || `${location.lat}, ${location.lon}`}</option>)}</select></label>
      <details><summary>Runtime settings</summary><label>Karst relay image<input required pattern="ghcr\.io/karst-net/karst-relay(:[a-zA-Z0-9_][a-zA-Z0-9_.-]*|@sha256:[a-f0-9]{64})" value={settings.image} onChange={event => change({ image: event.target.value.trim() })} /></label><label>Karst control image<input required pattern="ghcr\.io/karst-net/karst-control(:[a-zA-Z0-9_][a-zA-Z0-9_.-]*|@sha256:[a-f0-9]{64})" value={settings.control_image} onChange={event => change({ control_image: event.target.value.trim() })} /></label><p>Use compatible published tags or immutable digests. Ensure selected images are available locally or can be pulled. The installer rejects control images lacking the required admission capability.</p></details>
      <p>Applying restarts control and relay and may interrupt connections. The generated writer denies access to unconfigured and legacy tenants. Existing group-managed grants still apply. No administrator credentials, private keys or access grants are included in the download.</p>
      <label><input type="checkbox" checked={acknowledged} onChange={event => setAcknowledged(event.target.checked)} />I reviewed the deployment scope and interruption to existing relay access.</label>
      <button className="primary" type="submit" disabled={!acknowledged}>Download installation handoff</button>
    </form>
    {downloaded && <div role="status"><p>Handoff downloaded. Installation has not run.</p><ol><li>Copy the file to the existing control host.</li><li>Run <code>python3 karst-relay-install.py --directory /path/to/compose</code> to check prerequisites, then repeat with <code>--apply</code> to install. No file editing is required.</li><li>Import <code>state/relay-install/receipt.json</code> using Add relay, then review allowed groups and optional internet egress. Enable service publication through its preview if necessary.</li><li>Check admission and Gateway observations before relying on the relay. A running container does not prove traffic readiness.</li></ol><p>Failed installations record their stage locally. Retry the same handoff; keys are preserved. Keep using the generated Compose overlay for future lifecycle operations.</p></div>}
    <button onClick={onClose}>Close</button>
  </Dialog>;
}
