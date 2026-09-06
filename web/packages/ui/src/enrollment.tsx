// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.
import { useEffect, useState } from "react";

export type EnrollmentMetadata = { server_kem_pin: string; server_verify_pin: string; control_minimum_version: number };
export type EnrollmentGrant = { key: string; expires_at: string };

export function Enrollment({ metadata, issue }: { metadata: () => Promise<EnrollmentMetadata>; issue: () => Promise<EnrollmentGrant> }) {
  const [ready, setReady] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [download, setDownload] = useState<{ url: string; expires: string }>();
  useEffect(() => () => { if (download) URL.revokeObjectURL(download.url); }, [download]);
  const create = async () => {
    setBusy(true); setError(""); setDownload(undefined);
    try {
      if (location.protocol !== "https:") throw new Error("Open the portal over trusted HTTPS before downloading enrollment credentials.");
      const pins = await metadata();
      if (!pins.server_kem_pin || !pins.server_verify_pin || pins.control_minimum_version !== 1) throw new Error("The server did not supply supported enrollment settings.");
      const grant = await issue();
      // JSON string quoting is also valid for these TOML basic strings.
      const content = Object.entries({ server: location.origin, ...pins, setup_key: grant.key }).map(([key, value]) => `${key} = ${JSON.stringify(value)}`).join("\n") + "\n";
      setDownload({ url: URL.createObjectURL(new Blob([content], { type: "application/toml" })), expires: grant.expires_at });
    } catch (failure) { setError(failure instanceof Error ? failure.message : "Enrollment could not be prepared."); }
    finally { setBusy(false); }
  };
  return <section aria-label="Add a device">
    <h3>Add a device</h3>
    <p>Install the Karst client package on your Linux device first. This will connect it to <strong>{location.origin}</strong> as you.</p>
    <p>The bundle trusts this HTTPS deployment and includes its control-server pins. For independently provisioned pins, use your administrator’s bundle.</p>
    <label><input type="checkbox" checked={ready} onChange={(event) => setReady(event.target.checked)} /> I have installed the client and am ready to enroll.</label>
    <button disabled={!ready || busy} onClick={() => void create()}>{busy ? "Preparing…" : "Create enrollment bundle"}</button>
    {error && <p role="alert">{error}</p>}
    {download && <div role="status">
      <p><a download="karst-enrollment.toml" href={download.url}>Download enrollment bundle</a>. It can enroll one device before {new Date(download.expires).toLocaleString()}.</p>
      <p>On the device, in the directory containing the download:</p>
      <pre>chmod 600 karst-enrollment.toml{"\n"}sudo karst enroll --bundle karst-enrollment.toml{"\n"}rm karst-enrollment.toml{"\n"}sudo systemctl enable --now karstd{"\n"}sudo karst status</pre>
      <p>Run each command after the previous one succeeds. Keep the bundle private and delete it after enrollment. If enrollment fails, retry with the same device state. Your administrator may still need to approve the device in Bedrock or grant network access.</p>
    </div>}
  </section>;
}
