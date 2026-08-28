// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useEffect, useState } from "react";
import { Observed, Status } from "@karst-net/ui";
import { api, ApiError } from "../api";
import { Failure, Notice, Rows, useResource } from "../common";

type Flow = { source: string; destination: string; protocol: string; ports: string };
type TestResults = Awaited<ReturnType<typeof api.testPolicy>>;

export function Access() {
  const resource = useResource(api.policy);
  const history = useResource(api.policyVersions);
  const [document, setDocument] = useState("");
  const [diagnostics, setDiagnostics] = useState<Array<{ severity: string; message: string; line: number; column: number }>>([]);
  const [preview, setPreview] = useState<{ added: Flow[]; removed: Flow[] }>();
  const [tests, setTests] = useState<TestResults>();
  const [notice, setNotice] = useState<string>();
  const [conflicted, setConflicted] = useState(false);
  useEffect(() => { if (resource.value) setDocument(resource.value.document); }, [resource.value]);

  if (resource.loading) return <p>Loading access controls…</p>;
  if (resource.error) return <Failure message={resource.error} retry={resource.reload} />;

  const validate = async () => {
    try { const result = await api.validate(document); setDiagnostics(result.diagnostics); setNotice(result.valid ? "Policy is valid." : "Fix the diagnostics before saving."); }
    catch (error) { setNotice((error as Error).message); }
  };
  // A 412 means another admin saved between load and save. Last-write-wins on a
  // network access policy is a security bug, so say so and reload the base.
  const save = async () => {
    try { await api.savePolicy(document, resource.value?.version ?? 0); setNotice("Policy saved."); setConflicted(false); resource.reload(); history.reload(); }
    catch (error) {
      if (error instanceof ApiError && error.status === 412) { setConflicted(true); setNotice("Policy was not saved because another administrator saved a newer version. Reload it, reapply your intended edits, then save again."); return; }
      setNotice(`Policy was not saved: ${(error as Error).message}`);
    }
  };
  const reloadCurrent = () => { setConflicted(false); resource.reload(); setNotice("Current policy reloaded. Reapply any intended edits before saving."); };
  const restore = async (version: number) => {
    if (!confirm(`Restore policy version ${version}? This creates a new current version.`)) return;
    try { await api.rollbackPolicy(version, resource.value?.version ?? 0); setNotice(`Policy version ${version} restored as a new version.`); setConflicted(false); resource.reload(); history.reload(); }
    catch (error) {
      if (error instanceof ApiError && error.status === 412) { setConflicted(true); setNotice("Policy was not restored because another administrator saved a newer version. Reload the current policy and try again."); return; }
      setNotice(`Policy was not restored: ${(error as Error).message}`);
    }
  };
  const viewVersion = async (version: number) => {
    try { const selected = await api.policyVersion(version); setDocument(selected.document); setNotice(`Viewing version ${version}. Save will create a new current version from these contents.`); }
    catch (error) { setNotice((error as Error).message); }
  };
  const test = async () => {
    try { const results = await api.testPolicy(document); setTests(results); setNotice(results.passed ? "All access tests passed." : "Access tests failed. The policy would not do what the tests say it should."); }
    catch (error) { setNotice((error as Error).message); }
  };

  return <section>
    <h2>Access controls</h2>
    <p className="lede">JSON policies are validated by the same server that applies them.</p>
    <label htmlFor="policy">Policy document</label>
    <textarea id="policy" spellCheck={false} value={document} onChange={(event) => setDocument(event.target.value)} aria-describedby="policy-help" />
    <p id="policy-help">Use strict JSON. Save uses the version currently loaded.</p>
    <div className="actions">
      <button onClick={() => void validate()}>Validate policy</button>
      <button onClick={() => void api.preview(document).then(setPreview).catch((e: Error) => setNotice(e.message))}>Preview changes</button>
      <button onClick={() => void test()}>Test policy</button>
      <button className="primary" onClick={() => void save()}>Save policy</button>
    </div>
    <Notice message={notice} />
    {conflicted && <section aria-label="Policy conflict">
      <h3>Policy changed elsewhere</h3>
      <p>Your edits remain in the editor. Reload the current policy, reapply the changes you still want, and save against its new version.</p>
      <button onClick={reloadCurrent}>Reload current policy</button>
    </section>}
    {diagnostics.length > 0 && <section aria-label="Policy diagnostics">
      <h3>Diagnostics</h3>
      <ul>{diagnostics.map((d, index) => <li key={index}><strong>{d.severity}</strong> at line {d.line}, column {d.column}: {d.message}</li>)}</ul>
    </section>}
    {tests && <section aria-label="Policy tests">
      <h3>Access tests</h3>
      <ul>{tests.results.map((result, index) => <li key={index}><Status state={result.passed ? "healthy" : "danger"} label={result.name} /> — {result.message}</li>)}</ul>
    </section>}
    {preview && <section><h3>Preview</h3><div className="two-col"><FlowList title="Added" rows={preview.added} /><FlowList title="Removed" rows={preview.removed} /></div></section>}
    <section aria-label="Policy version history">
      <h3>Version history</h3>
      {history.loading ? <p>Loading policy history…</p> : history.error ? <Failure message={history.error} retry={history.reload} />
        : <Rows head={<><th>Version</th><th>Author</th><th>Created</th><th>Actions</th></>}>
          {history.value?.items.map((version) => <tr key={version.version}>
            <td>{version.version}{version.version === resource.value?.version ? " (current)" : ""}</td>
            <td>{version.author}</td>
            <td><Observed at={version.created_at} /></td>
            <td><div className="actions">
              <button onClick={() => void viewVersion(version.version)}>View</button>
              {version.version !== resource.value?.version && <button onClick={() => void restore(version.version)}>Restore</button>}
            </div></td>
          </tr>)}
        </Rows>}
    </section>
  </section>;
}

function FlowList({ title, rows }: { title: string; rows: Flow[] }) {
  return <div><h4>{title}</h4>{rows.length === 0 ? <p>None</p> : <ul>{rows.map((row, index) => <li key={index}><code>{row.source}</code> → <code>{row.destination}:{row.ports}</code> ({row.protocol})</li>)}</ul>}</div>;
}
