// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useState } from "react";
import { Dialog, Observed } from "@karst-net/ui";
import type { ComplianceDraftWrite, ComplianceGuardrail, ComplianceRequirement, ComplianceResource } from "@karst-net/api-client";
import { api, ApiError } from "../api";
import { Failure, Notice, Rows, useResource } from "../common";

const emptyDraft: ComplianceDraftWrite = { requirement_sets: {}, guardrails: [], remediation: [] };

function describeRequirement(r: ComplianceRequirement): string {
  if (r.kind === "minimum-client-version") return `Karst client ≥ ${r.minimum_version}`;
  return `${r.platform ?? "?"}${r.distribution ? ` (${r.distribution})` : ""} ≥ ${r.minimum_version}`;
}

function describeResource(r: ComplianceResource): string {
  const ports = r.first === 0 && r.last === 65535 ? "all ports" : r.first === r.last ? `port ${r.first}` : `ports ${r.first}-${r.last}`;
  return `${r.selector} (${r.protocol === "*" ? "tcp/udp" : r.protocol}, ${ports})`;
}

function RequirementSetEditor({ onAdd }: { onAdd: (id: string, requirements: ComplianceRequirement[]) => void }) {
  const [id, setId] = useState("");
  const [requirements, setRequirements] = useState<ComplianceRequirement[]>([]);
  const [kind, setKind] = useState<ComplianceRequirement["kind"]>("minimum-client-version");
  const [minimumVersion, setMinimumVersion] = useState("");
  const [platform, setPlatform] = useState<NonNullable<ComplianceRequirement["platform"]>>("linux");
  const [distribution, setDistribution] = useState("ubuntu");
  const [reqId, setReqId] = useState("");
  return <fieldset>
    <legend>New requirement set</legend>
    <label>Set name<input required value={id} onChange={(event) => setId(event.target.value)} /></label>
    {requirements.length > 0 && <ul>{requirements.map((r) => <li key={r.id}>{describeRequirement(r)} <button type="button" onClick={() => setRequirements(requirements.filter((other) => other.id !== r.id))}>Remove</button></li>)}</ul>}
    <fieldset>
      <legend>Add a requirement to this set</legend>
      <label>Requirement ID<input value={reqId} onChange={(event) => setReqId(event.target.value)} /></label>
      <label>Kind<select aria-label="Requirement kind" value={kind} onChange={(event) => setKind(event.target.value as ComplianceRequirement["kind"])}><option value="minimum-client-version">Minimum Karst client version</option><option value="minimum-os-version">Minimum OS version</option></select></label>
      <label>Minimum version<input value={minimumVersion} onChange={(event) => setMinimumVersion(event.target.value)} /></label>
      {kind === "minimum-os-version" && <>
        <label>Platform<select aria-label="Platform" value={platform} onChange={(event) => setPlatform(event.target.value as typeof platform)}><option value="linux">Linux</option><option value="darwin">macOS</option><option value="windows">Windows</option></select></label>
        {platform === "linux" && <label>Distribution<select aria-label="Distribution" value={distribution} onChange={(event) => setDistribution(event.target.value)}><option value="ubuntu">Ubuntu</option><option value="debian">Debian</option></select></label>}
      </>}
      <button type="button" disabled={!reqId || !minimumVersion} onClick={() => {
        setRequirements([...requirements, kind === "minimum-client-version" ? { id: reqId, kind, minimum_version: minimumVersion, provenance: "self-reported" } as ComplianceRequirement : { id: reqId, kind, minimum_version: minimumVersion, platform, distribution: platform === "linux" ? distribution : undefined, provenance: "self-reported" } as ComplianceRequirement]);
        setReqId(""); setMinimumVersion("");
      }}>Add requirement</button>
    </fieldset>
    <button type="button" className="primary" disabled={!id || requirements.length === 0} onClick={() => { onAdd(id, requirements); setId(""); setRequirements([]); }}>Save requirement set</button>
  </fieldset>;
}

function GuardrailEditor({ requirementSetNames, onAdd }: { requirementSetNames: string[]; onAdd: (guardrail: ComplianceGuardrail) => void }) {
  const [id, setId] = useState("");
  const [selector, setSelector] = useState("");
  const [protocol, setProtocol] = useState<ComplianceResource["protocol"]>("*");
  const [portChoice, setPortChoice] = useState("all");
  const [customPorts, setCustomPorts] = useState("");
  const [sets, setSets] = useState<string[]>([]);
  const ports = portChoice === "all" ? { first: 0, last: 65535 } : portChoice === "ssh" ? { first: 22, last: 22 } : portChoice === "web" ? { first: 443, last: 443 } : (() => { const n = Number(customPorts); return { first: n, last: n }; })();
  return <fieldset>
    <legend>New guardrail</legend>
    <label>Guardrail ID<input required value={id} onChange={(event) => setId(event.target.value)} /></label>
    <label>Destination selector<input required placeholder="10.0.0.0/24, group:prod-db, or *" value={selector} onChange={(event) => setSelector(event.target.value)} /></label>
    <label>Protocol<select aria-label="Protocol" value={protocol} onChange={(event) => setProtocol(event.target.value as typeof protocol)}><option value="*">TCP/UDP</option><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
    <label>Ports<select aria-label="Ports" value={portChoice} onChange={(event) => setPortChoice(event.target.value)}><option value="all">All ports</option><option value="ssh">SSH (22)</option><option value="web">HTTPS (443)</option><option value="custom">Specific port</option></select></label>
    {portChoice === "custom" && <label>Port number<input required type="number" min={0} max={65535} value={customPorts} onChange={(event) => setCustomPorts(event.target.value)} /></label>}
    <fieldset><legend>Required of every matching source device</legend>
      {requirementSetNames.length === 0 && <p>Add a requirement set first.</p>}
      {requirementSetNames.map((name) => <label key={name}><input type="checkbox" checked={sets.includes(name)} onChange={(event) => setSets(event.target.checked ? [...sets, name] : sets.filter((n) => n !== name))} />{name}</label>)}
    </fieldset>
    <button type="button" className="primary" disabled={!id || !selector || sets.length === 0} onClick={() => { onAdd({ id, resource: { selector, protocol, first: ports.first, last: ports.last }, requirement_sets: sets }); setId(""); setSelector(""); setSets([]); }}>Save guardrail</button>
  </fieldset>;
}

function ResourceEditor({ onAdd }: { onAdd: (resource: ComplianceResource) => void }) {
  const [selector, setSelector] = useState("");
  const [protocol, setProtocol] = useState<ComplianceResource["protocol"]>("*");
  return <fieldset>
    <legend>New remediation resource</legend>
    <label>Selector<input required placeholder="help, or a CIDR" value={selector} onChange={(event) => setSelector(event.target.value)} /></label>
    <label>Protocol<select aria-label="Remediation protocol" value={protocol} onChange={(event) => setProtocol(event.target.value as typeof protocol)}><option value="*">TCP/UDP</option><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
    <button type="button" className="primary" disabled={!selector} onClick={() => { onAdd({ selector, protocol, first: 0, last: 65535 }); setSelector(""); }}>Save remediation resource</button>
  </fieldset>;
}

export function ComplianceGuardrails() {
  const resource = useResource(async () => {
    try { return await api.complianceDraft(); }
    catch (error) { if (error instanceof ApiError && error.status === 404) return { version: 0, requirement_sets: {}, guardrails: [], remediation: [], author: "", created_at: new Date(0).toISOString() }; throw error; }
  });
  const history = useResource(api.complianceDraftVersions);
  const [draft, setDraft] = useState<ComplianceDraftWrite>(emptyDraft);
  const [editing, setEditing] = useState<"requirementSet" | "guardrail" | "remediation">();
  const [notice, setNotice] = useState<string>();
  const [conflicted, setConflicted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [review, setReview] = useState<{ draft: ComplianceDraftWrite; preview: Awaited<ReturnType<typeof api.previewComplianceDraft>> }>();
  const [acknowledged, setAcknowledged] = useState(false);

  if (resource.value && draft === emptyDraft && resource.value.guardrails.length + Object.keys(resource.value.requirement_sets).length + resource.value.remediation.length > 0) {
    setDraft({ requirement_sets: resource.value.requirement_sets, guardrails: resource.value.guardrails, remediation: resource.value.remediation });
  }

  const review_ = async (candidate: ComplianceDraftWrite) => {
    setBusy(true); setNotice(undefined);
    try {
      const validation = await api.validateComplianceDraft(candidate);
      if (!validation.valid) throw new Error(validation.diagnostics.map((d) => d.message).join("; "));
      const result = await api.previewComplianceDraft(candidate);
      setReview({ draft: candidate, preview: result }); setAcknowledged(false);
    } catch (error) { setNotice((error as Error).message); }
    finally { setBusy(false); }
  };
  const save = async () => {
    if (!review) return;
    setBusy(true);
    try {
      await api.saveComplianceDraft(review.draft, resource.value?.version ?? 0);
      setReview(undefined); setNotice("Compliance guardrails saved."); resource.reload(); history.reload();
    } catch (error) {
      if (error instanceof ApiError && error.status === 412) { setConflicted(true); setReview(undefined); setNotice("Guardrails were not saved because another administrator changed them. Reload before reapplying your edits."); }
      else setNotice(`Guardrails were not saved: ${(error as Error).message}`);
    } finally { setBusy(false); }
  };
  const restore = async (version: number) => {
    setBusy(true);
    try { const old = await api.complianceDraftVersion(version); await review_({ requirement_sets: old.requirement_sets, guardrails: old.guardrails, remediation: old.remediation }); }
    catch (error) { setNotice((error as Error).message); }
    finally { setBusy(false); }
  };

  if (resource.loading) return <p>Loading compliance guardrails…</p>;
  if (resource.error) return <Failure message={resource.error} retry={resource.reload} />;
  const requirementSetNames = Object.keys(draft.requirement_sets);

  return <section>
    <h3>Compliance guardrails</h3>
    <p>A guardrail requires fresh passing device evidence for every matching device before it may reach a protected destination. Guardrails compose with AND, independently of identity access grants; they can only narrow access, never grant it.</p>
    <Notice message={notice} />
    {conflicted && <section aria-label="Draft conflict"><h4>Guardrails changed elsewhere</h4><button onClick={() => { resource.reload(); setConflicted(false); }}>Reload current guardrails</button></section>}

    <h4>Requirement sets</h4>
    {requirementSetNames.length === 0 ? <p>No requirement sets yet.</p> : <Rows head={<><th>Name</th><th>Requirements</th><th>Actions</th></>}>
      {requirementSetNames.map((name) => <tr key={name}><td>{name}</td><td>{draft.requirement_sets[name].map(describeRequirement).join("; ")}</td><td><button disabled={busy || conflicted} onClick={() => void review_({ ...draft, requirement_sets: Object.fromEntries(Object.entries(draft.requirement_sets).filter(([n]) => n !== name)), guardrails: draft.guardrails.filter((g) => !g.requirement_sets.includes(name)) })}>Remove {name}</button></td></tr>)}
    </Rows>}
    <button disabled={busy || conflicted} onClick={() => setEditing("requirementSet")}>Add requirement set</button>

    <h4>Guardrails</h4>
    {draft.guardrails.length === 0 ? <p>No guardrails yet. Every destination is unconstrained by compliance.</p> : <Rows head={<><th>ID</th><th>Destination</th><th>Requires</th><th>Actions</th></>}>
      {draft.guardrails.map((g) => <tr key={g.id}><td>{g.id}</td><td>{describeResource(g.resource)}</td><td>{g.requirement_sets.join(", ")}</td><td><button disabled={busy || conflicted} onClick={() => void review_({ ...draft, guardrails: draft.guardrails.filter((other) => other.id !== g.id) })}>Remove {g.id}</button></td></tr>)}
    </Rows>}
    <button disabled={busy || conflicted || requirementSetNames.length === 0} onClick={() => setEditing("guardrail")}>Add guardrail</button>

    <h4>Remediation resources</h4>
    <p>Destinations explicitly exempt from every guardrail — help/remediation access a noncompliant device keeps. Must not overlap a guardrail's own destination.</p>
    {draft.remediation.length === 0 ? <p>No remediation resources configured.</p> : <Rows head={<><th>Resource</th><th>Actions</th></>}>
      {draft.remediation.map((r, i) => <tr key={`${r.selector}-${i}`}><td>{describeResource(r)}</td><td><button disabled={busy || conflicted} onClick={() => void review_({ ...draft, remediation: draft.remediation.filter((_, index) => index !== i) })}>Remove</button></td></tr>)}
    </Rows>}
    <button disabled={busy || conflicted} onClick={() => setEditing("remediation")}>Add remediation resource</button>

    <div className="actions"><button className="primary" disabled={busy || conflicted} onClick={() => void review_(draft)}>Review guardrail changes</button></div>

    <section aria-label="Compliance guardrail history"><h3>Change history</h3>{history.error ? <Failure message={history.error} retry={history.reload} /> : <Rows head={<><th>Version</th><th>Author</th><th>Created</th><th>Actions</th></>}>{history.value?.items.map((version) => <tr key={version.version}><td>{version.version}</td><td>{version.author}</td><td><Observed at={version.created_at} /></td><td><button disabled={busy || conflicted} onClick={() => void restore(version.version)}>Review version {version.version}</button></td></tr>)}</Rows>}</section>

    {editing === "requirementSet" && <Dialog open title="Add requirement set" onClose={() => { if (!busy) setEditing(undefined); }}>
      <RequirementSetEditor onAdd={(id, requirements) => { setDraft({ ...draft, requirement_sets: { ...draft.requirement_sets, [id]: requirements } }); setEditing(undefined); }} />
    </Dialog>}
    {editing === "guardrail" && <Dialog open title="Add guardrail" onClose={() => { if (!busy) setEditing(undefined); }}>
      <GuardrailEditor requirementSetNames={requirementSetNames} onAdd={(guardrail) => { setDraft({ ...draft, guardrails: [...draft.guardrails, guardrail] }); setEditing(undefined); }} />
    </Dialog>}
    {editing === "remediation" && <Dialog open title="Add remediation resource" onClose={() => { if (!busy) setEditing(undefined); }}>
      <ResourceEditor onAdd={(resourceItem) => { setDraft({ ...draft, remediation: [...draft.remediation, resourceItem] }); setEditing(undefined); }} />
    </Dialog>}

    {review && <Dialog open title="Review guardrail changes" onClose={() => { if (!busy) setReview(undefined); }}>
      {review.preview.diagnostics.length > 0 && <ul>{review.preview.diagnostics.map((d, i) => <li key={i} role="alert">{d.message}</li>)}</ul>}
      <Rows head={<><th>Device</th><th>Ingress gates</th><th>Egress gates</th></>}>
        {review.preview.devices.map((device) => <tr key={device.handle}><td>{device.handle}</td><td>{device.ingress.length === 0 ? "None" : device.ingress.map((gate) => `${gate.guardrail_id}: ${gate.sources.length} passing device(s)`).join("; ")}</td><td>{device.egress.length === 0 ? "None" : device.egress.map((gate) => `${gate.guardrail_id}: ${gate.sources.length} passing device(s)`).join("; ")}</td></tr>)}
      </Rows>
      <label><input type="checkbox" checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)} />I reviewed the compiled guardrail changes for every device above.</label>
      <div className="actions"><button disabled={busy} onClick={() => setReview(undefined)}>Back</button><button className="primary" disabled={!acknowledged || busy || conflicted} onClick={() => void save()}>Apply guardrail changes</button></div>
    </Dialog>}
  </section>;
}
