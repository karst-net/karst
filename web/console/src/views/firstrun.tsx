// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useState } from "react";
import { api } from "../api";
import { Failure } from "../common";
import { RootRenameDialog } from "./domains";

type Step = "domain" | "groups";

/** The console's actual first-run onboarding gate -- not to be confused
 *  with the "Add device" nav item (the old "setup" route), which is the
 *  device-enrollment/invite flow and has nothing to do with account
 *  onboarding. main.tsx renders only this component, with no sidebar at
 *  all, until GET /firstrun reports completed=true. */
export function FirstRunWizard({ onComplete }: { onComplete: () => void }) {
  const [step, setStep] = useState<Step>("domain");
  const [renaming, setRenaming] = useState(false);
  const [domainSet, setDomainSet] = useState(false);
  const [finishing, setFinishing] = useState(false);
  const [finishError, setFinishError] = useState<string>();

  const finish = async () => {
    setFinishing(true); setFinishError(undefined);
    try { await api.completeFirstRun(); onComplete(); }
    catch (e) { setFinishError(e instanceof Error ? e.message : "Could not complete first-run setup."); }
    finally { setFinishing(false); }
  };

  return <div className="shell">
    <main>
      <h1>Welcome to Karst</h1>
      <p className="lede">Before anything else, let's set this account's default domain and a few starting groups. Both can be changed later from Domains and Groups — this is just enough to get a usable account.</p>

      <ol className="steps">
        <li aria-current={step === "domain" ? "step" : undefined}>
          <h2>1. Default domain</h2>
          <p className="lede">Devices are addressed under this account's root domain, e.g. <code>device.yourcompany.example</code>. You can rename it later, but every device's name changes when you do.</p>
          {step === "domain" && (domainSet
            ? <>
              <p role="status">Default domain set.</p>
              <div className="actions"><button className="primary" onClick={() => setStep("groups")}>Continue</button></div>
            </>
            : <div className="actions">
              <button className="primary" onClick={() => setRenaming(true)}>Set default domain</button>
              <button onClick={() => setStep("groups")}>Skip for now</button>
            </div>)}
          {step === "groups" && domainSet && <p role="status">Default domain set.</p>}
        </li>

        {step === "groups" && <li aria-current="step">
          <h2>2. Initial groups</h2>
          <p className="lede">Groups are how access policy, routes, and DNS settings target a set of devices or users. Create a few to start with — "Admins" and "Engineering" are common choices, but name them however your organization thinks about itself.</p>
          <InitialGroups />
          <div className="actions">
            <button className="primary" onClick={() => void finish()} disabled={finishing}>{finishing ? "Finishing…" : "Finish setup"}</button>
          </div>
          {finishError && <Failure message={finishError} retry={() => void finish()} />}
        </li>}
      </ol>

      {renaming && <RootRenameDialog initialSuffix="" onClose={() => setRenaming(false)} onCommitted={() => { setDomainSet(true); setRenaming(false); }} />}
    </main>
  </div>;
}

/** A short editable list of group names, each created with [api.createGroup]
 *  on submit. Deliberately not a table/CRUD view like groups.tsx's own --
 *  this is a one-shot batch add for onboarding, not ongoing management.
 *  "Finish setup" above does not wait on this: creating initial groups is
 *  a convenience, not a precondition, so an admin can leave this empty and
 *  finish anyway. */
function InitialGroups() {
  const [names, setNames] = useState<string[]>(["Admins", "Engineering"]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [created, setCreated] = useState<string[]>();

  const setName = (index: number, value: string) => setNames((current) => current.map((n, i) => i === index ? value : n));
  const addRow = () => setNames((current) => [...current, ""]);
  const removeRow = (index: number) => setNames((current) => current.filter((_, i) => i !== index));

  const createAll = async () => {
    const wanted = names.map((n) => n.trim()).filter(Boolean);
    if (wanted.length === 0) { setCreated([]); return; }
    setBusy(true); setError(undefined);
    const ok: string[] = [];
    for (const name of wanted) {
      try { await api.createGroup(name); ok.push(name); }
      catch (e) { setError(`Could not create "${name}": ${e instanceof Error ? e.message : "unknown error"}`); break; }
    }
    setCreated(ok);
    setBusy(false);
  };

  if (created) return <p role="status">{created.length > 0 ? `Created: ${created.join(", ")}.` : "No groups created."}</p>;

  return <div>
    {names.map((name, index) => <div className="actions" key={index}>
      <input aria-label={`Group name ${index + 1}`} value={name} disabled={busy} onChange={(event) => setName(index, event.target.value)} placeholder="group name" />
      <button type="button" disabled={busy} onClick={() => removeRow(index)}>Remove</button>
    </div>)}
    <div className="actions">
      <button type="button" disabled={busy} onClick={addRow}>Add another group</button>
      <button className="primary" disabled={busy} onClick={() => void createAll()}>Create groups</button>
      <button disabled={busy} onClick={() => setCreated([])}>Skip for now</button>
    </div>
    {error && <Failure message={error} retry={() => void createAll()} />}
  </div>;
}
