// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useEffect, useId, useRef, type ReactNode } from "react";

export type StatusState = "healthy" | "warning" | "danger" | "unknown";

const statusText: Record<StatusState, string> = { healthy: "Healthy", warning: "Needs attention", danger: "Problem", unknown: "Unknown" };

export function Status({ state, label }: { state: StatusState; label?: string }) {
  return <span className={`status status-${state}`}><span aria-hidden="true" className="status-shape">{state === "healthy" ? "●" : state === "warning" ? "▲" : state === "danger" ? "■" : "?"}</span>{label ?? statusText[state]}</span>;
}

export function Observed({ at }: { at?: string | null }) {
  if (!at) return <span>Not observed</span>;
  const date = new Date(at);
  const minutes = Math.max(0, Math.floor((Date.now() - date.getTime()) / 60_000));
  const age = minutes < 1 ? "just now" : minutes === 1 ? "1 min ago" : `${minutes} min ago`;
  return <time dateTime={at} title={date.toLocaleString()}>{date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })} ({age})</time>;
}

export function EmptyState({ title, children }: { title: string; children: ReactNode }) {
  return <section className="empty-state"><h2>{title}</h2><p>{children}</p></section>;
}

/** A modal built on the platform's `<dialog>`, not on a div with a z-index.
 *
 *  `showModal()` is what makes it a modal in the accessibility tree as well as
 *  on screen: it moves focus inside, traps it there, marks everything behind it
 *  inert, and closes on Escape. A hand-rolled overlay has to reimplement all
 *  four and usually reimplements two, which is how a create form becomes
 *  unreachable by keyboard while looking correct in a screenshot. */
export function Dialog({ open, title, onClose, children }: { open: boolean; title: string; onClose: () => void; children: ReactNode }) {
  const ref = useRef<HTMLDialogElement>(null);
  const heading = useId();
  useEffect(() => {
    const element = ref.current;
    if (!element) return;
    if (open && !element.open) element.showModal();
    else if (!open && element.open) element.close();
  }, [open]);
  // A closed <dialog> is display:none by every browser's default stylesheet, so
  // the form inside is out of the accessibility tree rather than merely
  // invisible — nothing here is scanned or tabbable until it is opened.
  return <dialog ref={ref} aria-labelledby={heading} onCancel={(event) => { event.preventDefault(); onClose(); }} onClose={onClose}>
    <h2 id={heading}>{title}</h2>
    {children}
  </dialog>;
}
