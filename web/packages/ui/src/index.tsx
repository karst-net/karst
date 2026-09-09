// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useEffect, useId, useRef, type ReactNode } from "react";

export type StatusState = "healthy" | "warning" | "danger" | "unknown";

const statusText: Record<StatusState, string> = { healthy: "Healthy", warning: "Needs attention", danger: "Problem", unknown: "Unknown" };

export function Status({ state, label }: { state: StatusState; label?: string }) {
  return <span className={`status status-${state}`}><span aria-hidden="true" className="status-shape">{state === "healthy" ? "●" : state === "warning" ? "▲" : state === "danger" ? "■" : "?"}</span>{label ?? statusText[state]}</span>;
}

// Rolls a timestamp up to the coarsest useful unit — "6589 min ago" tells an
// admin nothing that "4d ago" doesn't say better — and handles a timestamp
// that hasn't happened yet (a setup key's `expires`, say) as "in N unit"
// rather than clamping it to "just now". Beyond a week neither direction of
// relative count is worth reading, so this falls back to a plain date; the
// exact instant is always one hover away via Observed's `title` tooltip.
function relativeLabel(date: Date, now = Date.now()): string {
  const diffMs = date.getTime() - now;
  const future = diffMs > 0;
  const seconds = Math.abs(diffMs) / 1000;
  if (seconds < 45) return "just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return future ? `in ${minutes} min` : `${minutes} min ago`;
  const hours = Math.round(seconds / 3600);
  if (hours < 24) return future ? `in ${hours} hr` : `${hours} hr ago`;
  const days = Math.round(seconds / 86_400);
  if (days < 7) return future ? `in ${days} d` : `${days} d ago`;
  const sameYear = date.getFullYear() === new Date(now).getFullYear();
  return date.toLocaleDateString([], sameYear ? { month: "short", day: "numeric" } : { year: "numeric", month: "short", day: "numeric" });
}

export function Observed({ at }: { at?: string | null }) {
  if (!at) return <span>Not observed</span>;
  const date = new Date(at);
  return <time dateTime={at} title={date.toLocaleString()}>{relativeLabel(date)}</time>;
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

export { Enrollment, type EnrollmentMetadata, type EnrollmentGrant } from "./enrollment";
