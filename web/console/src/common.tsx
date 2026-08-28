// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { useEffect, useState, type ReactNode } from "react";
import type { Node } from "@karst-net/api-client";

export const statusFor = (posture: Node["posture"]["status"]) => posture === "pq" ? "healthy" : posture === "lattice_only" ? "warning" : posture === "stale" ? "danger" : "unknown";

export function useResource<T>(load: () => Promise<T>, dependencies: unknown[] = []) {
  const [value, setValue] = useState<T>(); const [error, setError] = useState<string>(); const [loading, setLoading] = useState(true);
  const reload = () => { setLoading(true); setError(undefined); load().then(setValue).catch((e: Error) => setError(e.message)).finally(() => setLoading(false)); };
  useEffect(reload, dependencies);
  return { value, error, loading, reload };
}

/** Every mutating view needs the same three things: run it, say what happened,
 *  reload. Written once so that a view cannot quietly forget the third — a
 *  table that still shows the row you just deleted is worse than an error. */
export function useMutation(reload: () => void) {
  const [message, setMessage] = useState<string>();
  const run = async (action: () => Promise<unknown>, success: string) => {
    try { await action(); setMessage(success); reload(); return true; }
    catch (error) { setMessage((error as Error).message); return false; }
  };
  return { message, setMessage, run };
}

/** One status region per view. Two would break `getByRole("status")` for a
 *  screen reader user as surely as for a test. */
export function Notice({ message }: { message?: string }) { return message ? <p role="status">{message}</p> : null; }

export function Failure({ message, retry }: { message: string; retry: () => void }) {
  return <section role="alert"><h2>Could not load this view</h2><p>{message}</p><button onClick={retry}>Try again</button></section>;
}

export function Planned({ title }: { title: string }) {
  return <section><h2>{title}</h2><EmptyPlaceholder /></section>;
}

function EmptyPlaceholder() {
  return <section className="empty-state"><h2>Not yet exposed by the control plane</h2><p>This view is ready for its API. The current Karst contract does not expose the required resource yet.</p></section>;
}

/** Comma-separated identifiers, in and out. Groups are ids rather than names in
 *  every one of these payloads, so the field says so rather than letting an
 *  admin type a display name that silently matches nothing. */
export const idList = (value: string) => value.split(",").map((item) => item.trim()).filter(Boolean);

export function Rows({ head, children }: { head: ReactNode; children: ReactNode }) {
  return <div className="table-wrap"><table><thead><tr>{head}</tr></thead><tbody>{children}</tbody></table></div>;
}
