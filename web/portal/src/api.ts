// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

export type Device = { handle: string; name: string; platform: string; last_seen_at: string | null };
export type Access = { destination: string; rule: number; group: string; changed_at: string; changed_by: string };
export type Session = { started_at: string; ended_at: string | null; device: string; ip: string };
// arch and format are what make a Linux row actionable: packages ship as .deb
// and .rpm for amd64 and arm64, so "the Linux download" names four files and a
// page that picks one of them silently is wrong for three users in four.
export type ReleaseAsset = { platform: "windows" | "macos" | "linux"; arch: string; format: string; name: string; url: string; sha256: string };
const base = "/api/karst/v1/me";
async function request<T>(path: string, init?: RequestInit): Promise<T> { const response = await fetch(base + path, { ...init, headers: { "content-type": "application/json", ...init?.headers } }); if (!response.ok) throw new Error((await response.json().catch(() => ({ message: response.statusText }))).message ?? "Request failed"); return response.status === 204 ? undefined as T : response.json(); }
async function releases(): Promise<ReleaseAsset[]> { const response = await fetch("/releases/manifest.json"); if (!response.ok) throw new Error("Release manifest is unavailable."); const manifest = await response.json() as { assets?: ReleaseAsset[] }; return manifest.assets ?? []; }
export const api = { devices: () => request<Device[]>("/devices"), rename: (handle: string, name: string) => request<Device>(`/devices/${encodeURIComponent(handle)}`, { method: "PATCH", body: JSON.stringify({ name }) }), revoke: (handle: string) => request<void>(`/devices/${encodeURIComponent(handle)}`, { method: "DELETE" }), enroll: () => request<{ key: string; expires_at: string }>("/devices/enroll", { method: "POST" }), access: () => request<Access[]>("/access"), sessions: () => request<Session[]>("/sessions"), releases };
