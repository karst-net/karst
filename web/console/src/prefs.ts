// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

/**
 * Console-local preferences. These are conveniences and setup progress, never
 * credentials: §4 keeps tokens out of localStorage deliberately, and a server
 * URL is not a secret. Every access is guarded because a private window, or a
 * browser set to block site data, throws on the accessor itself rather than
 * returning empty.
 */
export function readPref(key: string): string | undefined {
  try { return localStorage.getItem(`karst.${key}`) ?? undefined; } catch { return undefined; }
}

export function writePref(key: string, value: string): void {
  try { localStorage.setItem(`karst.${key}`, value); } catch { /* preferences are best-effort */ }
}

export type Theme = "system" | "light" | "dark";

export const isTheme = (value: unknown): value is Theme => value === "system" || value === "light" || value === "dark";

/**
 * Applies a theme by stamping the root element. "system" removes the attribute
 * so `prefers-color-scheme` decides; anything else wins over it in both
 * directions. The tokens define all three states, so this is the only place
 * that needs to know how the switch is spelled.
 */
export function applyTheme(theme: Theme, root: HTMLElement): void {
  if (theme === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", theme);
}

export function storedTheme(): Theme {
  const stored = readPref("theme");
  return isTheme(stored) ? stored : "system";
}
