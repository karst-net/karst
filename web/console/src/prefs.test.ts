// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { afterEach, expect, test } from "vitest";
import { applyTheme, isTheme, readPref, storedTheme, writePref } from "./prefs";

type FakeRoot = HTMLElement & { attributes: Map<string, string> };

function root(): FakeRoot {
  const attributes = new Map<string, string>();
  return { attributes, setAttribute: (k: string, v: string) => attributes.set(k, v), removeAttribute: (k: string) => attributes.delete(k) } as unknown as FakeRoot;
}

/** The suite runs in the node environment, so storage is whatever we install. */
function installStorage(behavior: "working" | "throws") {
  const store = new Map<string, string>();
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: behavior === "throws"
      ? { getItem() { throw new Error("blocked"); }, setItem() { throw new Error("blocked"); } }
      : { getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => void store.set(k, v) },
  });
}

afterEach(() => { Reflect.deleteProperty(globalThis, "localStorage"); });

test("an explicit theme is stamped and system clears the attribute", () => {
  const element = root();
  applyTheme("dark", element);
  expect(element.attributes.get("data-theme")).toBe("dark");
  applyTheme("light", element);
  expect(element.attributes.get("data-theme")).toBe("light");
  // Removing it, rather than stamping "system", is what hands the decision back
  // to prefers-color-scheme.
  applyTheme("system", element);
  expect(element.attributes.has("data-theme")).toBe(false);
});

test("an unrecognized stored theme falls back to system rather than stamping it", () => {
  installStorage("working");
  writePref("theme", "chartreuse");
  expect(isTheme("chartreuse")).toBe(false);
  expect(storedTheme()).toBe("system");
  writePref("theme", "dark");
  expect(storedTheme()).toBe("dark");
});

test("setup progress round-trips", () => {
  installStorage("working");
  writePref("setup.serverUrl", "https://control.example.test");
  expect(readPref("setup.serverUrl")).toBe("https://control.example.test");
  expect(readPref("setup.missing")).toBeUndefined();
});

test("preferences survive a browser that throws on the accessor", () => {
  // A private window, or a browser set to block site data, throws on access
  // rather than returning empty — which would take the whole view down with it.
  installStorage("throws");
  expect(readPref("setup.serverUrl")).toBeUndefined();
  expect(storedTheme()).toBe("system");
  expect(() => writePref("setup.done", "2")).not.toThrow();
});
