// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { afterEach, expect, test, vi } from "vitest";
import { recentKarstReleases } from "./karst-releases";

afterEach(() => { vi.unstubAllGlobals(); });

const release = (tag: string, publishedAt: string, draft = false) => ({ tag_name: tag, draft, published_at: publishedAt });

test("returns tags newest first, regardless of the API's own order", () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
    ok: true,
    json: () => Promise.resolve([release("v1.0.0", "2026-01-01T00:00:00Z"), release("v1.2.0", "2026-03-01T00:00:00Z")]),
  }));
  return recentKarstReleases().then(tags => expect(tags).toEqual(["v1.2.0", "v1.0.0"]));
});

test("drafts are excluded", () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
    ok: true,
    json: () => Promise.resolve([release("v1.2.0", "2026-03-01T00:00:00Z", true), release("v1.0.0", "2026-01-01T00:00:00Z")]),
  }));
  return recentKarstReleases().then(tags => expect(tags).toEqual(["v1.0.0"]));
});

test("a non-OK response raises rather than silently returning an empty list", () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 403, statusText: "rate limited" }));
  return expect(recentKarstReleases()).rejects.toThrow(/403/);
});
