// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { describe, expect, it } from "vitest";
import { installationScript, parseInstallationReceipt, type InstallationSettings } from "./relay-installation";

const settings: InstallationSettings = { schema_version: 1, address: "203.0.113.7:443", tls_server_name: "relay.example.com", region: "denver", image: "ghcr.io/karst-net/karst-relay:dev", control_image: "ghcr.io/karst-net/karst-control:dev", location: null };
const receipt = { schema_version: 1, kind: "karst-relay-installation", relay_id: "ab".repeat(32), entry: { address: settings.address, tls_server_name: settings.tls_server_name, identity_key: "A".repeat(3456), region: settings.region } };

describe("relay installation handoff", () => {
  it("embeds public settings as UTF-8 data, never Python source", () => {
    const script = installationScript({ ...settings, location: { lat: 1, lon: 2, label: '\"; print(\"injected\") # 🏔' } });
    expect(script).not.toContain("SETTINGS = None");
    expect(script).not.toContain('print("injected")');
    const encoded = script.match(/bytes.fromhex\("([a-f0-9]+)"\)/)![1];
    const decoded = JSON.parse(new TextDecoder().decode(Uint8Array.from(encoded.match(/../g)!.map(byte => parseInt(byte, 16)))));
    expect(decoded.location.label).toContain("🏔");
    expect(decoded.address).toBe(settings.address);
    expect(script).toContain('"KARST_RELAY_REQUIRE_MANAGED": "true"');
  });
  it("imports only public registration fields", () => {
    expect(parseInstallationReceipt(JSON.stringify({ ...receipt, credential: "ignored", entry: { ...receipt.entry, token: "ignored" } }))).toEqual(receipt);
  });
  it("rejects unrelated, malformed or oversized identity data", () => {
    for (const value of [{}, { ...receipt, schema_version: 2 }, { ...receipt, relay_id: "bad" }, { ...receipt, entry: { ...receipt.entry, identity_key: "short" } }, { ...receipt, entry: { ...receipt.entry, location: { lat: 91, lon: 0 } } }]) {
      expect(() => parseInstallationReceipt(JSON.stringify(value))).toThrow();
    }
  });
});
