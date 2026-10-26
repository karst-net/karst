// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import installer from "./installation/relay-install.py?raw";
import type { RelayLocation } from "@karst-net/api-client";

export type InstallationSettings = { schema_version: 1; address: string; tls_server_name: string; region: string; image: string; control_image: string; location: RelayLocation | null };
export type InstallationReceipt = { schema_version: 1; kind: "karst-relay-installation"; relay_id: string; entry: { address: string; tls_server_name: string; identity_key: string; region: string; location?: RelayLocation } };

export function validateInstallationSettings(settings: InstallationSettings) {
  const match = settings.address.match(/^(\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-fA-F:]+\]):(\d{1,5})$/);
  if (!match || Number(match[2]) < 1 || Number(match[2]) > 65535 || (!match[1].startsWith("[") && match[1].split(".").some(octet => Number(octet) > 255 || (octet.length > 1 && octet.startsWith("0"))))) throw new Error("Use a valid IP address and a port between 1 and 65535.");
  try { new URL(`https://${settings.address}`); } catch { throw new Error("Use a valid IP address and port."); }
  if (settings.tls_server_name.length > 253 || !settings.tls_server_name.split(".").every(label => /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(label))) throw new Error("Use a valid TLS DNS server name.");
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/.test(settings.region)) throw new Error("Use a valid region name.");
  if (!/^ghcr\.io\/karst-net\/karst-relay(?::[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}|@sha256:[a-f0-9]{64})$/.test(settings.image)) throw new Error("Use a Karst relay image tag or sha256 digest.");
  if (!/^ghcr\.io\/karst-net\/karst-control(?::[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}|@sha256:[a-f0-9]{64})$/.test(settings.control_image)) throw new Error("Use a Karst control image tag or sha256 digest.");
}

export function installationScript(settings: InstallationSettings) {
  validateInstallationSettings(settings);
  const bytes = new TextEncoder().encode(JSON.stringify(settings));
  const hex = Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
  return installer.replace("SETTINGS = None", `SETTINGS = json.loads(bytes.fromhex("${hex}").decode("utf-8"))`);
}

// Receipts are untrusted public metadata, never credentials or commands. Build
// the API entry explicitly: unknown file fields cannot become request fields.
export function parseInstallationReceipt(source: string): InstallationReceipt {
  const value = JSON.parse(source);
  if (value?.schema_version !== 1 || value?.kind !== "karst-relay-installation" || !/^[a-f0-9]{64}$/.test(value.relay_id) || !value.entry) throw new Error("Choose a relay installation receipt generated on the control host.");
  const { address, tls_server_name, identity_key, region, location } = value.entry;
  if (![address, tls_server_name, identity_key, region].every(field => typeof field === "string" && field.length > 0) || !/^[A-Za-z0-9+/]{3456}$/.test(identity_key)) throw new Error("The receipt is missing valid relay identity or endpoint fields.");
  if (location != null && (typeof location !== "object" || !Number.isFinite(location.lat) || !Number.isFinite(location.lon) || location.lat < -90 || location.lat > 90 || location.lon < -180 || location.lon > 180 || (location.label !== undefined && typeof location.label !== "string"))) throw new Error("The receipt has an invalid declared location.");
  return { schema_version: 1, kind: "karst-relay-installation", relay_id: value.relay_id, entry: { address, tls_server_name, identity_key, region, ...(location ? { location: { lat: location.lat, lon: location.lon, ...(location.label ? { label: location.label } : {}) } } : {}) } };
}

export function downloadInstaller(settings: InstallationSettings) {
  const url = URL.createObjectURL(new Blob([installationScript(settings)], { type: "text/x-python;charset=utf-8" }));
  const link = document.createElement("a");
  link.href = url; link.download = "karst-relay-install.py"; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
