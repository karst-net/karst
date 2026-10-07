// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// The NOC view, Phase 1a (#241, ADR-0046 ADR-0047): a map of every relay
// with a declared location, colored by health, plus a drill-down dialog.
// History, current rate and utilization are Phase 1b (ADR-0047 §1/§3/§4) --
// this page shows only what ADR-0021's existing telemetry already carries,
// drawn on a map instead of the Relays page's table.
import { useEffect, useRef, useState } from "react";
import { LngLatBounds, Map as MapLibreMap, type GeoJSONSource, type MapGeoJSONFeature, type MapLayerMouseEvent } from "maplibre-gl";
import "maplibre-gl/dist/maplibre-gl.css";
import type { Relay } from "@karst-net/api-client";
import { Dialog, Observed, Status, type StatusState } from "@karst-net/ui";
import { api } from "../api";
import { Failure, formatBytes, usePolledResource } from "../common";

// Matches the Relays page's own mapping (views/relays.tsx) -- the NOC view
// shows the same health ADR-0021 already derives, not a second opinion on it.
const healthState = (relay: Relay): StatusState =>
  relay.health.admission_state === "confirmed" ? "healthy" : relay.health.admission_state === "stale" ? "warning" : "unknown";

// ADR-0047 §3: polling, not push, for Phase 1a. 30s matches Prometheus's own
// typical scrape cadence, named there as the reference point.
const pollIntervalMs = 30_000;

// A hand-authored, deliberately coarse set of continent silhouettes -- not a
// geographic dataset, and not meant to be read as one. ADR-0047 §5 requires
// the basemap to be bundled with zero runtime network dependency; a properly
// licensed, higher-fidelity dataset is a follow-up (see docs/admin-console.md),
// not something to fetch from a third party without knowing its license.
const worldOutlineURL = "/noc-world-outline.geojson";

// Resolved once at map construction, matching policy-editor.tsx's own reason
// for doing this: a WebGL paint property takes a literal color, not CSS
// var(...), so the design tokens have to be read out of computed style here
// rather than written as a hex literal (which the project's own eslint rule
// would reject anyway).
function token(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function relayFeature(relay: Relay) {
  return {
    type: "Feature" as const,
    properties: { id: relay.id, health: healthState(relay), label: relay.location?.label || relay.region },
    geometry: { type: "Point" as const, coordinates: [relay.location!.lon, relay.location!.lat] },
  };
}

export function Noc() {
  const resource = usePolledResource(api.nocComponents, pollIntervalMs);
  const container = useRef<HTMLDivElement>(null);
  const map = useRef<MapLibreMap>(undefined);
  const mapReady = useRef(false);
  // A fixed default center/zoom is as likely to show an empty ocean as any
  // relay -- a fleet concentrated in one region (or, worse, split across
  // two) can sit entirely outside an arbitrary initial viewport. Fit once,
  // to whatever the first poll actually contains, then leave the operator's
  // own pan/zoom alone on every poll after that.
  const didInitialFit = useRef(false);
  const [selected, setSelected] = useState<{ id: string; value?: Relay; error?: string }>();

  // Mount-once: construct the map and its static layers. Relay data is
  // pushed in via the effect below, the same construct-once/update-via-ref
  // split policy-editor.tsx uses for CodeMirror.
  useEffect(() => {
    if (!container.current) return;
    const instance = new MapLibreMap({
      container: container.current,
      style: {
        version: 8,
        sources: {},
        layers: [{ id: "background", type: "background", paint: { "background-color": token("--surface") } }],
      },
      center: [10, 25],
      zoom: 1.2,
      attributionControl: false,
    });
    map.current = instance;
    instance.on("load", () => {
      instance.addSource("world", { type: "geojson", data: worldOutlineURL });
      instance.addLayer({ id: "world-fill", type: "fill", source: "world", paint: { "fill-color": token("--surface-raised"), "fill-outline-color": token("--border") } });
      instance.addSource("relays", { type: "geojson", data: { type: "FeatureCollection", features: [] }, cluster: true, clusterRadius: 40 });
      instance.addLayer({
        id: "relay-clusters", type: "circle", source: "relays", filter: ["has", "point_count"],
        paint: { "circle-color": token("--accent"), "circle-radius": ["step", ["get", "point_count"], 14, 10, 18, 50, 24] },
      });
      instance.addLayer({
        id: "relay-cluster-count", type: "symbol", source: "relays", filter: ["has", "point_count"],
        layout: { "text-field": "{point_count_abbreviated}", "text-size": 12 },
        paint: { "text-color": token("--accent-text") },
      });
      instance.addLayer({
        id: "relay-points", type: "circle", source: "relays", filter: ["!", ["has", "point_count"]],
        paint: {
          "circle-radius": 7,
          "circle-stroke-width": 1,
          "circle-stroke-color": token("--surface"),
          "circle-color": ["match", ["get", "health"], "healthy", token("--success"), "warning", token("--warning"), token("--muted")],
        },
      });
      instance.on("mouseenter", "relay-points", () => { instance.getCanvas().style.cursor = "pointer"; });
      instance.on("mouseleave", "relay-points", () => { instance.getCanvas().style.cursor = ""; });
      instance.on("mouseenter", "relay-clusters", () => { instance.getCanvas().style.cursor = "pointer"; });
      instance.on("mouseleave", "relay-clusters", () => { instance.getCanvas().style.cursor = ""; });
      instance.on("click", "relay-points", (event: MapLayerMouseEvent) => {
        const id = event.features?.[0]?.properties?.id as string | undefined;
        if (id) setSelected({ id });
      });
      instance.on("click", "relay-clusters", (event: MapLayerMouseEvent) => {
        const feature: MapGeoJSONFeature | undefined = event.features?.[0];
        const clusterId = feature?.properties?.cluster_id as number | undefined;
        const source = instance.getSource("relays") as GeoJSONSource | undefined;
        if (clusterId === undefined || !source || feature?.geometry.type !== "Point") return;
        source.getClusterExpansionZoom(clusterId).then((zoom) => {
          instance.easeTo({ center: feature.geometry.type === "Point" ? (feature.geometry.coordinates as [number, number]) : undefined, zoom });
        }).catch(() => { /* best-effort zoom; a failed expansion just leaves the view as it was */ });
      });
      mapReady.current = true;
    });
    return () => { mapReady.current = false; instance.remove(); map.current = undefined; };
  }, []);

  const relays = resource.value ?? [];
  const placed = relays.filter((relay) => relay.location);
  const unplaced = relays.filter((relay) => !relay.location);

  // Pushes the latest poll into the already-constructed map. Guarded on
  // mapReady because the "load" event (and so the "relays" source) may not
  // exist yet the first time data arrives -- the two are racing, not
  // sequenced, since one is a network fetch and the other is WebGL init.
  useEffect(() => {
    if (!mapReady.current || !map.current) return;
    const source = map.current.getSource("relays") as GeoJSONSource | undefined;
    source?.setData({ type: "FeatureCollection", features: placed.map(relayFeature) });
    if (!didInitialFit.current && placed.length > 0) {
      didInitialFit.current = true;
      const bounds = placed.reduce(
        (acc, relay) => acc.extend([relay.location!.lon, relay.location!.lat]),
        new LngLatBounds(),
      );
      map.current.fitBounds(bounds, { padding: 48, maxZoom: 6, duration: 0 });
    }
  }, [resource.value]);

  useEffect(() => {
    if (!selected) return;
    let active = true;
    api.nocRelay(selected.id).then((value) => { if (active) setSelected({ id: selected.id, value }); })
      .catch((error: Error) => { if (active) setSelected({ id: selected.id, error: error.message }); });
    return () => { active = false; };
  }, [selected?.id]);

  return <section>
    <h2>NOC view</h2>
    <p className="lede">Every relay with a declared location, colored by health. A relay with no declared location is listed separately, never guessed onto the map. History, current rate and utilization against capacity are not shown yet -- see docs/admin-console.md.</p>
    {resource.error && <Failure message={resource.error} retry={resource.reload} />}
    <div className="two-col">
      <div ref={container} className="noc-map" role="application" aria-label="Relay map" />
      <div>
        <h3>Relays with no declared location ({unplaced.length})</h3>
        {unplaced.length === 0
          ? <p className="lede">Every relay has a declared location.</p>
          : <div className="noc-unplaced"><ul>{unplaced.map((relay) => <li key={relay.id}>
            <code>{relay.address}</code> <Status state={healthState(relay)} label={relay.health.admission_state} />
          </li>)}</ul></div>}
      </div>
    </div>

    <Dialog open={Boolean(selected)} title={`Relay — ${selected?.value?.location?.label || selected?.value?.region || selected?.id || ""}`} onClose={() => setSelected(undefined)}>
      {selected?.error ? <p role="alert">{selected.error}</p> : !selected?.value ? <p>Loading…</p> : <>
        <p><code>{selected.value.address}</code></p>
        <p>Region: {selected.value.region}</p>
        <p>Health: <Status state={healthState(selected.value)} label={selected.value.health.admission_state} /></p>
        <p>Sessions: {selected.value.health.sessions ?? "—"}</p>
        <p>Bytes (cumulative): {selected.value.health.bytes != null ? formatBytes(selected.value.health.bytes) : "—"}</p>
        <p>Last confirmed: <Observed at={selected.value.health.last_confirmed_at} /></p>
      </>}
      <div className="actions"><button onClick={() => setSelected(undefined)}>Close</button></div>
    </Dialog>
  </section>;
}
