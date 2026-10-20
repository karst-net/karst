// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// The NOC view, Phase 1a (#241, ADR-0046/ADR-0047), extended to ADR-0046
// §1's full component list plus the admin-authorized "possible locations"
// registry: a map of every relay, TURN server, exit-node/subnet-router
// gateway group, and the account's control-plane/Bedrock declared
// locations, each colored by health where it has one, plus every
// authorized-but-possibly-unoccupied location as a hollow marker. History,
// current rate and utilization are Phase 1b (ADR-0047 §1/§3/§4) -- this
// page shows only what ADR-0021's existing telemetry already carries, drawn
// on a map instead of a table.
import { useEffect, useRef, useState } from "react";
import { LngLatBounds, Map as MapLibreMap, setWorkerUrl, type GeoJSONSource, type MapGeoJSONFeature, type MapLayerMouseEvent } from "maplibre-gl";
import "maplibre-gl/dist/maplibre-gl.css";
import workerUrl from "maplibre-gl/dist/maplibre-gl-worker.mjs?url";
import type { Location as NocLocation, NocComponent, Relay } from "@karst-net/api-client";
import { Dialog, Observed, Status, type StatusState } from "@karst-net/ui";
import { api } from "../api";
import { Failure, formatBytes, useResource, usePolledResource } from "../common";
import { TutorialHint } from "../tutorial";

// maplibre-gl resolves its worker's own URL at runtime relative to wherever
// its *own* module ends up being served from -- but that resolution is a
// dynamic template, not a literal relative path, so Vite's static-asset
// analysis never sees it as a worker chunk to copy into the build. Left
// alone, the worker 404s in production ("Worker failed to load"), even
// though the map otherwise renders. The `?url` import above is a literal
// Vite CAN see, so it copies/hashes the file and gives us the real URL to
// hand to maplibre-gl's own override instead of letting it guess.
setWorkerUrl(workerUrl);

// ADR-0047 §3: polling, not push, for Phase 1a. 30s matches Prometheus's own
// typical scrape cadence, named there as the reference point.
const pollIntervalMs = 30_000;

// Bundled Natural Earth public-domain boundaries; see public/noc-boundaries.md.
const worldOutlineURL = "/noc-world-outline.geojson";
const provinceBordersURL = "/noc-state-province-borders.geojson";

// Resolved once at map construction, matching policy-editor.tsx's own reason
// for doing this: a WebGL paint property takes a literal color, not CSS
// var(...), so the design tokens have to be read out of computed style here
// rather than written as a hex literal (which the project's own eslint rule
// would reject anyway).
function token(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

// kindGlyph/kindLabel/kindChartToken are ADR-0046 §1's full component list,
// in the dataviz skill's own fixed categorical order (see tokens/theme.css's
// own --chart-1..--chart-5 comment for why the order and the past-three-slot
// tradeoff are deliberate). Shape is the primary way a marker's kind reads
// at a glance -- the same plain-text-glyph convention
// @karst-net/ui's own <Status> already uses for health (●/▲/■/?) -- and
// color is a secondary channel on top of it, never the only cue: every
// glyph here is also always paired with its color in the legend, which is
// what makes the chart-4/chart-5 slots' relaxed CVD floor acceptable for
// this use (see the token comment).
const kindGlyph: Record<string, string> = { relay: "●", turn: "◆", route: "▲", control_plane: "■", bedrock: "★" };
const kindLabel: Record<string, string> = { relay: "Relay", turn: "TURN server", route: "Exit/subnet gateway", control_plane: "Control plane", bedrock: "Bedrock" };
const kindChartToken: Record<string, string> = { relay: "--chart-1", turn: "--chart-2", route: "--chart-3", control_plane: "--chart-4", bedrock: "--chart-5" };
const kinds = Object.keys(kindGlyph);

const healthState = (health?: string): StatusState => health === "confirmed" ? "healthy" : health === "stale" ? "warning" : "unknown";

// Matches the Relays page's own mapping (views/relays.tsx) -- the drill-down
// dialog for a relay shows the same health ADR-0021 already derives, not a
// second opinion on it. Only relays carry this richer, telemetry-backed
// shape; every other kind's detail comes straight from the NocComponent
// already in hand.
const relayHealthState = (relay: Relay): StatusState =>
  relay.health.admission_state === "confirmed" ? "healthy" : relay.health.admission_state === "stale" ? "warning" : "unknown";

function componentFeature(component: NocComponent) {
  return {
    type: "Feature" as const,
    properties: { id: component.id, kind: component.kind, health: healthState(component.health), label: component.label },
    geometry: { type: "Point" as const, coordinates: [component.location!.lon, component.location!.lat] },
  };
}

function locationFeature(location: NocLocation) {
  return {
    type: "Feature" as const,
    properties: { id: location.id, label: location.label || "" },
    geometry: { type: "Point" as const, coordinates: [location.lon, location.lat] },
  };
}

export function Noc() {
  const resource = usePolledResource(api.nocComponents, pollIntervalMs);
  const locations = useResource(api.locations);
  const container = useRef<HTMLDivElement>(null);
  const map = useRef<MapLibreMap>(undefined);
  const mapReady = useRef(false);
  // A fixed default center/zoom is as likely to show an empty ocean as any
  // component -- a fleet concentrated in one region (or, worse, split
  // across two) can sit entirely outside an arbitrary initial viewport. Fit
  // once, to whatever the first poll actually contains, then leave the
  // operator's own pan/zoom alone on every poll after that.
  const didInitialFit = useRef(false);
  const [selected, setSelected] = useState<{ kind: string; id: string; component?: NocComponent; relay?: Relay; error?: string }>();

  // Mount-once: construct the map and its static layers. Component data is
  // pushed in via the effects below, the same construct-once/update-via-ref
  // split policy-editor.tsx uses for CodeMirror.
  useEffect(() => {
    if (!container.current) return;
    const instance = new MapLibreMap({
      container: container.current,
      style: {
        version: 8,
        projection: { type: "globe" },
        sources: {},
        layers: [{ id: "background", type: "background", paint: { "background-color": token("--surface") } }],
      },
      center: [10, 25],
      zoom: 1.2,
      attributionControl: false,
    });
    map.current = instance;
    // Layout changes can resize the map independently of a window resize
    // (for example, expanding the location list or the map description).
    const resizeObserver = new ResizeObserver(() => instance.resize());
    resizeObserver.observe(container.current);
    instance.on("load", () => {
      instance.addSource("world", { type: "geojson", data: worldOutlineURL });
      instance.addLayer({ id: "world-fill", type: "fill", source: "world", paint: { "fill-color": token("--surface-raised") } });
      instance.addSource("state-province-borders", { type: "geojson", data: provinceBordersURL });
      instance.addLayer({
        id: "state-province-borders", type: "line", source: "state-province-borders",
        paint: {
          "line-color": token("--muted"), "line-opacity": 0.65,
          "line-width": ["interpolate", ["linear"], ["zoom"], 0, 0.4, 5, 1],
          "line-dasharray": [3, 3],
        },
      });
      // Draw country outlines last so solid national borders remain dominant.
      instance.addLayer({
        id: "national-borders", type: "line", source: "world",
        paint: { "line-color": token("--muted"), "line-width": 1.2 },
      });

      // Relays: clustered, exactly as Phase 1a shipped it -- untouched
      // except for the added glyph layer, which carries this marker's kind
      // the same secondary-channel way every other kind below does.
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
      instance.addLayer({
        id: "relay-glyph", type: "symbol", source: "relays", filter: ["!", ["has", "point_count"]],
        layout: { "text-field": kindGlyph.relay, "text-size": 10, "text-allow-overlap": true },
        paint: { "text-color": token(kindChartToken.relay) },
      });

      // Every other component kind (ADR-0046 §1): one shared source, not
      // clustered -- turn/route/control_plane/bedrock are infrastructure,
      // never numerous enough in one deployment to need it the way a
      // client-peer-scale fleet of relays can be.
      instance.addSource("components", { type: "geojson", data: { type: "FeatureCollection", features: [] } });
      instance.addLayer({
        id: "component-points", type: "circle", source: "components",
        paint: {
          "circle-radius": 7,
          "circle-stroke-width": 2,
          "circle-stroke-color": ["match", ["get", "kind"], "turn", token(kindChartToken.turn), "route", token(kindChartToken.route), "control_plane", token(kindChartToken.control_plane), "bedrock", token(kindChartToken.bedrock), token("--border")],
          "circle-color": ["match", ["get", "health"], "healthy", token("--success"), "warning", token("--warning"), token("--muted")],
        },
      });
      instance.addLayer({
        id: "component-glyph", type: "symbol", source: "components",
        layout: {
          "text-field": ["match", ["get", "kind"], "turn", kindGlyph.turn, "route", kindGlyph.route, "control_plane", kindGlyph.control_plane, "bedrock", kindGlyph.bedrock, "?"],
          "text-size": 10, "text-allow-overlap": true,
        },
        paint: { "text-color": ["match", ["get", "kind"], "turn", token(kindChartToken.turn), "route", token(kindChartToken.route), "control_plane", token(kindChartToken.control_plane), "bedrock", token(kindChartToken.bedrock), token("--text")] },
      });

      // Authorized-but-possibly-unoccupied locations: always rendered,
      // independent of whether any component is actually there. Hollow
      // (fill matches the surface, only the stroke shows) and permanently
      // neutral -- this is a single category, not one of the five kinds
      // above, and nothing is deployed there to have a health.
      instance.addSource("locations", { type: "geojson", data: { type: "FeatureCollection", features: [] } });
      instance.addLayer({
        id: "location-points", type: "circle", source: "locations",
        paint: { "circle-radius": 6, "circle-color": token("--surface"), "circle-stroke-width": 2, "circle-stroke-color": token("--border") },
      });
      instance.addLayer({
        id: "location-glyph", type: "symbol", source: "locations",
        layout: { "text-field": "○", "text-size": 10, "text-allow-overlap": true },
        paint: { "text-color": token("--muted") },
      });

      for (const layer of ["relay-points", "relay-clusters", "component-points"]) {
        instance.on("mouseenter", layer, () => { instance.getCanvas().style.cursor = "pointer"; });
        instance.on("mouseleave", layer, () => { instance.getCanvas().style.cursor = ""; });
      }
      instance.on("click", "relay-points", (event: MapLayerMouseEvent) => {
        const id = event.features?.[0]?.properties?.id as string | undefined;
        if (id) setSelected({ kind: "relay", id });
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
      instance.on("click", "component-points", (event: MapLayerMouseEvent) => {
        const id = event.features?.[0]?.properties?.id as string | undefined;
        const kind = event.features?.[0]?.properties?.kind as string | undefined;
        if (id && kind) setSelected({ kind, id });
      });
      mapReady.current = true;
    });
    return () => { resizeObserver.disconnect(); mapReady.current = false; instance.remove(); map.current = undefined; };
  }, []);

  const components = resource.value ?? [];
  const placed = components.filter((component) => component.location);
  const unplaced = components.filter((component) => !component.location);
  const authorized = locations.value ?? [];

  // Fits the view once, to whatever the first poll of *either* resource
  // actually contains -- a fleet concentrated in one region, or a set of
  // authorized-but-unoccupied locations on another continent, can each sit
  // entirely outside an arbitrary initial viewport, and the two load
  // independently (one is a relay/component poll, the other an admin
  // registry fetch). Takes the current snapshot of both every time either
  // effect below calls it, so whichever loads first does not fit a bounds
  // that then ignores the other arriving later.
  function tryInitialFit() {
    if (didInitialFit.current || !map.current) return;
    if (placed.length === 0 && authorized.length === 0) return;
    didInitialFit.current = true;
    let bounds = placed.reduce((acc, component) => acc.extend([component.location!.lon, component.location!.lat]), new LngLatBounds());
    bounds = authorized.reduce((acc, location) => acc.extend([location.lon, location.lat]), bounds);
    map.current.fitBounds(bounds, { padding: 48, maxZoom: 6, duration: 0 });
  }

  // Pushes the latest poll into the already-constructed map. Guarded on
  // mapReady because the "load" event (and so every source below) may not
  // exist yet the first time data arrives -- the two are racing, not
  // sequenced, since one is a network fetch and the other is WebGL init.
  useEffect(() => {
    if (!mapReady.current || !map.current) return;
    const relaySource = map.current.getSource("relays") as GeoJSONSource | undefined;
    relaySource?.setData({ type: "FeatureCollection", features: placed.filter((c) => c.kind === "relay").map(componentFeature) });
    const componentSource = map.current.getSource("components") as GeoJSONSource | undefined;
    componentSource?.setData({ type: "FeatureCollection", features: placed.filter((c) => c.kind !== "relay").map(componentFeature) });
    tryInitialFit();
  }, [resource.value]);

  useEffect(() => {
    if (!mapReady.current || !map.current) return;
    const source = map.current.getSource("locations") as GeoJSONSource | undefined;
    source?.setData({ type: "FeatureCollection", features: authorized.map(locationFeature) });
    tryInitialFit();
  }, [locations.value]);

  useEffect(() => {
    if (!selected || selected.kind !== "relay") return;
    let active = true;
    api.nocRelay(selected.id).then((value) => { if (active) setSelected({ kind: "relay", id: selected.id, relay: value }); })
      .catch((error: Error) => { if (active) setSelected({ kind: "relay", id: selected.id, error: error.message }); });
    return () => { active = false; };
  }, [selected?.kind, selected?.id]);

  const selectedComponent = selected?.kind !== "relay" ? components.find((c) => c.kind === selected?.kind && c.id === selected?.id) : undefined;

  return <section className="noc-view">
    <h2>NOC view</h2>
    <TutorialHint>A read-only map of this account's physical components (relays, TURN servers) and logical ones (exit-node/subnet-router gateways, the control plane itself, Bedrock) plotted wherever each has a location — detected, declared, or just authorized but not yet occupied (the hollow markers). Every relay, TURN server, exit-node/subnet-router gateway, and declared control-plane/Bedrock location this account has, colored by health where it has one, plus every admin-authorized location -- hollow markers, shown whether or not anything is deployed there yet. A component with no location is listed separately, never guessed onto the map. History, current rate and utilization against capacity are not shown yet -- see docs/admin-console.md.</TutorialHint>
    {resource.error && <Failure message={resource.error} retry={resource.reload} />}
    {locations.error && <Failure message={locations.error} retry={locations.reload} />}
    <div ref={container} className="noc-map" role="application" aria-label="Component map" />
    <ul className="noc-legend">
      {kinds.map((kind) => <li key={kind}><span className="noc-legend-glyph" style={{ color: `var(${kindChartToken[kind]})` }}>{kindGlyph[kind]}</span> {kindLabel[kind]}</li>)}
      <li><span className="noc-legend-glyph" style={{ color: "var(--muted)" }}>○</span> Authorized location</li>
      <li><span className="noc-legend-border" aria-hidden="true" /> National border</li>
      <li><span className="noc-legend-border noc-legend-border-province" aria-hidden="true" /> State/province border</li>
    </ul>
    <details className="noc-location-list">
      <summary>Components with no location ({unplaced.length})</summary>
      {unplaced.length === 0
        ? <p className="lede">Every component has a declared or detected location.</p>
        : <div className="noc-unplaced"><ul>{unplaced.map((component) => <li key={`${component.kind}/${component.id}`}>
          <strong>{kindLabel[component.kind] ?? component.kind}</strong> — {component.label} {component.health && <Status state={healthState(component.health)} label={component.health} />}
        </li>)}</ul></div>}
    </details>

    <Dialog open={Boolean(selected)} title={selected?.kind === "relay" ? `Relay — ${selected?.relay?.location?.label || selected?.relay?.region || selected?.id || ""}` : `${kindLabel[selected?.kind ?? ""] ?? selected?.kind} — ${selectedComponent?.label ?? selected?.id ?? ""}`} onClose={() => setSelected(undefined)}>
      {selected?.kind === "relay"
        ? (selected.error ? <p role="alert">{selected.error}</p> : !selected.relay ? <p>Loading…</p> : <>
          <p><code>{selected.relay.address}</code></p>
          <p>Region: {selected.relay.region}</p>
          {selected.relay.location && <p>Location: {selected.relay.location.label || `${selected.relay.location.lat}, ${selected.relay.location.lon}`} <span className="lede">({selected.relay.location_source === "detected" ? "detected via cloud metadata" : "declared"})</span></p>}
          <p>Health: <Status state={relayHealthState(selected.relay)} label={selected.relay.health.admission_state} /></p>
          <p>Sessions: {selected.relay.health.sessions ?? "—"}</p>
          <p>Bytes (cumulative): {selected.relay.health.bytes != null ? formatBytes(selected.relay.health.bytes) : "—"}</p>
          <p>Last confirmed: <Observed at={selected.relay.health.last_confirmed_at} /></p>
        </>)
        : selectedComponent && <>
          <p>Kind: {kindLabel[selectedComponent.kind] ?? selectedComponent.kind}</p>
          {selectedComponent.location && <p>Location: {selectedComponent.location.label || `${selectedComponent.location.lat}, ${selectedComponent.location.lon}`}</p>}
          {selectedComponent.health && <p>Health: <Status state={healthState(selectedComponent.health)} label={selectedComponent.health} /></p>}
        </>}
      <div className="actions"><button onClick={() => setSelected(undefined)}>Close</button></div>
    </Dialog>
  </section>;
}
