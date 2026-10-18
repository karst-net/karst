<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# NOC basemap data

Both datasets are public-domain Natural Earth data, served from the console's
own origin. No external tile service or runtime data provider is used.

- `noc-world-outline.geojson`: existing 1:110m admin-0 country polygons,
  converted from `world-atlas`, with coordinates rounded to three decimals.
- `noc-state-province-borders.geojson`: worldwide 1:10m admin-1 boundary
  lines (not province polygon outlines, so coastlines and national borders
  are not intentionally repeated). Null geometries and unused properties
  are removed; Douglas-Peucker simplification uses a 0.02 degree tolerance
  and coordinates are rounded to three decimals. This is an overview map,
  not a source for precise administrative boundary decisions. Coverage and
  boundary conventions follow Natural Earth.

Admin-1 source downloaded October 18, 2026:
https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_10m_admin_1_states_provinces_lines.geojson

Source SHA-256:
`1a1f30ccaaf4cc9c4bde34266f0b8cbb955d3a4cf254b756912255f2ec7c75b6`

From the repository root, regenerate with:

```sh
python3 web/tools/build-noc-boundaries.py /path/to/ne_10m_admin_1_states_provinces_lines.geojson web/console/public/noc-state-province-borders.geojson
```

The map uses MapLibre's globe projection to reduce Mercator's exaggeration
of high latitudes at overview scales. National outlines are solid and drawn
above thinner dashed state/province lines; both are labeled in the legend.
