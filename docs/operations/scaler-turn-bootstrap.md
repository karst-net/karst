<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# The reference coturn bootstrap

Operations reference for `deploy/images/karst-turn-bootstrap.Dockerfile`
(ADR-0045 §7b, issue #311) — the reference coturn image #310 named as a
non-goal. This wraps the official `coturn/coturn` image with a shell
entrypoint that self-enrolls against the control server before starting
`turnserver`; it is not a complete TURN deployment guide, and it is not
itself a `karst-scaler` `Driver` — see issue #311 for where this fits
relative to the Kubernetes TURN driver that consumes it (not built yet).

## What the entrypoint actually does

`deploy/images/karst-turn-bootstrap-entrypoint.sh` runs before `turnserver`
starts:

1. `POST /karst/v1/turn/enroll` with `{"uri": ..., "region": ...}`,
   authenticated by the single-use bearer token
   `POST /karst/v1/turn/enroll-tokens` minted — registers this instance's
   `uri` in `turncred.Store`. A `412` (already registered — e.g. this
   container restarted and re-ran its own already-consumed token's `uri`)
   is treated as success, not a failure.
2. Appends `use-auth-secret` / `static-auth-secret=...` / `realm=...` to
   whatever base coturn config was supplied, writing the result to
   `/etc/turnserver.generated.conf`.
3. `exec turnserver -c /etc/turnserver.generated.conf -n "$@"` — any
   extra arguments the container is run with pass straight through.

No Karst code runs inside coturn — this is a shell wrapper, not a
`karst-turn` binary, because there is nothing to integrate with inside a
vanilla coturn process (RFC 8656 authenticates the client to the server,
never the reverse — see `turncred.go`'s own package doc). The instance
mints nothing of its own; it only redeems a token someone else minted.

## The one thing this script will not do for you

`static-auth-secret` **must be the same secret** the control server's
`turncred.Minter` is configured with. This script never receives that
secret over the network, derives it, or mints it — the shared-secret
design is exactly how `turncred.go` keeps "Static TURN credentials must
never be placed in a netmap" true: the secret lives only in the control
server's own config and in whatever an operator passes to this
container as `KARST_TURN_STATIC_AUTH_SECRET`. Getting that value to both
places is the operator's own key-management problem — the same posture
the Kubernetes relay driver's docs already take toward identity-key
persistence.

Every other coturn setting this script does not know anything about
(`turns:` TLS certificates, `min-port`/`max-port` for the relay port
range, `external-ip` for a NAT'd instance, ...) is the operator's own
config, supplied via `KARST_TURN_BASE_CONF` and copied in before the two
lines above are appended. A deployment running `turns:` or behind NAT
needs that base config; this image supplies none of it by default.

## Required environment variables

| Variable | Meaning |
|---|---|
| `KARST_CONTROL_API_BASE` | The control server's own API base, e.g. `https://control.example.test/api`. |
| `KARST_TURN_ENROLL_TOKEN` | A single-use token from `POST /karst/v1/turn/enroll-tokens`. |
| `KARST_TURN_URI` | This instance's own `turn:` or `turns:` URI, e.g. `turn:turn-0.turn.example.test:3478`. Must match what coturn actually listens on, and whatever a driver will later pass to `POST /karst/v1/turn/deenroll` to remove this exact entry — see `turncred.Store.DeleteByURI`'s own doc comment for why the two must agree exactly, byte for byte. |
| `KARST_TURN_STATIC_AUTH_SECRET` | The operator's own shared TURN-REST secret — see above. |

Optional: `KARST_TURN_REGION` (default: unset, which `turncred`'s own
`validate()` maps to `DefaultRegion`), `KARST_TURN_REALM` (default:
`karst`), `KARST_TURN_BASE_CONF` (default: none — an empty config plus
the two Karst-required lines), `KARST_TURN_GENERATED_CONF` (default:
`/etc/turnserver.generated.conf`).

## Verified by running

Built the image from `coturn/coturn:4.6` and ran the entrypoint against a
local fake control server standing in for the real one:

- A `201` response writes the generated config correctly and the real
  `turnserver` binary starts from it.
- A `412` response (uri already registered) is treated as success, not
  a failure — confirmed the container still starts `turnserver`.
- A non-2xx/412 response (e.g. an invalid token, `401`) exits non-zero
  before ever writing a config or starting `turnserver` — confirmed
  nothing is left half-configured.
- Extra arguments passed to `docker run` reach `turnserver` unchanged.

Not verified here: a real control server round trip (only a fake one),
and real coturn TURN-REST credential validation against a minted
`turncred.Credential` end to end — both need a running control server
and relay/client stack this environment did not have, the same posture
the Kubernetes and AWS relay drivers' own docs already flag for their
own real-infrastructure gaps.
