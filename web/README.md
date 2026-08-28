# Karst web

Admin console and user portal. **AGPL-3.0-or-later**, matching the coordination
server.

## Control API mock

Run `just api-mock` to serve the frozen Karst control-API contract at
`http://127.0.0.1:4010/api/karst/v1`. It has fifty nodes across paginated
results, two relays with different health, mixed PQ posture, a Bedrock signing
request, and an audit-chain verification failure. The fixture is deliberately
not a happy-path-only account.

> **npm scope:** placeholder `@karst-net`. The `karst` scope was unavailable;
> correct this in `web/package.json` and `web/*/package.json` if the registered
> scope differs. Single point of change — see ADR-0010.
