# Admin console — `karst-console`

**PLAN.md §8.1, §8.3 · W2–W10 · Frontend 1 and 2.**

## 1. Starting point

> **Re-baselined 2026-08-27.** The console workspace and its principal views
> now exist. Prioritize integration correctness over building shells: its setup
> screen still instructs users to run nonexistent `karst up`; Bedrock signing
> controls cannot complete because their API is stubbed; audit export does not
> supply the API's required format; and sink creation currently promises
> forwarding that the server does not perform. Reconcile the getting-started
> guide's claims that groups/relays/settings are read-only with the current UI
> and real-server behavior, then cover each mutation with E2E tests.

The following is the historical empty-workspace baseline, retained for context
only; the re-baseline above is the current work list.

`web/` holds a `package.json`, a `pnpm-workspace.yaml` naming `console`,
`portal`, and `packages/*`, and a README explaining that `@karst-net` is a
placeholder scope. **None of the three workspace members exist.** `just
web-install` and `just web-check` are wired and there is no web job in
`.github/workflows/ci.yml` — only `licenses-check` walks `web/` today, checking
SPDX headers on files that are not there yet.

So W2 starts from an empty directory with a decided stack: Vite, React 19,
TypeScript strict, TanStack Router + Query, Tailwind, Radix primitives, a
generated OpenAPI client, Playwright, Vitest, and no state-management library
beyond Query.

## 2. Eleven views, ranked

§8.1 specifies eleven. Ten weeks, two engineers, and a phase whose exit
criterion names five specific tasks. **Rank them now, so the cut in W9 is a
decision made in W2 rather than a panic.**

| Rank | View | Why | Cut to |
|---|---|---|---|
| 1 | **First-run setup** | *Not in §8.1.* The exit criterion is "a non-expert admin can install the server … following only the published docs". Nothing else matters if enrolment has no front door | — must ship |
| 2 | Machines | The primary object. Everything else is configuration of it | — must ship |
| 3 | Access controls | Writing an ACL is named in the exit criterion | Editor + validate; **preview diff can slip** |
| 4 | Auth keys | You cannot connect a node without one | — must ship |
| 5 | Users | Deprovisioning a user is named in the exit criterion | — must ship |
| 6 | Bedrock | Enabling network lock is named in the exit criterion | Mode switch + pending requests + inventory; **log viewer can be a table** |
| 7 | Crypto posture | §8.1: "a differentiating feature, not a nicety" | Aggregate + session table; charts can wait |
| 8 | DNS | Needed to demonstrate [01](01-karstdns.md) | Read-write, plain forms |
| 9 | Audit log | Compliance story | **Read-only, no SIEM sink UI** — configure sinks by API in Phase 5 |
| 10 | Groups | Mostly IdP-driven | **Read-only** |
| 11 | Relays | Self-hosters need it; most operators run the defaults | **Read-only list + health** |
| 12 | Settings | Org profile, SSO, SCIM token, webhooks | Minimal forms |

Ranks 10–12 shipping read-only is the planned outcome, not a failure. Write
that in the release notes rather than leaving an admin to discover a disabled
button.

## 3. Workspace layout

```
web/
  packages/
    api-client/     generated from karst-openapi.yml; CI fails on drift
    ui/             the shared component library — both apps import it
    tokens/         design tokens: colour, type, spacing, dark mode
  console/
  portal/
```

**`packages/ui` is built by Frontend 2 in W2–W3 and is the only shared code.**
Two apps and one design system, per §8. Resist a `packages/shared-hooks`: the
portal's data needs are tiny and deliberately so ([05](05-user-portal.md)), and
a shared hook layer would couple the security boundary between the two apps.

## 4. Cross-cutting decisions to make in W2

**Auth.** OIDC Authorization Code + PKCE against the same IdP the server uses,
tokens in memory with a silent-refresh iframe or a refresh token in an
HttpOnly cookie issued by the server. **Not `localStorage`.** An XSS in an
admin console that stores a bearer token in `localStorage` is total account
compromise; the same XSS against an HttpOnly cookie still hurts but does not
exfiltrate a durable credential. Decide this in W2 because it constrains the
server's callback handling.

**Status encoding.** §8.3 is explicit: "a red/green dot for connection state
fails colorblind users — pair with shape and text". Build this into
`packages/ui` as a single `<Status>` primitive taking a state enum and
rendering icon + shape + label, and make it the *only* way status is rendered.
A rule that lives in a component is followed; a rule that lives in a style
guide is not.

**Time.** Everything this console shows is an observation with an age
([03](03-control-api.md) §5.1). One `<Observed at={…}>` primitive, used
everywhere, rendering "14:32 (4 min ago)" with the absolute time in a tooltip
and `<time datetime>` underneath for screen readers. No bare "online".

**Empty and error states are first-class.** A fresh install has zero machines,
zero users, no policy, and no relays. That is the state the exit criterion's
non-expert admin sees first, and it is the state most consoles render as a
blank table with a spinner. Every list view gets a designed empty state that
says what to do next and links to it.

## 5. The two hard views

### 5.1 Access controls — the HuJSON editor

The hardest single component in the phase.

- **CodeMirror 6**, not Monaco. Monaco is ~2 MB gzipped and brings a worker
  architecture for one editor on one page. CodeMirror 6 is modular, ~150 KB
  for what is needed here, and its lint and autocomplete extensions are the
  ones this needs.
- **HuJSON** — JSON with comments and trailing commas — needs its own parser
  for the editor. Do not write one: the fork's Go side already parses it in
  `karst/policy`, so the editor parses loosely for syntax highlighting and
  **defers all real diagnostics to `POST /policy/validate`**, debounced at
  ~400 ms. One parser of record, on the server, which is also the one that
  compiles the filter that actually runs. Two parsers that disagree is a
  console that lints a document the server then rejects.
- Autocomplete is schema-aware from a JSON Schema shipped by the server, so
  adding a policy field does not require a console release.
- **Preview diff** (`POST /policy/preview`) rendered as a two-column
  added/removed flow list in admin language: "`group:sre` → `tag:prod:22`
  **added**". Behind a "Preview changes" button, not live — recompiling the
  netmap for every keystroke is a denial-of-service against your own server.
- Version history with a diff view and one-click rollback, per §4.3.
- Save uses `If-Match` on the current version and surfaces a real conflict UI.
  Two admins editing an ACL simultaneously is not hypothetical, and
  last-write-wins on a network access policy is a security bug.

### 5.2 Crypto posture

The view that proves the product's claim. §8.1: "the product must be able to
prove that claim, per-session, on screen, to an auditor."

Three bands:

1. **The headline**, with its denominator and its as-of time. Never a bare
   percentage. If 3 of 52 nodes have not reported in an hour, the headline
   says so next to the number — the honest version has to be the prominent
   one, or the view is decoration.
2. **Exceptions first**: lattice-only (PSK-absent) sessions, downgraded
   sessions, nodes below the minimum suite, nodes that have not reported.
   Sorted worst-first, with a filter per category. An auditor's question is
   "show me what is not compliant", and that should be the default view rather
   than a filter they have to construct.
3. **The full session table**, filterable and exportable to CSV, with the
   negotiated suite, PSK epoch, and path type per row.

Minimum-suite enforcement is a write here: set a floor, see how many sessions
would fail it, then apply. Same acknowledge-the-damage pattern as Bedrock's
`enforcing` switch, and for the same reason.

## 6. Schedule

| Weeks | Frontend 1 | Frontend 2 |
|---|---|---|
| W2 | App shell, routing, auth flow, layout | `packages/tokens`, `packages/ui` primitives, `<Status>`, `<Observed>` |
| W3 | Machines list + detail against the mock | Forms, tables, dialogs, empty states; Vitest + axe harness |
| W4 | Machines: paths, tags, expiry, deprovision | Auth keys; Users |
| W5 | Access controls: editor + validate | DNS; Groups (read-only) |
| W6 | Access controls: history, rollback, conflict | Audit log; Relays (read-only) |
| W7 | Crypto posture | **First-run setup wizard** |
| W8 | Bedrock: inventory, mode switch, requests | Portal ([05](05-user-portal.md)) |
| W9 | Preview diff; polish; a11y sweep | Portal; Settings |
| W10 | Exit walkthrough fixes | Exit walkthrough fixes |

The first-run wizard is ranked first in §2 and scheduled in W7 on purpose: it
can only be built once the flows it stitches together exist, and it is the
thing most likely to be discovered wrong during the W10 walkthrough. Give it a
full week and expect to redo half of it.

## 7. Quality bar and how it is enforced

§8.3 sets WCAG 2.2 AA, keyboard navigation throughout, dark mode, and no
colour-only status. Enforced, not aspired to:

- `@axe-core/playwright` runs on every E2E route; violations fail CI.
- One Playwright spec per critical flow driven **keyboard-only**: create an
  auth key, edit and save a policy, deprovision a user. If it cannot be done
  with the keyboard it is not done.
- Dark mode is a token-level concern in `packages/tokens`; no component
  defines a colour literal, checked by an ESLint rule on hex literals in
  `.tsx`.
- Every source file carries an SPDX header — `just licenses-check` already
  walks `web/` for `.ts` and `.tsx` and will start failing the moment the
  first file lands without one.

## 8. CI

There is no web job in `.github/workflows/ci.yml`. Add one in W2, before the
code volume makes it painful:

```
web:
  - pnpm install --frozen-lockfile
  - just web-check                 # tsc --noEmit + lint, both already defined
  - pnpm -r test                   # Vitest
  - pnpm -r build
  - pnpm --filter console exec playwright test   # against the mock server
  - client drift check: regenerate from karst-openapi.yml, fail on diff
```

Playwright against the **mock** in the ordinary job, and against a real
`deploy/compose` stack in a nightly. The second is slower and flakier and is
also the only one that would have caught Phase 4's findings 42 and 43 —
components that existed only in the test harness while production read the
field the harness filled. A console tested exclusively against its own mock
is precisely that failure shape, one layer up.

## 9. Risks

| Risk | Mitigation |
|---|---|
| API contract slips past W2 | Frontend builds against a hand-written fixture set for one week maximum, then escalates. Two idle engineers is the most expensive failure available in this phase |
| The HuJSON editor eats W5 and W6 | It is scheduled for both. If it eats W7, ship it without preview diff and without history — a plain textarea with server-side validation and a save button meets the exit criterion |
| Design system rebuilt mid-phase | Freeze `packages/tokens` at the end of W3. Visual dissatisfaction in W7 is a Phase 6 item |
| The console looks finished and is not | The W10 walkthrough is run by someone who did not build it — [09](09-exit-criteria.md) |

## 10. Exit criteria

1. A non-expert admin completes first-run setup, creates an auth key, and
   connects a node, using only the console and the published docs.
2. Writing, validating, and saving an ACL works, and a syntax error is
   reported with a line number in the editor.
3. Deprovisioning a user from the console expires their node keys and drops
   their sessions within 60 seconds — the console half of PLAN.md §4.4's
   integration test.
4. Network lock can be enabled from the console, including the
   acknowledge-the-cut-off list.
5. The crypto posture view shows per-session negotiated suites with a
   denominator and an as-of time, and exports to CSV.
6. Every route passes axe with no violations, and the three critical flows are
   completable keyboard-only.
