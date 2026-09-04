# Windows client — pulled forward from Phase 8

**Re-scoped 2026-09-04.** [00-overview.md](00-overview.md) §1/§2 item 10:
Windows moves out of Phase 8 and becomes a firm requirement before public
beta (#12) opens, swapped in for the FreeBSD best-effort line that this
phase drops entirely (§6 there). PLAN.md §9's platform table and §10/Phase 8
are updated to match.

This file does not re-derive the technical plan.
[phase-5/07-windows-client.md](../phase-5/07-windows-client.md) already
covers the device, addressing, service, DNS, MSI, signing, and testing work
in full, written for a Phase 8 handoff — none of that content changes by
moving phases, since none of it is written against a calendar. What changes
is the framing below: this is no longer background work with a re-estimate
pending, it is the thing public beta waits on.

## 1. What's inherited unchanged from the Phase 8 handoff

All of [phase-5/07-windows-client.md](../phase-5/07-windows-client.md)'s
technical content applies as written:

- §1 — the Wintun/GPL licensing question, and why it is a lawyer's call.
- §2 — no driver to sign; only ordinary code-signing for the binaries and MSI.
- §3 — the device (`crates/karst-tun/src/windows.rs`, the `Device` enum's
  third arm alongside `Tun`/`Userspace`), Wintun's ring-buffer I/O model, the
  shutdown-event problem.
- §4 — addressing and routing via the IP Helper API, deliberately not
  `netsh` (locale-dependent output parsing).
- §5 — the service: SCM registration, `LocalSystem`, ACLs on
  `%ProgramData%\Karst\`, power-event handling.
- §6 — DNS via NRPT, the revert-file-before-write discipline, testing against
  a domain-joined machine.
- §7 — the MSI: WiX, upgrade codes, uninstall correctness, ARM64 out of scope.
- §8 — signing: Azure Trusted Signing preferred, OV/EV as fallback, checked
  in W1.
- §9 — the test matrix, including the cross-platform seam
  `scripts/two-host-test.sh` already has from the macOS work.

Nothing in §§1-9 is Phase-8-specific; it was simply never staffed because
PLAN.md §10 didn't schedule an engineer against it until now.

## 2. What actually changes

1. **Staffing starts now, not in a later phase.** [00-overview.md](00-overview.md)
   §4 gives this to Rust 3 for the full W1–W8, replacing what would otherwise
   have been split time on FreeBSD and residual observability work — both of
   which are done or dropped (§8 there is done; FreeBSD is cut).
2. **The schedule is compressed from 9 weeks to 8, and one week has to come
   from somewhere.** [phase-5/07-windows-client.md](../phase-5/07-windows-client.md)
   §10's historical breakdown runs W1 (license) through W9 (signing/SmartScreen/
   clean-machine verification) as a dedicated final week. Folding into 8 means
   running signing (§8) in parallel with MSI packaging (§7) in the same week
   rather than sequencing them — both are mechanical once the certificate
   route is decided in W1, and neither blocks the other's start. The schedule
   below reflects that; everything else keeps its original week's scope,
   shifted down by one:

   | Week | Work |
   |---|---|
   | W1 | Wintun license answer, ADR-0015, signing-certificate route decided. **Hard deadline: if no answer by end of W2, take the ADR-0012 userspace-mode fallback (§1's "honest fallback") rather than block on it further** |
   | W2 | `windows.rs`: adapter, session, ring I/O, shutdown event |
   | W3 | Addressing, routes, IP Helper; `local_addresses`, `default_gateway` |
   | W4 | `karstd` runs end to end on Windows; loopback pair test |
   | W5 | Service: SCM, lifecycle, power events, ACLs, Event Log |
   | W6 | NRPT, per-interface DNS, revert, domain-joined testing |
   | W7 | MSI: install, service, firewall, upgrade codes — signing and SmartScreen check run in parallel, not after |
   | W8 | Uninstall correctness, upgrade path, CI job, clean-machine verification |

3. **The beta gate is [phase-5/07-windows-client.md](../phase-5/07-windows-client.md)
   §11 as written**, unchanged — six criteria, reproduced in
   [00-overview.md](00-overview.md) §7. "Full port" means all six, not a
   subset; the userspace-mode fallback in item 1 above is a licensing
   contingency, not a lowered bar — it still has to meet the same six
   criteria (userspace mode has no kernel routing to lose sight of, since
   ADR-0012's stack already runs without one).

## 3. Risk

Carried in full at [00-overview.md](00-overview.md) §5's top row: an
unresolved legal question and a one-week compression are both real, and
the mitigation is the same one §1 of the original handoff already gave —
decide the fallback before it's discovered late, not after.
