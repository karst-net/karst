# Plan-to-issue migration

Migrated 2026-09-06 from commit `49b008ebbe4ebb490fd17597ff42451225a6003c`.

**GitHub issues are the source of truth for remaining work.** PLAN.md and the other files under plans/ are archived design and implementation records. Their schedules, open markers and future-tense instructions are historical, not a second backlog. Update the linked issues for progress and scope; retain these records for design rationale and completed-work evidence.

## Migrated work

- [Release validation: run the unaided outsider installation walkthrough](https://github.com/karst-net/karst/issues/107)
- [Implement ACL-gated SSH as an independent TCP/22 admission gate](https://github.com/karst-net/karst/issues/108)
- [Validate subnet routers and exit nodes from published packages](https://github.com/karst-net/karst/issues/109)
- [Deliver and validate the Windows client for the public beta](https://github.com/karst-net/karst/issues/110)
- [macOS: apply mesh DNS search domains without replacing DHCP domains](https://github.com/karst-net/karst/issues/111)
- [macOS: validate and enable the menu-bar status app](https://github.com/karst-net/karst/issues/112)
- [macOS: record real sleep/wake and clean-machine Gatekeeper validation](https://github.com/karst-net/karst/issues/113)
- [Documentation: validate the operations restore runbook with an independent operator](https://github.com/karst-net/karst/issues/114)
- [Documentation: complete independent reviews, crypto sign-off and README status update](https://github.com/karst-net/karst/issues/115)
- [Run the public design-partner beta and meet the 30-day stability gate](https://github.com/karst-net/karst/issues/116)
- [Build iOS and Android clients over the Rust core](https://github.com/karst-net/karst/issues/117)
- [Shard the datapath across TUN and UDP queues](https://github.com/karst-net/karst/issues/118)
- [Measure the deferred absolute throughput and resource targets](https://github.com/karst-net/karst/issues/119)
- [Evaluate and implement io_uring datapath I/O](https://github.com/karst-net/karst/issues/120)
- [Implement path MTU discovery for the encrypted datapath](https://github.com/karst-net/karst/issues/121)
- [Add QUIC relay transport](https://github.com/karst-net/karst/issues/122)
- [Prepare and publish v1.0 GA after beta and Phase 7 acceptance](https://github.com/karst-net/karst/issues/123)
- [Sign and timestamp Windows release artifacts](https://github.com/karst-net/karst/issues/124)
- [Book and complete an external cryptographic review](https://github.com/karst-net/karst/issues/125)
- [Commission and complete an external control-plane and console penetration test](https://github.com/karst-net/karst/issues/126)
- [Finish trademark registration and package-name reservations](https://github.com/karst-net/karst/issues/127)
- [Complete deferred admin-console management and policy-preview surfaces](https://github.com/karst-net/karst/issues/128)
- [Make karst-proto usable without std](https://github.com/karst-net/karst/issues/129)
- [Complete live Bedrock anchor-age and PSK-rotation demonstrations](https://github.com/karst-net/karst/issues/130)
- [Record dispositions for explicitly unscheduled product extensions](https://github.com/karst-net/karst/issues/131)

## Existing issues reused

- [#101: karstd: finish the tracing migration — remaining println!/eprintln! call sites](https://github.com/karst-net/karst/issues/101)
- [#99: PSK epoch never rotates without a karst-control restart](https://github.com/karst-net/karst/issues/99)
- [#93: relayreg.StoredRelay has no JSON tags: /relays returns capitalized field names, no health](https://github.com/karst-net/karst/issues/93)
- [#88: No rate-limiting on node enrollment attempts (setup-key validation)](https://github.com/karst-net/karst/issues/88)
- [#86: karst-control's CORS policy is unconditionally AllowAll(), with no management.json knob](https://github.com/karst-net/karst/issues/86)
- [#85: No documented path for a domain-matched deployment's first OIDC user to become admin](https://github.com/karst-net/karst/issues/85)
- [#59: [Finding 54] PHREATIC's transport type byte is outside the AEAD, so it cannot discriminate a second message type](https://github.com/karst-net/karst/issues/59)

## Reconciliation

- Phases 0–5 are completed historical records, except the residual work explicitly linked above. Later completion evidence supersedes older “remaining” paragraphs (including true delta netmaps and relay mesh/metrics/reload work).
- Phase 6 anchor authorities, cache migration, first internal crypto-review pass, internal pentest, TURN, observability implementation and HA engineering drills are complete. Existing open findings remain in their original issues.
- Subnet routing is implemented (PR #95 and follow-ups); #109 tracks the published-package demonstration. Documentation is written (PR #104); #107, #114 and #115 track independent demonstrations and sign-off.
- Release-manifest generation and publication landed in 59e597e and 26e5b5d. Control-client TLS landed in 3851717. Older missing-manifest and h2c-only statements are superseded.
- ADR-0018 supersedes the old hybrid/selectable CNSA suite roadmap; no issue recreates that obsolete work. Windows paid signing remains post-GA and separate from the functional beta requirement.
- #131 preserves unscheduled ideas as disposition work, including the explicitly cut FreeBSD port; it does not restore them as release commitments.

## Source coverage

| Archived document | Remaining work or disposition |
|---|---|
| [PLAN.md](../PLAN.md) | [#116](https://github.com/karst-net/karst/issues/116), [#117](https://github.com/karst-net/karst/issues/117), [#118](https://github.com/karst-net/karst/issues/118), [#119](https://github.com/karst-net/karst/issues/119), [#120](https://github.com/karst-net/karst/issues/120), [#121](https://github.com/karst-net/karst/issues/121), [#122](https://github.com/karst-net/karst/issues/122), [#123](https://github.com/karst-net/karst/issues/123), [#124](https://github.com/karst-net/karst/issues/124), [#125](https://github.com/karst-net/karst/issues/125), [#126](https://github.com/karst-net/karst/issues/126), [#127](https://github.com/karst-net/karst/issues/127), [#128](https://github.com/karst-net/karst/issues/128), [#129](https://github.com/karst-net/karst/issues/129), [#131](https://github.com/karst-net/karst/issues/131) |
| [plans/phase-5/00-overview.md](phase-5/00-overview.md) | [#131](https://github.com/karst-net/karst/issues/131) |
| [plans/phase-5/01-karstdns.md](phase-5/01-karstdns.md) | [#131](https://github.com/karst-net/karst/issues/131) |
| [plans/phase-5/02-bedrock.md](phase-5/02-bedrock.md) | [#130](https://github.com/karst-net/karst/issues/130) |
| [plans/phase-5/03-control-api.md](phase-5/03-control-api.md) | [#128](https://github.com/karst-net/karst/issues/128) |
| [plans/phase-5/04-admin-console.md](phase-5/04-admin-console.md) | [#128](https://github.com/karst-net/karst/issues/128) |
| [plans/phase-5/05-user-portal.md](phase-5/05-user-portal.md) | [#107](https://github.com/karst-net/karst/issues/107) |
| [plans/phase-5/06-macos-client.md](phase-5/06-macos-client.md) | [#111](https://github.com/karst-net/karst/issues/111), [#113](https://github.com/karst-net/karst/issues/113), [#131](https://github.com/karst-net/karst/issues/131) |
| [plans/phase-5/07-windows-client.md](phase-5/07-windows-client.md) | [#110](https://github.com/karst-net/karst/issues/110) |
| [plans/phase-5/08-scim-and-groups.md](phase-5/08-scim-and-groups.md) | Complete; deprovisioning #72/#73 and push #75 are closed. |
| [plans/phase-5/09-exit-criteria.md](phase-5/09-exit-criteria.md) | [#107](https://github.com/karst-net/karst/issues/107) |
| [plans/phase-6/00-overview.md](phase-6/00-overview.md) | [#116](https://github.com/karst-net/karst/issues/116) |
| [plans/phase-6/04-pentest.md](phase-6/04-pentest.md) | Internal test complete; existing [#85](https://github.com/karst-net/karst/issues/85), [#86](https://github.com/karst-net/karst/issues/86), [#88](https://github.com/karst-net/karst/issues/88) retain follow-ups. |
| [plans/phase-6/06-subnet-routers-and-exit-nodes.md](phase-6/06-subnet-routers-and-exit-nodes.md) | [#109](https://github.com/karst-net/karst/issues/109) |
| [plans/phase-6/07-acl-gated-ssh.md](phase-6/07-acl-gated-ssh.md) | [#108](https://github.com/karst-net/karst/issues/108) |
| [plans/phase-6/08-observability-exit-demo.md](phase-6/08-observability-exit-demo.md) | [#130](https://github.com/karst-net/karst/issues/130) |
| [plans/phase-6/08-observability.md](phase-6/08-observability.md) | [#130](https://github.com/karst-net/karst/issues/130), [#131](https://github.com/karst-net/karst/issues/131) |
| [plans/phase-6/09-ha-exit-demo.md](phase-6/09-ha-exit-demo.md) | [#114](https://github.com/karst-net/karst/issues/114) |
| [plans/phase-6/09-ha.md](phase-6/09-ha.md) | [#114](https://github.com/karst-net/karst/issues/114) |
| [plans/phase-6/10-windows-client.md](phase-6/10-windows-client.md) | [#110](https://github.com/karst-net/karst/issues/110) |
| [plans/phase-6/11-documentation-exit-demo.md](phase-6/11-documentation-exit-demo.md) | [#107](https://github.com/karst-net/karst/issues/107), [#114](https://github.com/karst-net/karst/issues/114), [#115](https://github.com/karst-net/karst/issues/115) |
| [plans/phase-6/11-documentation.md](phase-6/11-documentation.md) | [#115](https://github.com/karst-net/karst/issues/115) |
| [plans/phase-6/13-macos-status-indicators.md](phase-6/13-macos-status-indicators.md) | [#112](https://github.com/karst-net/karst/issues/112) |
