# Security Policy

Karst is a post-quantum mesh VPN. Cryptographic and network-facing code is the
product, so security reports are treated as first-class work, not interruptions.

The full threat model — assets, adversary tiers, trust boundaries, accepted
risks and residual risks — is at [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).
Reading §7 (accepted risks) before reporting will tell you whether a behavior
is a bug or a documented limitation.

## Reporting a vulnerability

**Do not open a public issue for a security bug.**

- Preferred: GitHub **private vulnerability reporting** on the affected
  repository (Security → Report a vulnerability).
- Alternative: email `security@` the project domain, encrypted to the key in
  `SECURITY-KEY.asc` if you prefer.

Please include what you did, what happened, what you expected, and the commit
or release you tested. A proof of concept helps enormously; a failing test case
helps more.

### What to expect

| Stage | Target |
|---|---|
| Acknowledgment | 3 working days |
| Initial assessment | 10 working days |
| Fix or mitigation plan agreed with you | 30 days |
| Public disclosure | Coordinated, default 90 days from report |

We will tell you honestly if a report is a duplicate, out of scope, or already
a documented accepted risk. We would rather say "we already know" than let a
report sit unanswered.

## Safe harbour for good-faith research

If you make a good-faith effort to comply with this policy, we will:

- consider your research **authorized** under the Computer Fraud and Abuse Act
  and equivalent legislation, and not initiate or support legal action against
  you;
- consider it **exempt** from anti-circumvention provisions (DMCA §1201 and
  equivalents), and raise no claim against you for circumvention undertaken to
  perform the research;
- waive any relevant restriction in our terms of use to the extent needed to
  permit the research; and
- work with you if a third party brings action against you for research
  conducted under this policy.

Good faith means: only test against infrastructure you own or are explicitly
authorized to test; do not access, modify, or retain data belonging to others;
do not degrade service for others; stop as soon as you have demonstrated the
issue; and give us reasonable time to remediate before disclosure.

If you are unsure whether something is in scope, ask first — we would rather
answer a question than receive a report we cannot safely act on.

## Scope

**In scope:** the PHREATIC handshake and datapath, the Ponor relay, the
coordination server, the console and portal, KarstDNS, Bedrock, the CLI and
node agent, and the build and release pipeline.

**Out of scope**, per the threat model:

- Endpoint compromise (root on a node yields that node's keys — §7.2).
- Metadata exposure to relays and TURN providers (§7.1, by design).
- Denial of service against your own self-hosted deployment.
- Findings against a dependency that are already public and unpatched
  upstream — report those upstream; tell us so we can pin or mitigate.
- Social engineering of maintainers or users.

## Recognition

Reporters are credited in release notes and in `THANKS.md` unless they ask not
to be. There is no bug bounty; this is a community project with no revenue
(see [ADR-0007](docs/adr/0007-licensing.md)). We will not pretend otherwise to
attract reports.

## Verifying a release

Every tagged release ships `SHA256SUMS` covering the `.deb`, `.rpm` and macOS
packages, and a detached `SHA256SUMS.asc` signed with the release key in
[docs/release-key.asc](docs/release-key.asc):

```
pub   ed25519 2026-09-01 [C] [expires: 2028-08-31]
      DD5C 7054 DBFA E8D6 9704  95A3 0CFE 3D34 6567 3971
uid   Karst Release Signing
sub   ed25519 2026-09-01 [S] [expires: 2028-08-31]
      95E8 4D07 245E E5CD 73F9  EA0D F07F BCFA 8E79 B334
```

```sh
gpg --import docs/release-key.asc
gpg --verify SHA256SUMS.asc SHA256SUMS   # must say "Good signature"
sha256sum --check --ignore-missing SHA256SUMS
```

Both steps matter and neither substitutes for the other: the checksum proves
the file arrived intact, the signature proves we are the ones who computed the
checksum.

**What this does and does not get you.** The key is distributed in the same
repository as the code it signs, so anyone who can rewrite this repository can
replace the key along with the artifacts. That makes the signature a defence
against a compromised release runner, a substituted download, or a hostile
mirror — not against a compromised repository. Cross-check the fingerprint
above against a second source before trusting it for anything consequential.
Only the signing subkey is held by CI; the certifying primary key is offline,
so a compromise of the release pipeline can be revoked without changing this
key's identity.

The macOS `.pkg` is separately signed with a Developer ID Installer certificate
and notarized by Apple, which is what lets Gatekeeper accept it. Both are
checkable locally:

```sh
pkgutil --check-signature karst-macos-universal.pkg
spctl --assess --type install -vv karst-macos-universal.pkg
xcrun stapler validate karst-macos-universal.pkg
```

Container images are signed keylessly with cosign, so there is no public key to
fetch — the identity is the workflow that built them, recorded in a public
transparency log:

```sh
cosign verify \
  --certificate-identity "https://github.com/karst-net/karst/.github/workflows/deliverables.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/karst-net/karstd:vX.Y.Z
```

The same applies to `karst-relay` and `karst-control`. Verify against the
digest rather than the tag where it matters: a tag can be moved, a digest
cannot.

## Our commitments

- Advisories published via GitHub Security Advisories with CVEs requested where
  applicable.
- The security whitepaper and threat model are updated when a finding changes
  the model, not only when it changes the code.
- External cryptographic review and penetration test results are published in
  summary before GA, including findings we did not fix and why.
