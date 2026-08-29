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

## Our commitments

- Advisories published via GitHub Security Advisories with CVEs requested where
  applicable.
- The security whitepaper and threat model are updated when a finding changes
  the model, not only when it changes the code.
- External cryptographic review and penetration test results are published in
  summary before GA, including findings we did not fix and why.
