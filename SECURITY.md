# Security policy

Eunoia is a read-only registry for public, authorized vulnerability
disclosures. It does not run scanners, does not store or serve
payloads against live targets, and does not execute exploits. This
policy covers the code in this repository and the hosted API and
MCP server operated from it.

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | Yes                |
| < 0.1   | No (pre-release)   |

## Reporting a vulnerability

Report through GitHub's private vulnerability reporting on this
repository (Security tab → Report a vulnerability). If that channel
is unavailable, open a public issue with minimal detail and ask for
a private channel; do not include credentials, tokens, or personal
data in any report.

A useful report includes:

- The affected version or commit.
- Steps to reproduce, with the smallest setup that shows the issue.
- The impact: what an attacker gains, and who is affected.

Do not test a suspected vulnerability against the hosted service
or against any live target. Use a local checkout with
`bash scripts/setup_dev.sh` and the test database instead.

## What happens after a report

- We aim to acknowledge a report within 5 working days.
- Fix timing depends on severity: issues that expose writeup
  content beyond the serving gate, bypass authentication, or leak
  credentials are treated first.
- Please do not disclose a vulnerability publicly until a fix is
  released, or 90 days after the report, whichever comes first.
  We will credit reporters who ask to be credited.

## Out of scope

- Third-party services Eunoia reads from (HackerOne, NVD, CISA KEV).
- Social engineering, physical access, and volumetric denial of
  service.
- Reports without reproduction steps or a demonstrated impact.
- The lab-only reference harness (`src/eunoia/harness/`), which is
  explicitly not for use against shared or live targets.

## Takedowns and content removal

Content removal requests are not security reports. They follow
`docs/policies/takedown.md`. A DMCA agent email has not been
published yet; see that policy and `docs/transparency.md` for the
current status.
