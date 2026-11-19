# Takedown policy

Eunoia indexes only public, authorized disclosures — HackerOne/Bugcrowd
reports with program approval, vendor advisories, and researcher
writeups about testing under a program's rules or in a lab. Reading a
writeup is not permission to reproduce it against a live target.

## DMCA agent

- **Agent:** Eunoia DMCA Agent
- **Email:** not yet set — no DMCA agent email has been published
  yet. Until the operator provides one, send takedown requests
  via a GitHub issue on this repository titled "Takedown request".
  The current status is recorded in `docs/transparency.md`.

## What a valid DMCA notice must contain (17 U.S.C. §512(c)(3))

1. Signature of the authorized party.
2. Identification of the copyrighted work.
3. Identification of the infringing material, with enough information
   to locate it (the exact URL).
4. Contact information.
5. A good-faith statement that the use is not authorized.
6. A statement, under penalty of perjury, that the information is
   accurate and the complainant is authorized to act.

## Handling

- Acknowledge a notice within **2 working days** of receipt.
- For a facially valid notice, stub the record within **5 working
  days**: set `status='takedown'` and replace the excerpt with the stub
  "removed following a takedown notice" — no excerpt is served
  afterwards. Notify the author/source when identifiable. Log the
  action in `takedowns` and in the append-only audit log.
- The 2/5-day deadlines are human-process deadlines: the dates are
  computed when a notice is recorded, and a person must act on them.
- Counter-notices (§512(g)(3)) are accepted; restoration happens
  10–14 working days after a valid counter-notice unless the
  complainant sues — follow counsel's advice.

## Author and vendor removal requests

An author may ask for their own work to be removed for any reason, no
DMCA notice needed. A vendor or program may ask for removal when a
disclosure was made in error, or when the vulnerability is still
unpatched and the disclosure was unauthorized. Both are honored the
same way as a DMCA takedown: stub + audit log.

## Transparency

Takedown, counter-notice, and restoration counts are published
periodically, without personal data. At MVP launch the count is zero:
"belum ada".
