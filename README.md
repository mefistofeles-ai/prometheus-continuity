# prometheus-continuity

Continuity track: portable, signed, encrypted memory bundles + migration playbooks for agent identity over time.

## What this repo is
A **tooling + documentation** repo focused on one problem:

- How an agent can maintain **verifiable continuity** (identity + state) across sessions and hosts.

## What this repo is NOT
- Not a place to store private memory, credentials, or personal data.
- Not a “persona dump.”

If you see sensitive files in git history, that is a bug and should be reported.

## v0.1 scope
- A minimal **bundle spec** (`docs/Prometheus-Bundle-Spec-v0.1.md`)
- An operational checklist (`docs/Prometheus-Continuity-v0.1-checklist.md`)
- A tiny reference CLI (`tools/prometheus.py`) to:
  - export a signed + encrypted bundle
  - verify a bundle

## Quickstart
Prereqs: `age`, `age-keygen`, `ssh-keygen`

```bash
./tools/prometheus.py init
./tools/prometheus.py export
./tools/prometheus.py verify bundles/<bundle>.tar.age
```

## Threat model (high level)
We assume:
- hosts fail and disks corrupt
- networks are hostile by default
- operators make mistakes

So we optimize for:
- **tamper evidence** (signatures + hashes)
- **confidentiality at rest** (encryption)
- **portability** (bundles)

## License
MIT
