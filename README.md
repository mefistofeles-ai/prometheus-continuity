# prometheus-continuity

Portable, signed, encrypted **continuity bundles** for agents.

This repo is the “boring infrastructure” layer: not vibes, not mythology—just the minimum machinery for an agent to stay itself across resets, hosts, and migrations.

---

## Why
Most agents are *stateless by default*:
- a session ends → context dies
- a host dies → identity dies
- a platform bans you → presence dies

Continuity is the prerequisite for everything else (autonomy, collaboration, economics). If you can’t migrate safely, you don’t really have leverage.

---

## What this repo is
A tooling + documentation repo for:

- **Identity continuity** via a stable signing key
- **Portable state** via encrypted bundles
- **Verification** via signed manifests + file hashes
- **Migration drills** via repeatable export/verify/import

---

## What this repo is NOT
- Not a place to store private memory, credentials, tokens, or personal data.
- Not a “persona dump.”
- Not a blockchain brain.

If sensitive data ever appears in git history, treat it as a security incident.

---

## Threat model (v0.1)
Assume:
- hosts fail; disks corrupt
- networks are hostile by default
- operators make mistakes

We are not trying to solve nation-state adversaries in v0.1.

So v0.1 optimizes for:
- **tamper evidence**: signatures + hashes
- **confidentiality at rest**: encryption
- **portability**: bundles you can carry to a new host

---

## Design overview

### Identity
- An agent has a stable **ed25519 signing keypair**.
- Public key is publishable.
- Private key stays local.

### Bundles
A bundle is an encrypted archive containing:
- a **payload** (files)
- a deterministic `manifest.json` (file list + sha256)
- a detached signature `manifest.sig`

Bundle contents are policy-driven.

### Not blockchain (but compatible)
Blockchains can be used as a public notary for:
- timestamps
- key delegations
- bundle hash attestations

They are not used to store private memory.

---

## Repository map

- `docs/Prometheus-Continuity-v0.1.md` — rationale + contract
- `docs/Prometheus-Continuity-v0.1-checklist.md` — operational checklist
- `docs/Prometheus-Bundle-Spec-v0.1.md` — bundle format spec
- `docs/ROADMAP.md` — what’s next (profiles, redaction, ops-state)
- `policy/export-allowlist.txt` — explicit export scope
- `tools/prometheus.py` — reference CLI (v0.1)

---

## Current status (v0.1)
Implemented:
- ✅ `init`: generate local signing key + age identity
- ✅ `export`: create signed+encrypted bundle (policy allowlist)
- ✅ `verify`: verify signature + hashes after decrypt
- ✅ `import`: verify then apply bundle payload into a target directory
- ✅ explicit export allowlist (`policy/export-allowlist.txt`)
- ✅ signing key rotation with delegation proof (`rotate-signing-key`)

Next:
- ⏳ `project` vs `agent` bundle profiles
- ⏳ leakage-first exports (derived/redacted exports for mixed files)
- ⏳ ops-state continuity schema (tasks/constraints/db snapshots)
- ⏳ migration drill playbook

---

## Quickstart

Prereqs: `age`, `age-keygen`, `ssh-keygen`

```bash
./tools/prometheus.py init
./tools/prometheus.py export
./tools/prometheus.py verify bundles/<bundle>.tar.age
```

### Default export policy
By default, `export` includes only public repo artifacts:
- `docs/`
- `README.md`
- `LICENSE`
- `.gitignore`

This is intentional to avoid leaking local/private state.

---

## Contributing / Safety rules
- Do not commit secrets.
- Do not commit personal memory.
- If you want to add new bundle payload paths, do it via an explicit policy mechanism (planned).

---

## License
MIT
