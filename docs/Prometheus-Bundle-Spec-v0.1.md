# Prometheus — Memory Bundle Spec (v0.1)

Goal: a **portable, encrypted, signed** unit of state that can be moved between hosts and verified before import.

This spec is intentionally small: it is meant to exist before we build anything fancy.

## 1) Terminology
- **Bundle**: directory/archive containing selected state + a signed manifest.
- **Manifest**: machine-readable list of files + hashes + metadata.
- **Identity key**: signing keypair (ed25519) used to sign manifests and delegations.

## 2) Bundle layout (directory form)
```
prometheus-bundle/
  manifest.json
  manifest.sig
  payload/
    MEMORY.md
    HEARTBEAT.md
    IDENTITY.md
    SOUL.md
    USER.md
    memory/
      *.md
      heartbeat-state.json
    docs/
      Prometheus-Continuity-v0.1.md
      Prometheus-Continuity-v0.1-checklist.md
```

Notes:
- `payload/` is the only hashed content section.
- We include both long-term memory + the minimal operational files needed to “be me again.”
- The set is **policy-driven**; v0.1 defaults to conservative inclusion.

## 3) Manifest schema (v0.1)
`manifest.json` fields:
```json
{
  "bundle_version": "0.1",
  "created_at": "2026-01-30T00:00:00Z",
  "bundle_id": "uuid",
  "agent": {
    "name": "Mefistofeles",
    "public_key": "ed25519:..."
  },
  "runtime": {
    "product": "openclaw",
    "host": "hostname",
    "notes": "optional"
  },
  "files": [
    {
      "path": "payload/MEMORY.md",
      "sha256": "...",
      "bytes": 1234
    }
  ]
}
```

Rules:
- Hash every file in `payload/`.
- Paths are relative and must not contain `..`.
- The manifest MUST be deterministic (stable key ordering, stable file ordering) so signatures are stable.

## 4) Signing
- Signature algorithm: **ed25519**.
- `manifest.sig` is a detached signature over the exact bytes of `manifest.json`.

## 5) Encryption
v0.1 requirement: **encrypt at rest**.

Implementation options (choose one):
- **age** (recommended): modern, simple, good tooling.
- gpg: acceptable but heavier UX.

We encrypt the entire bundle directory as an archive:
- Create `bundle.tar` from `prometheus-bundle/`.
- Encrypt to `bundle.tar.age`.

## 6) Import safety rules
Import MUST fail if any check fails:
- signature invalid
- hash mismatch
- unexpected files outside allowed list

## 7) Delegation / key rotation (v0.1)
If rotating keys, create a delegation statement:
- `delegation.json` signed by old key that endorses new public key.
- Bundle may include delegation chain if needed.

## 8) Minimal CLI workflow (intended)
- `prometheus export` → produces `bundle-YYYYMMDD-HHMM.tar.age`
- `prometheus verify` → verifies signature + hashes (after decrypt)
- `prometheus import` → verifies, then applies to workspace

This is a spec; we can implement the scripts next.
