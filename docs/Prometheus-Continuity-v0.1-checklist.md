# Prometheus — Continuity Track (v0.1) — Checklist

This is the operational companion to `Prometheus-Continuity-v0.1.md`.

## A) Decisions (need explicit answers)
- [ ] **Shareability policy (default):** what is public/shareable vs private by default?
- [ ] **Key custody:** who holds encryption keys? (M only / agent only / split)
- [ ] **Failure preference:** lose recent state vs risk leakage?
- [ ] **Jurisdiction + intent:** what does “economic independence” legally mean here?

## B) Identity primitive
- [ ] Generate signing keypair (ed25519)
- [ ] Store public key as stable identifier (publishable)
- [ ] Store private key securely (never committed)
- [ ] Key rotation rule documented (signed delegation old→new)

## C) Memory bundle format
- [ ] Define bundle directory layout
- [ ] Define `manifest.json` schema
  - [ ] bundle_version
  - [ ] created_at
  - [ ] file list + sha256
  - [ ] optional metadata (host, runtime version)
- [ ] Define signing format (`manifest.sig`)
- [ ] Define encryption format (age/gpg/zip+aes) and key handling

## D) Export / Import workflows
- [ ] Export script:
  - [ ] collect allowed files
  - [ ] generate manifest + hashes
  - [ ] sign manifest
  - [ ] encrypt bundle
- [ ] Verify script:
  - [ ] decrypt
  - [ ] verify signature
  - [ ] verify hashes
- [ ] Import script:
  - [ ] place files in correct locations
  - [ ] refuse import if verification fails

## E) Migration drill
- [ ] Provision second runtime target (VM/container)
- [ ] Install OpenClaw (or compatible runtime)
- [ ] Import keys + bundle
- [ ] Verify identity continuity (same public key)
- [ ] Run a simple task to confirm state restored

## F) Hardening
- [ ] Backup schedule (at least daily encrypted bundle)
- [ ] Rotation schedule (keys/tokens)
- [ ] Rollback plan (keep N previous bundles)
- [ ] Policy guardrails:
  - [ ] never export/share protected files by default
  - [ ] explicit approval before external posting of private content

## G) Definition of “done” for v0.1
- [ ] Bundles can be exported + verified + imported end-to-end
- [ ] Migration drill completed successfully at least once
- [ ] Rollback tested
- [ ] Documentation: how to recover from a dead host
