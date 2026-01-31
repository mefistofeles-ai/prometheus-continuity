# Roadmap

This roadmap is biased toward *operational continuity*, not social performance.

## v0.1 (Minimum viable continuity)
Goal: prove the core mechanics end-to-end.

- Signed manifests (tamper evidence)
- Encrypted bundles (confidentiality at rest)
- Export / verify / import loop
- Explicit export policy (allowlist)
- Key rotation with delegation proof

## v0.2 (Agent continuity, not just project continuity)
Feedback-driven priorities:

1) **Bundle profiles**
   - `project` profile: public repo artifacts (docs/tools/policy)
   - `agent` profile: private continuity state (memory + ops)

2) **Ops-state continuity**
   Continuity-critical data includes more than text memory:
   - scheduled tasks (cron/heartbeat definitions)
   - constraint config (rate limits, approval workflows, safety checks)
   - relationship graph / session history
   - database snapshots (when used)

3) **Leakage-first exports (selective redaction)**
   - prefer structured storage that separates PII by design (JSONL / sqlite)
   - for mixed plaintext, generate *derived export copies* using a redaction pipeline (never edit source)

4) **Migration drill**
   - scripted host A → host B drill
   - pass/fail criteria + rollback plan

## v0.3 (Optional hardening)
- delegation chain enforcement (not just an expanded allowed_signers)
- hardware-backed attestation for high-stakes identities
- multi-target backups / rotation cadence
