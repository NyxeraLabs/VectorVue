# Technical Notes

- Added importer path argument in `seed_db.py`:
  - `--spectrastrike-seed-contract` (default `/opt/vectorvue/local_federation/seed/spectrastrike_seed_contract.json`).
- Import logic creates federation tables if absent and upserts request/event/finding records by tenant.
- API response model for federation timeline returns:
  - event envelope metadata (`envelope_id`, `signature_state`, `attestation_measurement_hash`, `policy_decision_hash`)
  - associated finding summaries.
- TUI fallback behavior:
  - if no federation rows exist, assisted demo still runs with explicit empty-context messaging.
- New parity behavior:
  - Every imported SpectraStrike seeded event can materialize as a tenant-scoped client finding with deterministic evidence hash.
  - Campaign tag extraction uses `metadata_json.campaign_id` to preserve cross-platform campaign naming.
- Remediation seeding behavior:
  - Federation event findings create `remediation_tasks` with status derived from severity (`open` for high/critical, otherwise `in_progress`).
  - Federation findings also create campaign-tagged remediation tasks linked to corresponding imported finding IDs.

## 2026-03-05 Final Addendum
- Federation seed evidence implementation details:
  - Added `_seed_finding_evidence(...)` helper in `scripts/seed_db.py`.
  - Inserts approved artifacts (`log`, `json`, `timeline`) into `evidence_items` with deterministic hashes.
  - Inserts matching `activity_log` entries with `action_type=EVIDENCE_INGESTED` and federation context JSON.
  - Campaign FK resolution for evidence uses tenant campaign lookup by imported campaign tag when available.
- CI behavior:
  - `ci.yml` and `release.yml` now use `npm run test:unit --if-present` for portal validation.
