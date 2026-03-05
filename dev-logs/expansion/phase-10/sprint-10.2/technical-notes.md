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
