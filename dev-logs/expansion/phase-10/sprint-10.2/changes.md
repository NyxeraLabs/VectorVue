# Changes

## Scope
Critical cross-platform seed parity fix so VectorVue TUI + tenant portal consume the same seeded federation records emitted by SpectraStrike demo seed.

## Implemented
- `scripts/seed_db.py`
  - Added SpectraStrike seed-contract loader.
  - Added federation mirror seeding into `spectrastrike_ingest_requests`, `spectrastrike_events`, `spectrastrike_findings`.
- `vv_client_api.py`
  - Added `GET /api/v1/client/federation/timeline` for tenant-scoped federation events/findings.
- `portal`
  - Added proxy route: `/api/proxy/federation/timeline`.
  - Validation page now reads live federation timeline artifacts instead of synthetic finding-derived placeholders.
- `app/demo_tui.py`
  - Replaced synthetic envelope (`env-demo-0001`) with latest real seeded federation envelope lookup.
  - Signature/attestation/policy steps now display real metadata when available.

## Outcome
VectorVue runtime surfaces real seeded federation records aligned with SpectraStrike seed output.
