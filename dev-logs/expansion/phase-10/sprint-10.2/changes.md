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

## 2026-03-05 Addendum
- Enhanced `seed_spectrastrike_federation_data` to mirror seeded SpectraStrike events into client-facing `findings` records.
- Event-backed findings now include canonical campaign tags from federation metadata (`[campaign:OP_*_2026]`).
- Result in latest run:
  - `spectrastrike_events`: 12 per tenant
  - `spectrastrike_findings`: 12 per tenant
  - Client findings now include telemetry-event entries with matching campaign IDs.
- Remediation tracker accuracy upgrade:
  - seeded federated events/findings now generate campaign-tagged remediation tasks (`Contain and validate...` / `Investigate and remediate...`) linked to imported findings.
- Local federation DNS support:
  - `local_federation/federation-compose.override.yml` adds `vectorvue.local` alias on nginx service network for secure cross-stack sync.

## 2026-03-05 Final Addendum
- Theme quality pass:
  - Updated portal dark/light design tokens for cleaner contrast and more consistent visual language.
- Demo-seed evidence parity upgrade:
  - `seed_spectrastrike_federation_data` now seeds evidence artifacts for imported federation findings/events.
  - Added timeline-like evidence activity rows in `activity_log` per seeded artifact.
- CI/workflow reliability updates:
  - relaxed invalid hard pins in `requirements.txt` (`aiosqlite`, `certifi`, `cryptography`).
  - workflow portal test step now executes `npm run test:unit --if-present`.
  - portal `lint` script set to non-interactive CI-safe command.
