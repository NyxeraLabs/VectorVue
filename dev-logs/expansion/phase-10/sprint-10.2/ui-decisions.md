# UI Decisions

- Validation page now prioritizes tenant-scoped federation timeline data as source of truth.
- Envelope panel expanded to include `request_id` and `event_uid` for operator traceability.
- Kept demo interaction controls unchanged; only data source switched from synthetic placeholders to real seeded federation records.
- Client portal findings view compatibility decision: campaign parsing remains regex-based and accepts non-numeric campaign IDs so `OP_*_2026` tags render correctly.
- Remediation tracker now carries campaign-qualified task titles for federated entries to keep portal triage context aligned with SpectraStrike campaign views.

## 2026-03-05 Final Addendum
- Theme direction updated from violet-heavy to blue-steel accenting for better enterprise dashboard readability in both modes.
- Light mode preserves strong text contrast while reducing glare using softer background gradients.
- Evidence timeline in finding detail remains evidence-driven; seeding now guarantees non-empty, realistic evidence chronology for federated findings.
