# UI Decisions - Phase 9 Sprint 9.1 (Incremental)

## Decision 1: Demo TUI Must Survive Read-Only Home Environments
- Assisted demo state storage now falls back to writable paths automatically.
- Rationale: containers and restricted runtimes can mount `/home/*` as read-only.

## Decision 2: Resolved State Location Must Be Visible to Operator
- `--demo-reset` output now shows the real state file path used.
- Rationale: improves troubleshooting and avoids path ambiguity.
