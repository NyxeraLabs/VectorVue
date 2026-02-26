# Phase 8 Sprint 8.1 - Security Gates in Pipeline

## Objective
Enforce non-bypassable CI/CD security gates that fail closed on telemetry hardening regressions.

## Deliverables
- Security enforcement GitHub Actions workflow.
- SAST stage using `bandit`.
- Dependency vulnerability scanning using `pip-audit`.
- Security policy gate script for mTLS/signature/tenant guard enforcement.
- Unit test coverage for policy gate behavior.

## Exit Criteria
- Pipeline fails when telemetry mTLS is disabled.
- Pipeline fails when payload signature enforcement is disabled.
- Pipeline fails when security regression tests fail.
- Pipeline passes only when security gates remain intact.
