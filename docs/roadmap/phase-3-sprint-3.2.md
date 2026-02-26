# Phase 3 Sprint 3.2 - Sanitization and Isolation

## Objective
Sanitize telemetry content and enforce strict tenant mapping using signed metadata.

## Deliverables
- HTML/JS escaping in canonical string fields.
- Injection pattern blocking for suspicious payload text.
- Strict signed metadata model for tenant/operator/campaign mapping.
- Operator-to-tenant policy enforcement before queue publish.
- Security tests for sanitization and tenant-boundary enforcement.

## Exit Criteria
- Cross-tenant mapping attempts are rejected.
- Metadata mismatch attempts are rejected.
- Injection-like text is rejected.
- Valid payload strings are safely sanitized before queue publish.
