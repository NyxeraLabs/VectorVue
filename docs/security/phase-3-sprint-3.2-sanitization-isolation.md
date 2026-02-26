# Phase 3 Sprint 3.2 - Sanitization and Isolation

## Threat Model
- Asset: tenant-scoped telemetry integrity and processing trust boundaries.
- Adversary: attacker injecting HTML/JS or SQL-like payload fragments, cross-tenant event forger.
- Trust boundary: signed telemetry ingest before queue publish.

## Attack Vectors Considered
- HTML/JS content injection in descriptive telemetry fields.
- SQL-like injection markers in canonical payload text values.
- Operator claiming another tenant context in request envelope.
- Signed metadata mismatch between identity fields and payload mapping.

## Mitigations Implemented
- Canonical payload sanitization now escapes HTML/JS characters for string fields.
- Injection-pattern blocking rejects SQL-like attack markers.
- Strict signed metadata model enforces tenant/operator/campaign identity tuple.
- Explicit operator-to-tenant mapping (`VV_TG_OPERATOR_TENANT_MAP`) blocks cross-tenant claims.
- Violations are rejected before queue publish; schema failures route to DLQ.

## Residual Risk
- Mapping table is environment-configured and requires disciplined change control.
- Sanitization is rule-based and should evolve with threat intel.

## Future Improvements
- Move operator-tenant mapping to signed control-plane config source.
- Add centralized policy engine for text sanitization and deny-list updates.
