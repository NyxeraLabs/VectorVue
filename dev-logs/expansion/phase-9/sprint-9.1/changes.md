# Changes - Phase 9 Sprint 9.1

## File-by-file changes
- `portal/lib/intelligence-metrics.d.ts`
- `portal/lib/nexus-context.d.ts`
- `portal/tests/dashboard-rendering-performance.test.mjs`
- `portal/tests/global-ui-accessibility-performance.test.mjs`
- `portal/tests/nexus-state-synchronization.test.mjs`
- `portal/tests/telemetry-to-heatmap-integrity.test.mjs`
- `tests/unit/test_phase3_sprint31_control_modeling.py`
- `tests/unit/test_phase3_sprint32_soc_ir_readiness.py`
- `tests/unit/test_phase4_sprint41_asset_discovery.py`
- `tests/unit/test_phase4_sprint42_exposure_intelligence.py`
- `tests/unit/test_phase4_sprint43_asm_adversary_bridge.py`
- `tests/unit/test_phase6_sprint61_coverage_analytics.py`
- `tests/unit/test_phase6_sprint62_compliance_reporting.py`
- `tests/unit/test_phase7_sprint72_behavioral_ml.py`
  - Added required license-header markers for CI enforcement compatibility.

- `Makefile`
  - Added explicit UI URL output at the end of `local-federation-up`.

- `portal/lib/intelligence-metrics.mjs.d.ts`
- `portal/lib/nexus-context.mjs.d.ts`
  - Added declaration bridge files for `.mjs` imports referenced by TSX pages.

## Reason for each change
- Remove workflow failures from license-header gate without changing runtime behavior.
- Improve startup ergonomics and resolve CI type-check failure on extension-based module imports.
