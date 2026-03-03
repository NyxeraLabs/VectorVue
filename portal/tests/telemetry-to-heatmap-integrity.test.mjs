// Copyright (c) 2026 NyxeraLabs
// Licensed under BSL 1.1
// Change Date: 2033-02-22 -> Apache-2.0

import test from 'node:test';
import assert from 'node:assert/strict';

import { buildAttackHeatmap } from '../lib/intelligence-metrics.mjs';

test('telemetry-to-heatmap integrity preserves ATT&CK rows and bounded metrics', () => {
  const findings = [
    { id: 1, mitre_id: 'T1133', cvss_score: 8.4, status: 'open' },
    { id: 2, mitre_id: 'T1068', cvss_score: 9.1, status: 'in_progress' },
    { id: 3, mitre_id: 'T1021.002', cvss_score: 7.3, status: 'closed' },
    { id: 4, mitre_id: 'T1071', cvss_score: 5.6, status: 'verified' }
  ];
  const remediation = [
    { id: 7, status: 'in_progress' },
    { id: 8, status: 'closed' }
  ];

  const rows = buildAttackHeatmap(findings, remediation);

  assert.ok(rows.length >= 3);
  assert.ok(rows.some((row) => row.technique === 'T1133'));
  for (const row of rows) {
    assert.ok(row.coverage >= 0 && row.coverage <= 100);
    assert.ok(row.detection >= 0 && row.detection <= 100);
    assert.ok(row.response >= 0 && row.response <= 100);
    assert.ok(Number.isFinite(row.coverage));
    assert.ok(Number.isFinite(row.detection));
    assert.ok(Number.isFinite(row.response));
  }
});
