// Copyright (c) 2026 NyxeraLabs
// Licensed under BSL 1.1
// Change Date: 2033-02-22 -> Apache-2.0

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  buildAnomalyVisualization,
  buildDashboardRenderSlices,
  buildDetectionLatencyTimeline,
  buildTelemetryCompleteness
} from '../lib/intelligence-metrics.mjs';

test('dashboard rendering model scales for large datasets', () => {
  const findings = Array.from({ length: 6000 }, (_v, idx) => ({
    id: idx + 1,
    title: `Finding ${idx + 1}`,
    severity: idx % 4 === 0 ? 'critical' : 'high',
    status: idx % 5 === 0 ? 'closed' : 'open',
    cvss_score: (idx % 10) + 0.5,
    mitre_id: idx % 2 === 0 ? 'T1133' : 'T1071'
  }));
  const remediation = Array.from({ length: 2500 }, (_v, idx) => ({
    id: idx + 1,
    status: idx % 3 === 0 ? 'in_progress' : 'closed'
  }));

  const started = Date.now();
  const slices = buildDashboardRenderSlices(findings, remediation, 400);
  const latency = buildDetectionLatencyTimeline(slices.findings);
  const completeness = buildTelemetryCompleteness(slices.findings);
  const anomaly = buildAnomalyVisualization({ score: 0.71, confidence: 0.67 }, slices.findings);
  const elapsedMs = Date.now() - started;

  assert.equal(slices.findings.length, 400);
  assert.equal(slices.remediation.length, 400);
  assert.ok(latency.length > 0 && latency.length <= 24);
  assert.equal(completeness.length, 6);
  assert.ok(anomaly.length > 0);
  assert.ok(elapsedMs < 1500);
});
