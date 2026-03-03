/*
Copyright (c) 2026 NyxeraLabs
Author: José María Micoli
Licensed under BSL 1.1
Change Date: 2033-02-17 -> Apache-2.0
*/

const CONTROL_FAMILIES = ['EDR', 'XDR', 'NGFW', 'AV'];

function numeric(value, fallback = 0) {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function normalizeTechniqueId(raw) {
  if (typeof raw !== 'string' || !raw.trim()) return 'UNKNOWN';
  const s = raw.trim().toUpperCase();
  const match = s.match(/^T\d{4}(?:\.\d{3})?$/);
  return match ? match[0] : 'UNKNOWN';
}

function doneStatus(status) {
  const s = String(status ?? '').toLowerCase();
  return s.includes('done') || s.includes('complete') || s.includes('closed') || s.includes('verified');
}

function openStatus(status) {
  const s = String(status ?? '').toLowerCase();
  return s.includes('open') || s.includes('new') || s.includes('todo') || s.includes('progress') || s.length === 0;
}

export function buildAttackHeatmap(findings = [], remediation = []) {
  const techniqueMap = new Map();
  findings.forEach((finding) => {
    const technique = normalizeTechniqueId(finding.mitre_id);
    if (technique === 'UNKNOWN') return;
    const prev = techniqueMap.get(technique) ?? { findingCount: 0, severityWeight: 0, responseSignals: 0 };
    prev.findingCount += 1;
    prev.severityWeight += Math.max(0, Math.min(10, numeric(finding.cvss_score, 0)));
    if (doneStatus(finding.status)) prev.responseSignals += 1;
    techniqueMap.set(technique, prev);
  });

  const taskDone = remediation.filter((row) => doneStatus(row.status)).length;
  const taskTotal = remediation.length || 1;
  const responseFactor = taskDone / taskTotal;

  const rows = [...techniqueMap.entries()]
    .sort((a, b) => b[1].findingCount - a[1].findingCount)
    .slice(0, 12)
    .map(([technique, stats]) => {
      const baseCoverage = Math.max(0.15, 1 - stats.findingCount / Math.max(3, findings.length || 1));
      const detection = Math.max(0.1, 1 - stats.severityWeight / (stats.findingCount * 12));
      const response = Math.max(0.05, Math.min(1, (stats.responseSignals / stats.findingCount) * 0.65 + responseFactor * 0.35));
      return {
        technique,
        coverage: Number((baseCoverage * 100).toFixed(1)),
        detection: Number((detection * 100).toFixed(1)),
        response: Number((response * 100).toFixed(1))
      };
    });

  return rows.length > 0
    ? rows
    : [{ technique: 'T0000', coverage: 0, detection: 0, response: 0 }];
}

export function buildTechniqueConfidenceSeries(heatmapRows = []) {
  return heatmapRows.map((row) => {
    const confidence = Math.min(100, Math.max(0, row.coverage * 0.35 + row.detection * 0.4 + row.response * 0.25));
    return {
      technique: row.technique,
      confidence: Number(confidence.toFixed(1)),
      label: confidence >= 75 ? 'high' : confidence >= 50 ? 'medium' : 'low'
    };
  });
}

export function buildDetectionLatencyTimeline(findings = []) {
  return findings
    .slice(0, 24)
    .map((finding, idx) => {
      const severity = numeric(finding.cvss_score, 0);
      const latencyMins = Math.max(3, Math.round((11 - Math.min(severity, 10)) * 7 + (idx % 4) * 4));
      return {
        index: idx + 1,
        findingId: finding.id ?? idx + 1,
        technique: normalizeTechniqueId(finding.mitre_id),
        latencyMins
      };
    })
    .reverse();
}

export function buildFalseNegativeDashboard(findings = []) {
  const bins = {
    critical: { total: 0, potentialFalseNegatives: 0 },
    high: { total: 0, potentialFalseNegatives: 0 },
    medium: { total: 0, potentialFalseNegatives: 0 },
    low: { total: 0, potentialFalseNegatives: 0 }
  };

  findings.forEach((finding) => {
    const cvss = numeric(finding.cvss_score, 0);
    const bucket = cvss >= 9 ? 'critical' : cvss >= 7 ? 'high' : cvss >= 4 ? 'medium' : 'low';
    bins[bucket].total += 1;
    if (openStatus(finding.status) && cvss >= 7) bins[bucket].potentialFalseNegatives += 1;
  });

  return Object.entries(bins).map(([severity, stats]) => ({
    severity,
    total: stats.total,
    potentialFalseNegatives: stats.potentialFalseNegatives,
    ratio: stats.total === 0 ? 0 : Number(((stats.potentialFalseNegatives / stats.total) * 100).toFixed(1))
  }));
}

export function buildControlValidationMatrix(findings = []) {
  return CONTROL_FAMILIES.map((control, idx) => {
    const linked = findings.filter((finding) => {
      const code = normalizeTechniqueId(finding.mitre_id);
      if (code === 'UNKNOWN') return false;
      return (Number(code.replace(/\D/g, '')) + idx) % CONTROL_FAMILIES.length === idx;
    });
    const validated = linked.filter((finding) => doneStatus(finding.status)).length;
    const failed = linked.filter((finding) => openStatus(finding.status)).length;
    const score = linked.length === 0 ? 0 : Number(((validated / linked.length) * 100).toFixed(1));
    return { control, mappedTechniques: linked.length, validated, failed, score };
  });
}

export function buildSocPerformance(remediation = [], latencyTimeline = []) {
  const totalLatency = latencyTimeline.reduce((sum, point) => sum + numeric(point.latencyMins, 0), 0);
  const mttd = latencyTimeline.length === 0 ? 0 : Number((totalLatency / latencyTimeline.length).toFixed(1));

  const remCount = remediation.length || 1;
  const completed = remediation.filter((row) => doneStatus(row.status)).length;
  const inProgress = remediation.filter((row) => String(row.status ?? '').toLowerCase().includes('progress')).length;

  const mttr = Number((Math.max(30, (remCount - completed) * 12 + inProgress * 8) / 10).toFixed(1));
  const containmentRate = Number(((completed / remCount) * 100).toFixed(1));

  return { mttd, mttr, containmentRate };
}

export function buildTelemetryCompleteness(findings = []) {
  const requiredFields = ['id', 'title', 'severity', 'status', 'cvss_score', 'mitre_id'];
  const total = findings.length || 1;
  return requiredFields.map((field) => {
    const populated = findings.filter((finding) => {
      const value = finding[field];
      return value !== null && value !== undefined && String(value).trim() !== '';
    }).length;
    const percent = Number(((populated / total) * 100).toFixed(1));
    return { field, populated, total: findings.length, percent };
  });
}

export function buildAnomalyVisualization(anomalyInsight, findings = []) {
  const base = numeric(anomalyInsight?.score, 0);
  const confidence = numeric(anomalyInsight?.confidence, 0);
  const points = findings.slice(0, 20).map((finding, idx) => {
    const noise = (numeric(finding.cvss_score, 0) / 10) * 0.45;
    const drift = Math.max(0, Math.min(1, base * 0.55 + confidence * 0.25 + noise + (idx % 3) * 0.04));
    return { point: idx + 1, drift: Number((drift * 100).toFixed(1)) };
  });
  return points.length > 0 ? points : [{ point: 1, drift: Number((base * 100).toFixed(1)) }];
}

export function buildEvidenceLifecycle(findings = [], remediation = []) {
  const discovered = findings.length;
  const triaged = findings.filter((row) => !openStatus(row.status)).length;
  const inResponse = remediation.filter((row) => String(row.status ?? '').toLowerCase().includes('progress')).length;
  const contained = remediation.filter((row) => doneStatus(row.status)).length;
  return [
    { stage: 'Discovered', total: discovered },
    { stage: 'Triaged', total: triaged },
    { stage: 'In Response', total: inResponse },
    { stage: 'Contained', total: contained }
  ];
}

export function buildDashboardRenderSlices(findings = [], remediation = [], maxRows = 240) {
  const rowLimit = Math.max(10, Math.min(5000, numeric(maxRows, 240)));
  const sortedFindings = [...findings].sort((a, b) => numeric(b.id, 0) - numeric(a.id, 0));
  const sortedRemediation = [...remediation].sort((a, b) => numeric(b.id, 0) - numeric(a.id, 0));

  return {
    findings: sortedFindings.slice(0, rowLimit),
    remediation: sortedRemediation.slice(0, rowLimit)
  };
}
