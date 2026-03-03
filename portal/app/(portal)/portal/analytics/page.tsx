/*
Copyright (c) 2026 NyxeraLabs
Author: José María Micoli
Licensed under BSL 1.1
Change Date: 2033-02-17 → Apache-2.0

You may:
✔ Study
✔ Modify
✔ Use for internal security testing

You may NOT:
✘ Offer as a commercial service
✘ Sell derived competing products
*/

'use client';

import { useEffect, useMemo, useState } from 'react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from 'recharts';

import { Card } from '@/components/ui/card';
import {
  buildAnomalyVisualization,
  buildAttackHeatmap,
  buildControlValidationMatrix,
  buildDashboardRenderSlices,
  buildDetectionLatencyTimeline,
  buildEvidenceLifecycle,
  buildFalseNegativeDashboard,
  buildSocPerformance,
  buildTelemetryCompleteness,
  buildTechniqueConfidenceSeries
} from '@/lib/intelligence-metrics';
import { trackDashboardView } from '@/lib/telemetry';
import type { ClientFinding, ClientMLInsight, Paginated, RemediationTask } from '@/lib/types';
import { brandTheme } from '@/styles/theme';

type RemediationResponse = { items: RemediationTask[] };

const FALLBACK_ML: ClientMLInsight = {
  score: 0,
  confidence: 0,
  explanation: 'Model output is being generated.',
  model_version: 'pending',
  generated_at: new Date(0).toISOString()
};

function heatCell(value: number): string {
  if (value >= 80) return 'bg-emerald-500/30';
  if (value >= 60) return 'bg-cyan-500/30';
  if (value >= 40) return 'bg-amber-500/30';
  return 'bg-red-500/30';
}

export default function AnalyticsPage() {
  const [findings, setFindings] = useState<ClientFinding[]>([]);
  const [remediation, setRemediation] = useState<RemediationTask[]>([]);
  const [anomalies, setAnomalies] = useState<ClientMLInsight>(FALLBACK_ML);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedTechnique, setSelectedTechnique] = useState<string | null>(null);

  useEffect(() => {
    trackDashboardView('analytics');
  }, []);

  useEffect(() => {
    let active = true;

    async function run() {
      try {
        setLoading(true);
        const [findingsRes, remediationRes, anomaliesRes] = await Promise.all([
          fetch('/api/proxy/findings?page=1&page_size=2000', { credentials: 'include', cache: 'no-store' }),
          fetch('/api/proxy/remediation', { credentials: 'include', cache: 'no-store' }),
          fetch('/api/proxy/ml/anomalies', { credentials: 'include', cache: 'no-store' })
        ]);

        if (!findingsRes.ok) throw new Error(`Findings API ${findingsRes.status}`);
        if (!remediationRes.ok) throw new Error(`Remediation API ${remediationRes.status}`);

        const findingsData = (await findingsRes.json()) as Paginated<ClientFinding>;
        const remediationData = (await remediationRes.json()) as RemediationResponse;
        const anomaliesData = anomaliesRes.ok ? ((await anomaliesRes.json()) as ClientMLInsight) : FALLBACK_ML;

        const slices = buildDashboardRenderSlices(findingsData.items ?? [], remediationData.items ?? [], 500);
        if (!active) return;
        setFindings(slices.findings as ClientFinding[]);
        setRemediation(slices.remediation as RemediationTask[]);
        setAnomalies(anomaliesData);
      } catch (err) {
        if (active) setError(err instanceof Error ? err.message : 'Failed to load analytics');
      } finally {
        if (active) setLoading(false);
      }
    }

    run();
    return () => {
      active = false;
    };
  }, []);

  const heatmap = useMemo(() => buildAttackHeatmap(findings, remediation), [findings, remediation]);
  const confidenceSeries = useMemo(() => buildTechniqueConfidenceSeries(heatmap), [heatmap]);
  const detectionLatency = useMemo(() => buildDetectionLatencyTimeline(findings), [findings]);
  const falseNegatives = useMemo(() => buildFalseNegativeDashboard(findings), [findings]);
  const controlMatrix = useMemo(() => buildControlValidationMatrix(findings), [findings]);
  const soc = useMemo(() => buildSocPerformance(remediation, detectionLatency), [remediation, detectionLatency]);
  const telemetryCompleteness = useMemo(() => buildTelemetryCompleteness(findings), [findings]);
  const anomalySeries = useMemo(() => buildAnomalyVisualization(anomalies, findings), [anomalies, findings]);
  const evidenceLifecycle = useMemo(() => buildEvidenceLifecycle(findings, remediation), [findings, remediation]);

  useEffect(() => {
    if (!selectedTechnique && heatmap.length > 0) {
      setSelectedTechnique(heatmap[0].technique);
    }
  }, [selectedTechnique, heatmap]);

  if (loading) return <p className="text-sm text-muted">Loading telemetry intelligence dashboards...</p>;
  if (error) return <p className="text-sm text-red-400">Unable to load analytics: {error}</p>;

  const selectedTechniqueRow = heatmap.find((row) => row.technique === selectedTechnique) ?? heatmap[0];

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Telemetry Intelligence & Detection Visualization</h1>
      <p className="text-sm text-muted">
        ATT&amp;CK-native analytics view combining detection quality, response behavior, telemetry completeness, and evidence lifecycle.
      </p>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card>
          <h2 className="mb-3 text-sm font-semibold">Interactive ATT&amp;CK Heatmap</h2>
          <div className="overflow-x-auto rounded-lg border border-[color:var(--vv-border-subtle)]">
            <table className="w-full min-w-[560px] text-sm">
              <thead className="bg-bg-primary/80 text-xs uppercase tracking-wide text-text-secondary">
                <tr>
                  <th className="px-3 py-2 text-left">Technique</th>
                  <th className="px-3 py-2 text-left">Coverage</th>
                  <th className="px-3 py-2 text-left">Detection</th>
                  <th className="px-3 py-2 text-left">Response</th>
                </tr>
              </thead>
              <tbody>
                {heatmap.map((row) => (
                  <tr key={row.technique} className="border-t border-[color:var(--vv-border-subtle)]">
                    <td className="px-3 py-2">
                      <button
                        type="button"
                        className="rounded border border-[color:var(--vv-border-subtle)] px-2 py-1 text-left hover:border-accent"
                        onClick={() => setSelectedTechnique(row.technique)}
                      >
                        {row.technique}
                      </button>
                    </td>
                    <td className={`px-3 py-2 ${heatCell(row.coverage)}`}>{row.coverage}%</td>
                    <td className={`px-3 py-2 ${heatCell(row.detection)}`}>{row.detection}%</td>
                    <td className={`px-3 py-2 ${heatCell(row.response)}`}>{row.response}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>

        <Card>
          <h2 className="mb-3 text-sm font-semibold">Technique Confidence Score Visualization</h2>
          <p className="mb-3 text-xs text-text-secondary">
            Selected technique: {selectedTechniqueRow.technique} | coverage {selectedTechniqueRow.coverage}% | detection {selectedTechniqueRow.detection}%
          </p>
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={confidenceSeries}>
                <CartesianGrid strokeDasharray="3 3" stroke={brandTheme.colors.borderSubtle} />
                <XAxis dataKey="technique" tick={{ fontSize: 11 }} />
                <YAxis domain={[0, 100]} tick={{ fontSize: 12 }} />
                <Tooltip />
                <Bar dataKey="confidence" radius={[4, 4, 0, 0]}>
                  {confidenceSeries.map((row) => (
                    <Cell
                      key={`confidence-${row.technique}`}
                      fill={row.label === 'high' ? '#00C896' : row.label === 'medium' ? '#FFB020' : '#FF4D4F'}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card>
          <h2 className="mb-3 text-sm font-semibold">Detection Latency Timeline Graph</h2>
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={detectionLatency}>
                <CartesianGrid strokeDasharray="3 3" stroke={brandTheme.colors.borderSubtle} />
                <XAxis dataKey="index" tick={{ fontSize: 12 }} />
                <YAxis dataKey="latencyMins" tick={{ fontSize: 12 }} />
                <Tooltip />
                <Line type="monotone" dataKey="latencyMins" stroke="#22d3ee" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </Card>

        <Card>
          <h2 className="mb-3 text-sm font-semibold">False Negative Analysis Dashboard</h2>
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={falseNegatives}>
                <CartesianGrid strokeDasharray="3 3" stroke={brandTheme.colors.borderSubtle} />
                <XAxis dataKey="severity" tick={{ fontSize: 12 }} />
                <YAxis tick={{ fontSize: 12 }} />
                <Tooltip />
                <Bar dataKey="total" fill="#8A2BE2" radius={[4, 4, 0, 0]} />
                <Bar dataKey="potentialFalseNegatives" fill="#FF4D4F" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card>
          <h2 className="mb-3 text-sm font-semibold">Control Validation Matrix (EDR/XDR/NGFW/AV)</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-xs uppercase tracking-wide text-text-secondary">
                <tr>
                  <th className="px-2 py-2 text-left">Control</th>
                  <th className="px-2 py-2 text-left">Mapped</th>
                  <th className="px-2 py-2 text-left">Validated</th>
                  <th className="px-2 py-2 text-left">Failed</th>
                  <th className="px-2 py-2 text-left">Score</th>
                </tr>
              </thead>
              <tbody>
                {controlMatrix.map((row) => (
                  <tr key={row.control} className="border-t border-[color:var(--vv-border-subtle)]">
                    <td className="px-2 py-2">{row.control}</td>
                    <td className="px-2 py-2">{row.mappedTechniques}</td>
                    <td className="px-2 py-2">{row.validated}</td>
                    <td className="px-2 py-2">{row.failed}</td>
                    <td className={`px-2 py-2 ${heatCell(row.score)}`}>{row.score}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>

        <Card>
          <h2 className="mb-3 text-sm font-semibold">SOC Performance Dashboard</h2>
          <div className="grid gap-3 md:grid-cols-3">
            <div className="rounded border border-[color:var(--vv-border-subtle)] px-3 py-3">
              <p className="text-xs uppercase tracking-wide text-text-secondary">MTTD</p>
              <p className="mt-2 text-2xl font-semibold">{soc.mttd}m</p>
            </div>
            <div className="rounded border border-[color:var(--vv-border-subtle)] px-3 py-3">
              <p className="text-xs uppercase tracking-wide text-text-secondary">MTTR</p>
              <p className="mt-2 text-2xl font-semibold">{soc.mttr}h</p>
            </div>
            <div className="rounded border border-[color:var(--vv-border-subtle)] px-3 py-3">
              <p className="text-xs uppercase tracking-wide text-text-secondary">Containment Rate</p>
              <p className="mt-2 text-2xl font-semibold">{soc.containmentRate}%</p>
            </div>
          </div>
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card>
          <h2 className="mb-3 text-sm font-semibold">Telemetry Field Completeness Dashboard</h2>
          <div className="space-y-2">
            {telemetryCompleteness.map((row) => (
              <div key={row.field} className="rounded border border-[color:var(--vv-border-subtle)] px-3 py-2">
                <div className="flex items-center justify-between text-sm">
                  <span className="font-medium">{row.field}</span>
                  <span className="text-text-secondary">{row.percent}%</span>
                </div>
                <div className="mt-2 h-2 w-full rounded bg-bg-primary/80">
                  <div className="h-2 rounded bg-cyan-500" style={{ width: `${row.percent}%` }} />
                </div>
              </div>
            ))}
          </div>
        </Card>

        <Card>
          <h2 className="mb-3 text-sm font-semibold">Anomaly &amp; Behavioral Analytics Visualization</h2>
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={anomalySeries}>
                <CartesianGrid strokeDasharray="3 3" stroke={brandTheme.colors.borderSubtle} />
                <XAxis dataKey="point" tick={{ fontSize: 12 }} />
                <YAxis domain={[0, 100]} tick={{ fontSize: 12 }} />
                <Tooltip />
                <Line type="monotone" dataKey="drift" stroke="#f59e0b" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
          <p className="mt-2 text-xs text-text-secondary">
            ML signal: {anomalies.score.toFixed(2)} | confidence: {anomalies.confidence.toFixed(2)} | model: {anomalies.model_version}
          </p>
        </Card>
      </div>

      <Card>
        <h2 className="mb-3 text-sm font-semibold">Evidence Lifecycle Tracking Interface</h2>
        <div className="grid gap-4 lg:grid-cols-2">
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={evidenceLifecycle} dataKey="total" nameKey="stage" outerRadius={90}>
                  <Cell fill="#22d3ee" />
                  <Cell fill="#8A2BE2" />
                  <Cell fill="#f59e0b" />
                  <Cell fill="#00C896" />
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <ol className="space-y-2">
            {evidenceLifecycle.map((row) => (
              <li key={row.stage} className="rounded border border-[color:var(--vv-border-subtle)] px-3 py-2 text-sm">
                <span className="font-medium">{row.stage}:</span> {row.total}
              </li>
            ))}
          </ol>
        </div>
      </Card>
    </div>
  );
}
