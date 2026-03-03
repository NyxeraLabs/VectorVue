// Copyright (c) 2026 NyxeraLabs
// Licensed under BSL 1.1
// Change Date: 2033-02-22 -> Apache-2.0

export type HeatmapRow = {
  technique: string;
  coverage: number;
  detection: number;
  response: number;
};

export type ConfidenceRow = {
  technique: string;
  confidence: number;
  label: 'high' | 'medium' | 'low';
};

export declare function buildAttackHeatmap(findings?: Array<Record<string, unknown>>, remediation?: Array<Record<string, unknown>>): HeatmapRow[];
export declare function buildTechniqueConfidenceSeries(heatmapRows?: HeatmapRow[]): ConfidenceRow[];
export declare function buildDetectionLatencyTimeline(findings?: Array<Record<string, unknown>>): Array<{ index: number; findingId: number; technique: string; latencyMins: number }>;
export declare function buildFalseNegativeDashboard(findings?: Array<Record<string, unknown>>): Array<{ severity: string; total: number; potentialFalseNegatives: number; ratio: number }>;
export declare function buildControlValidationMatrix(findings?: Array<Record<string, unknown>>): Array<{ control: string; mappedTechniques: number; validated: number; failed: number; score: number }>;
export declare function buildSocPerformance(remediation?: Array<Record<string, unknown>>, latencyTimeline?: Array<Record<string, unknown>>): { mttd: number; mttr: number; containmentRate: number };
export declare function buildTelemetryCompleteness(findings?: Array<Record<string, unknown>>): Array<{ field: string; populated: number; total: number; percent: number }>;
export declare function buildAnomalyVisualization(anomalyInsight?: Record<string, unknown>, findings?: Array<Record<string, unknown>>): Array<{ point: number; drift: number }>;
export declare function buildEvidenceLifecycle(findings?: Array<Record<string, unknown>>, remediation?: Array<Record<string, unknown>>): Array<{ stage: string; total: number }>;
export declare function buildDashboardRenderSlices(findings?: Array<Record<string, unknown>>, remediation?: Array<Record<string, unknown>>, maxRows?: number): {
  findings: Array<Record<string, unknown>>;
  remediation: Array<Record<string, unknown>>;
};
