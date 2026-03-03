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
import { useSearchParams } from 'next/navigation';

import { Card } from '@/components/ui/card';
import { getSpectraStrikeUrl } from '@/lib/cross-app-links';
import { isDemoQuery, nextVectorVueDemoStep } from '@/lib/demo-mode';
import {
  buildNexusContext,
  buildSpectraStrikeDeepLink,
  canAccessNexusArea,
  decodeNexusContext,
  exportUnifiedValidationReport,
  mergeUnifiedActivities,
  searchUnifiedActivities
} from '@/lib/nexus-context';

type Activity = {
  source: 'spectrastrike' | 'vectorvue';
  type: 'execution' | 'detection' | 'assurance';
  title: string;
  detail: string;
  ts: string;
};

type ClientFinding = {
  id: number;
  title: string;
  severity?: string | null;
  status?: string | null;
};

type RemediationTask = {
  id: number;
  title: string;
  status: string;
};

type RiskSummary = {
  score?: number;
};

function downloadReport(content: string, filename: string): void {
  const blob = new Blob([content], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

export default function NexusPage() {
  const params = useSearchParams();
  const demoActive = isDemoQuery(params.toString());
  const parsed = decodeNexusContext(params.toString());
  const context = parsed ??
    buildNexusContext({
      tenantId: 'tenant-vectorvue',
      tenantName: 'VectorVue Tenant',
      role: 'analyst',
      campaignId: 'cmp-001',
      findingId: 'fnd-184'
    });

  const [query, setQuery] = useState('');
  const [selectedFinding, setSelectedFinding] = useState(context.findingId ?? 'fnd-184');
  const [demoStep, setDemoStep] = useState(
    'intro' as
      | 'intro'
      | 'envelope_intake'
      | 'signature_check'
      | 'attestation_verification'
      | 'measurement_hash'
      | 'policy_validation'
      | 'return_to_spectrastrike'
      | 'complete'
  );

  const [assurance, setAssurance] = useState({
    riskScore: 0,
    openTasks: 0,
    containmentRate: 0
  });
  const [feed, setFeed] = useState<Activity[]>([]);
  const [surfaceStatus, setSurfaceStatus] = useState('Loading live telemetry and remediation surfaces...');

  useEffect(() => {
    let active = true;
    Promise.all([
      fetch('/api/proxy/findings?page=1&page_size=20', { credentials: 'include', cache: 'no-store' }).then((res) => res.json()),
      fetch('/api/proxy/remediation', { credentials: 'include', cache: 'no-store' }).then((res) => res.json()),
      fetch('/api/proxy/risk', { credentials: 'include', cache: 'no-store' }).then((res) => res.json())
    ])
      .then(([findingsBody, remediationBody, riskBody]) => {
        if (!active) return;
        const findings: ClientFinding[] = Array.isArray(findingsBody?.items) ? findingsBody.items : [];
        const remediation: RemediationTask[] = Array.isArray(remediationBody?.items) ? remediationBody.items : [];
        const risk = (riskBody ?? {}) as RiskSummary;
        const openTasks = remediation.filter((task) => String(task.status).toLowerCase() !== 'done').length;
        const riskScore = Number(risk.score ?? 0);
        const containmentRate = remediation.length === 0
          ? 0
          : ((remediation.length - openTasks) / remediation.length) * 100;

        setAssurance({
          riskScore,
          openTasks,
          containmentRate
        });
        const nextFeed = mergeUnifiedActivities<Activity>([
          {
            source: 'spectrastrike',
            type: 'execution',
            title: 'Campaign execution branch',
            detail: `Campaign ${context.campaignId ?? 'n/a'} active with ${findings.length} telemetry-linked findings`,
            ts: new Date().toISOString()
          },
          ...findings.slice(0, 6).map((finding): Activity => ({
            source: 'vectorvue',
            type: 'detection',
            title: `Detection ${finding.id}: ${finding.title}`,
            detail: `${String(finding.status ?? 'open')} severity=${String(finding.severity ?? 'n/a')}`,
            ts: new Date().toISOString()
          })),
          {
            source: 'vectorvue',
            type: 'assurance',
            title: 'Assurance score recalculated',
            detail: `Risk ${riskScore.toFixed(2)} with containment ${containmentRate.toFixed(1)}%`,
            ts: new Date().toISOString()
          }
        ]);
        setFeed(nextFeed);
        setSurfaceStatus('Live telemetry and remediation surfaces loaded.');
      })
      .catch(() => {
        if (!active) return;
        setFeed([]);
        setAssurance({ riskScore: 0, openTasks: 0, containmentRate: 0 });
        setSurfaceStatus('Unable to load live telemetry surfaces.');
      });
    return () => {
      active = false;
    };
  }, [context.campaignId]);

  const filtered = useMemo(() => searchUnifiedActivities(feed, query), [feed, query]);

  const spectraUrl = useMemo(() => {
    const base = getSpectraStrikeUrl();
    const relay = buildNexusContext({
      tenantId: context.tenantId,
      tenantName: context.tenantName,
      role: context.role,
      campaignId: context.campaignId,
      findingId: selectedFinding,
      ts: context.ts
    });
    return buildSpectraStrikeDeepLink(base, relay);
  }, [context, selectedFinding]);

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Nexus Mode</h1>
      <p className="text-sm text-muted">
        Unified navigation and state synchronization between SpectraStrike execution and VectorVue detection assurance.
      </p>

      {demoActive ? (
        <Card>
          <h2 className="mb-2 text-sm font-semibold">VectorVue Guided Demo</h2>
          <p className="text-sm text-text-secondary">Current step: <span className="font-mono">{demoStep}</span></p>
          <div className="mt-3 flex flex-wrap gap-2">
            <button
              type="button"
              className="rounded border border-[color:var(--vv-border-subtle)] px-3 py-2 text-sm hover:border-accent"
              onClick={() => setDemoStep((current) => nextVectorVueDemoStep(current))}
            >
              Next Step
            </button>
            <a href="/portal/validation?demo=true&source=nexus" className="rounded border border-[color:var(--vv-border-subtle)] px-3 py-2 text-sm hover:border-accent">
              Validate in VectorVue
            </a>
          </div>
        </Card>
      ) : null}

      <div className="grid gap-4 xl:grid-cols-2">
        <Card>
          <h2 className="mb-2 text-sm font-semibold">Unified Navigation Shell</h2>
          <div className="grid gap-2 md:grid-cols-2">
            <a href={spectraUrl} className="rounded border border-[color:var(--vv-border-subtle)] px-3 py-2 text-sm hover:border-accent">
              Open SpectraStrike Nexus
            </a>
            <a href="/portal/analytics" className="rounded border border-[color:var(--vv-border-subtle)] px-3 py-2 text-sm hover:border-accent">
              Open VectorVue Analytics
            </a>
            <a href="/portal/risk" className="rounded border border-[color:var(--vv-border-subtle)] px-3 py-2 text-sm hover:border-accent">
              Open Risk Console
            </a>
            <a href="/portal/findings" className="rounded border border-[color:var(--vv-border-subtle)] px-3 py-2 text-sm hover:border-accent">
              Open Findings
            </a>
          </div>
        </Card>

        <Card>
          <h2 className="mb-2 text-sm font-semibold">Shared Authentication & RBAC Layer</h2>
          <p className="text-sm text-muted">Effective role: {context.role}</p>
          <ul className="mt-2 grid gap-2 text-sm sm:grid-cols-2">
            <li>Execution: {canAccessNexusArea(context.role, 'execution') ? 'allowed' : 'restricted'}</li>
            <li>Detection: {canAccessNexusArea(context.role, 'detection') ? 'allowed' : 'restricted'}</li>
            <li>Assurance: {canAccessNexusArea(context.role, 'assurance') ? 'allowed' : 'restricted'}</li>
            <li>Export: {canAccessNexusArea(context.role, 'export') ? 'allowed' : 'restricted'}</li>
          </ul>
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card>
          <h2 className="mb-2 text-sm font-semibold">Unified Activity Feed</h2>
          <p className="mb-2 text-xs text-text-secondary">{surfaceStatus}</p>
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search campaign, detection, assurance"
            className="w-full rounded border border-[color:var(--vv-border-subtle)] bg-bg-primary px-3 py-2 text-sm"
          />
          <ol className="mt-3 space-y-2" data-testid="vv-nexus-feed">
            {filtered.map((item) => (
              <li key={`${item.source}-${item.ts}-${item.title}`} className="rounded border border-[color:var(--vv-border-subtle)] px-3 py-2 text-sm">
                <span className="text-xs uppercase tracking-wide text-text-secondary">[{item.source}/{item.type}]</span> {item.title}
                <p className="mt-1 text-xs text-text-secondary">{item.detail}</p>
              </li>
            ))}
            {filtered.length === 0 ? (
              <li className="rounded border border-[color:var(--vv-border-subtle)] px-3 py-2 text-sm text-text-secondary">
                No live telemetry records available.
              </li>
            ) : null}
          </ol>
        </Card>

        <Card>
          <h2 className="mb-2 text-sm font-semibold">Campaign → Detection → Assurance Drill-Down</h2>
          <div className="space-y-3 text-sm">
            <p>Campaign: <strong>{context.campaignId ?? 'n/a'}</strong></p>
            <label className="block">
              Detection Finding ID
              <input
                value={selectedFinding}
                onChange={(event) => setSelectedFinding(event.target.value)}
                className="mt-1 w-full rounded border border-[color:var(--vv-border-subtle)] bg-bg-primary px-3 py-2"
              />
            </label>
            <p>Assurance Risk Score: <strong>{assurance.riskScore.toFixed(2)}</strong></p>
            <p>Containment Rate: <strong>{assurance.containmentRate.toFixed(1)}%</strong></p>
          </div>
        </Card>
      </div>

      {canAccessNexusArea(context.role, 'export') ? (
        <Card>
          <h2 className="mb-2 text-sm font-semibold">Export Unified Validation Report</h2>
          <button
            type="button"
            className="rounded border border-[color:var(--vv-border-subtle)] px-3 py-2 text-sm hover:border-accent"
            onClick={() =>
              downloadReport(
                exportUnifiedValidationReport(context, filtered, assurance),
                `nexus-validation-${context.tenantId}-${new Date().toISOString().slice(0, 10)}.md`
              )
            }
          >
            Export Report
          </button>
        </Card>
      ) : null}
    </div>
  );
}
