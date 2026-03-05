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
  NYXERA_DEMO_SESSION_KEY,
  VECTORVUE_ONBOARDED_KEY,
  nextVectorVueDemoStep,
  shouldStartTenantPortalDemo,
} from '@/lib/demo-mode';

const STEPS = [
  'welcome',
  'execution_list_intro',
  'open_execution',
  'signature_validation',
  'attestation_review',
  'policy_status',
  'export_report',
  'complete'
] as const;

type BootstrapStatus = {
  users: number;
  tenants: number;
  keys: number;
  wrapper_configured: number;
  federation_configured: number;
  ingest_requests: number;
  is_db_zero: boolean;
  platform_onboarded: boolean;
  federation_endpoint?: string | null;
  federation_key_fingerprint?: string | null;
  federation_connectivity_ok: boolean;
  federation_signature_test_passed: boolean;
};

async function getBootstrapStatus(): Promise<BootstrapStatus | null> {
  try {
    const res = await fetch('/api/proxy/bootstrap/status', { credentials: 'include', cache: 'no-store' });
    if (!res.ok) return null;
    return (await res.json()) as BootstrapStatus;
  } catch {
    return null;
  }
}

async function loadDemoSession(): Promise<{ step: string } | null> {
  try {
    const res = await fetch('/api/proxy/demo/session', { credentials: 'include', cache: 'no-store' });
    if (!res.ok) return null;
    return (await res.json()) as { step: string };
  } catch {
    return null;
  }
}

async function saveDemoSession(step: string): Promise<void> {
  await fetch('/api/proxy/demo/session', {
    method: 'PUT',
    credentials: 'include',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      source: 'vectorvue-portal',
      step,
      payload: { updated_via: 'tenant-demo-onboarding' }
    })
  }).catch(() => undefined);
}

export function TenantDemoOnboarding() {
  const [open, setOpen] = useState(false);
  const [step, setStep] = useState<(typeof STEPS)[number]>('welcome');
  const [bootstrap, setBootstrap] = useState<BootstrapStatus | null>(null);

  useEffect(() => {
    let active = true;
    (async () => {
      const [status, session] = await Promise.all([getBootstrapStatus(), loadDemoSession()]);
      if (!active) return;
      if (status) setBootstrap(status);

      const startByLocal = shouldStartTenantPortalDemo(window.localStorage);
      const startByBackend = status ? status.platform_onboarded === false || status.is_db_zero : false;
      if (startByLocal || startByBackend) {
        setOpen(true);
      }

      if (session && typeof session.step === 'string' && STEPS.includes(session.step as (typeof STEPS)[number])) {
        setStep(session.step as (typeof STEPS)[number]);
        return;
      }

      const raw = window.localStorage.getItem(NYXERA_DEMO_SESSION_KEY);
      if (!raw) return;
      try {
        const parsed = JSON.parse(raw);
        if (typeof parsed?.step === 'string' && STEPS.includes(parsed.step)) {
          setStep(parsed.step);
        }
      } catch {
        // ignore invalid JSON
      }
    })();
    return () => {
      active = false;
    };
  }, []);

  const progress = useMemo(() => {
    const index = STEPS.indexOf(step);
    return Math.max(0, Math.round(((index + 1) / STEPS.length) * 100));
  }, [step]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" data-testid="tenant-portal-onboarding">
      <div className="w-full max-w-2xl rounded-lg border border-[color:var(--vv-border-subtle)] bg-bg-secondary p-5">
        <h2 className="text-lg font-semibold">Tenant Portal Guided Demo</h2>
        <p className="mt-2 text-sm text-text-secondary">
          Step: <span className="font-mono">{step}</span>
        </p>
        <div className="mt-2 text-xs text-text-secondary">
          Federation: endpoint={bootstrap?.federation_endpoint ?? 'n/a'} connectivity={bootstrap?.federation_connectivity_ok ? 'ok' : 'pending'} signature={bootstrap?.federation_signature_test_passed ? 'verified' : 'pending'}
        </div>
        <div className="mt-3 h-2 rounded bg-bg-primary">
          <div className="h-2 rounded bg-accent" style={{ width: `${progress}%` }} />
        </div>
        <p className="mt-2 text-xs text-text-secondary">Progress: {progress}%</p>
        <div className="mt-4 flex flex-wrap gap-2">
          <button
            type="button"
            className="rounded border border-[color:var(--vv-border-subtle)] px-3 py-2 text-sm hover:border-accent"
            onClick={async () => {
              const next = nextVectorVueDemoStep(step);
              setStep(next);
              window.localStorage.setItem(
                NYXERA_DEMO_SESSION_KEY,
                JSON.stringify({ source: 'vectorvue-portal', step: next, updated_at: new Date().toISOString() })
              );
              await saveDemoSession(next);
              if (next === 'complete') {
                window.localStorage.setItem(VECTORVUE_ONBOARDED_KEY, 'true');
              }
            }}
          >
            Continue
          </button>
          <button
            type="button"
            className="rounded border border-[color:var(--vv-border-subtle)] px-3 py-2 text-sm hover:border-accent"
            onClick={() => {
              window.localStorage.setItem(VECTORVUE_ONBOARDED_KEY, 'true');
              setOpen(false);
            }}
          >
            Skip Demo
          </button>
          <button
            type="button"
            className="rounded border border-[color:var(--vv-border-subtle)] px-3 py-2 text-sm hover:border-accent"
            onClick={async () => {
              await fetch('/api/proxy/bootstrap/reset?purge_federation_ingest=true', {
                method: 'POST',
                credentials: 'include',
              }).catch(() => undefined);
              await fetch('/api/proxy/demo/session', { method: 'DELETE', credentials: 'include' }).catch(() => undefined);
              window.localStorage.removeItem(VECTORVUE_ONBOARDED_KEY);
              window.localStorage.removeItem(NYXERA_DEMO_SESSION_KEY);
              setStep('welcome');
            }}
          >
            Demo Reset
          </button>
        </div>
      </div>
    </div>
  );
}
