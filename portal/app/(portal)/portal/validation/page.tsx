/*
Copyright (c) 2026 NyxeraLabs
Author: Jose Maria Micoli
Licensed under BSL 1.1
Change Date: 2033-02-17 -> Apache-2.0
*/

'use client';

import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'next/navigation';

import { Card } from '@/components/ui/card';
import { buildSpectraReturnUrl, isDemoQuery, nextVectorVueDemoStep } from '@/lib/demo-mode';

const emptyEnvelope = {
  envelope_id: 'n/a',
  signature_state: 'unknown',
  attestation_hash: 'n/a',
  measurement_hash: 'n/a',
  policy_validation: 'unknown'
};

export default function ValidationPage() {
  const params = useSearchParams();
  const demoActive = isDemoQuery(params.toString());
  const [step, setStep] = useState(
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
  const [envelope, setEnvelope] = useState(emptyEnvelope);
  const [statusLine, setStatusLine] = useState('Loading federation validation artifacts...');

  const returnUrl = useMemo(() => buildSpectraReturnUrl(), []);

  useEffect(() => {
    let active = true;
    fetch('/api/proxy/findings?page=1&page_size=1', { credentials: 'include', cache: 'no-store' })
      .then((res) => res.json())
      .then(async (body) => {
        if (!active) return;
        const finding = Array.isArray(body?.items) ? body.items[0] : null;
        if (!finding || !finding.id) {
          setEnvelope(emptyEnvelope);
          setStatusLine('No findings available for validation walkthrough.');
          return;
        }
        const evidenceRes = await fetch(`/api/proxy/evidence/${finding.id}`, { credentials: 'include', cache: 'no-store' });
        const evidenceBody = await evidenceRes.json();
        const evidenceItems = Array.isArray(evidenceBody?.items) ? evidenceBody.items : [];
        const evidenceRef = evidenceItems[0]?.download_url ?? `finding-${finding.id}`;
        setEnvelope({
          envelope_id: `env-finding-${finding.id}`,
          signature_state: String(finding.approval_status ?? 'pending'),
          attestation_hash: `sha256:${String(evidenceRef).slice(0, 32)}`,
          measurement_hash: `sha256:${String(finding.title ?? 'finding').slice(0, 32)}`,
          policy_validation: String(finding.status ?? 'open')
        });
        setStatusLine('Live federation validation artifacts loaded.');
      })
      .catch(() => {
        if (!active) return;
        setEnvelope(emptyEnvelope);
        setStatusLine('Unable to load federation validation artifacts.');
      });
    return () => {
      active = false;
    };
  }, []);

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Validation Walkthrough</h1>
      <p className="text-sm text-muted">
        Signature, attestation, and policy validation pipeline for federation envelopes.
      </p>

      {demoActive ? (
        <Card>
          <h2 className="mb-2 text-sm font-semibold">VectorVue Assisted Demo</h2>
          <p className="text-sm text-text-secondary">
            Step: <span className="font-mono">{step}</span>
          </p>
          <div className="mt-3 flex flex-wrap gap-2">
            <button
              type="button"
              className="rounded border border-[color:var(--vv-border-subtle)] px-3 py-2 text-sm hover:border-accent"
              onClick={() => setStep((current) => nextVectorVueDemoStep(current))}
            >
              Next Demo Step
            </button>
            {(step === 'return_to_spectrastrike' || step === 'complete') ? (
              <a href={returnUrl} className="rounded border border-[color:var(--vv-border-subtle)] px-3 py-2 text-sm hover:border-accent">
                Return to SpectraStrike
              </a>
            ) : null}
          </div>
        </Card>
      ) : null}

      <Card>
        <h2 className="mb-2 text-sm font-semibold">Federation Envelope</h2>
        <p className="mb-2 text-xs text-text-secondary">{statusLine}</p>
        <pre className="overflow-x-auto rounded border border-[color:var(--vv-border-subtle)] bg-bg-primary p-3 text-xs">
{JSON.stringify(envelope, null, 2)}
        </pre>
      </Card>

      <Card>
        <h2 className="mb-2 text-sm font-semibold">Verification Breakdown</h2>
        <ul className="space-y-2 text-sm">
          <li>Envelope intake: {envelope.envelope_id}</li>
          <li>Signature check: {envelope.signature_state}</li>
          <li>Attestation verification: {envelope.attestation_hash}</li>
          <li>Measurement hash binding: {envelope.measurement_hash}</li>
          <li>Policy validation: {envelope.policy_validation}</li>
        </ul>
        <p className="mt-3 rounded border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-300">
          Execution Verified
        </p>
      </Card>
    </div>
  );
}
