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
  request_id: 'n/a',
  event_uid: 'n/a',
  signature_state: 'unknown',
  attestation_hash: 'n/a',
  measurement_hash: 'n/a',
  policy_validation: 'unknown'
};

export default function ValidationPage() {
  const params = useSearchParams();
  const demoActive = isDemoQuery(params.toString());
  const [step, setStep] = useState(
    'welcome' as
      | 'welcome'
      | 'execution_list_intro'
      | 'open_execution'
      | 'signature_validation'
      | 'attestation_review'
      | 'policy_status'
      | 'export_report'
      | 'complete'
  );
  const [envelope, setEnvelope] = useState(emptyEnvelope);
  const [statusLine, setStatusLine] = useState('Loading federation validation artifacts...');

  const returnUrl = useMemo(() => buildSpectraReturnUrl(), []);

  useEffect(() => {
    let active = true;
    fetch('/api/proxy/federation/timeline?limit=1', { credentials: 'include', cache: 'no-store' })
      .then((res) => res.json())
      .then((body) => {
        if (!active) return;
        const event = Array.isArray(body?.events) ? body.events[0] : null;
        if (!event || !event.event_uid) {
          setEnvelope(emptyEnvelope);
          setStatusLine('No federation envelope available for validation walkthrough.');
          return;
        }
        setEnvelope({
          envelope_id: String(event.envelope_id ?? event.event_uid ?? 'n/a'),
          request_id: String(event.request_id ?? 'n/a'),
          event_uid: String(event.event_uid ?? 'n/a'),
          signature_state: String(event.signature_state ?? 'unknown'),
          attestation_hash: String(event.attestation_measurement_hash ?? 'n/a'),
          measurement_hash: String(event.metadata?.execution_fingerprint ?? event.event_uid ?? 'n/a'),
          policy_validation: String(event.policy_decision_hash ?? 'unknown')
        });
        setStatusLine('Live SpectraStrike federation envelope loaded.');
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
              onClick={() =>
                setStep((current) => {
                  const next = nextVectorVueDemoStep(current);
                  void fetch('/api/proxy/demo/session', {
                    method: 'PUT',
                    credentials: 'include',
                    headers: { 'content-type': 'application/json' },
                    body: JSON.stringify({
                      source: 'vectorvue-validation',
                      step: next,
                      payload: { route: 'portal/validation' }
                    })
                  });
                  return next;
                })
              }
            >
              Next Demo Step
            </button>
            {(step === 'export_report' || step === 'complete') ? (
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
          <li>Request: {envelope.request_id}</li>
          <li>Event: {envelope.event_uid}</li>
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
