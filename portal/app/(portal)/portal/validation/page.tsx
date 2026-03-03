/*
Copyright (c) 2026 NyxeraLabs
Author: Jose Maria Micoli
Licensed under BSL 1.1
Change Date: 2033-02-17 -> Apache-2.0
*/

'use client';

import { useMemo, useState } from 'react';
import { useSearchParams } from 'next/navigation';

import { Card } from '@/components/ui/card';
import { buildSpectraReturnUrl, isDemoQuery, nextVectorVueDemoStep } from '@/lib/demo-mode.mjs';

const demoEnvelope = {
  envelope_id: 'env-demo-001',
  signature_state: 'verified',
  attestation_hash: 'sha256:17e53fcbf9ce38a3f7b1bbd0427ad9fd',
  measurement_hash: 'sha256:5f742ed52d1fe2447027f8d16f6ab003',
  policy_validation: 'pass',
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

  const returnUrl = useMemo(() => buildSpectraReturnUrl(), []);

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
        <pre className="overflow-x-auto rounded border border-[color:var(--vv-border-subtle)] bg-bg-primary p-3 text-xs">
{JSON.stringify(demoEnvelope, null, 2)}
        </pre>
      </Card>

      <Card>
        <h2 className="mb-2 text-sm font-semibold">Verification Breakdown</h2>
        <ul className="space-y-2 text-sm">
          <li>Envelope intake: {demoEnvelope.envelope_id}</li>
          <li>Signature check: {demoEnvelope.signature_state}</li>
          <li>Attestation verification: {demoEnvelope.attestation_hash}</li>
          <li>Measurement hash binding: {demoEnvelope.measurement_hash}</li>
          <li>Policy validation: {demoEnvelope.policy_validation}</li>
        </ul>
        <p className="mt-3 rounded border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-300">
          Execution Verified
        </p>
      </Card>
    </div>
  );
}
