/*
Copyright (c) 2026 NyxeraLabs
Author: Jose Maria Micoli
Licensed under BSL 1.1
Change Date: 2033-02-17 -> Apache-2.0
*/

import { getSpectraStrikeUrl } from './cross-app-links.mjs';

export const SPECTRA_ONBOARDED_KEY = 'spectrastrike_onboarded';

export const VECTORVUE_DEMO_STEPS = [
  'intro',
  'envelope_intake',
  'signature_check',
  'attestation_verification',
  'measurement_hash',
  'policy_validation',
  'return_to_spectrastrike',
  'complete'
];

export function isDemoQuery(search) {
  const raw = String(search ?? '').startsWith('?') ? String(search).slice(1) : String(search ?? '');
  const params = new URLSearchParams(raw);
  return params.get('demo') === 'true';
}

export function buildSpectraReturnUrl() {
  const base = getSpectraStrikeUrl().replace(/\/$/, '');
  return `${base}/ui/dashboard?nexus_demo=complete&source=vectorvue`;
}

export function shouldStartSpectraDemo(storage) {
  return storage.getItem(SPECTRA_ONBOARDED_KEY) !== 'true';
}

export function nextVectorVueDemoStep(current) {
  const idx = VECTORVUE_DEMO_STEPS.indexOf(current);
  if (idx < 0 || idx + 1 >= VECTORVUE_DEMO_STEPS.length) return VECTORVUE_DEMO_STEPS[VECTORVUE_DEMO_STEPS.length - 1];
  return VECTORVUE_DEMO_STEPS[idx + 1];
}
