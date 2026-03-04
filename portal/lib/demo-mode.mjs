/*
Copyright (c) 2026 NyxeraLabs
Author: Jose Maria Micoli
Licensed under BSL 1.1
Change Date: 2033-02-17 -> Apache-2.0
*/

import { getSpectraStrikeUrl } from './cross-app-links.mjs';

export const SPECTRA_ONBOARDED_KEY = 'spectrastrike_onboarded';
export const VECTORVUE_ONBOARDED_KEY = 'vectorvue_onboarded';
export const NYXERA_DEMO_SESSION_KEY = 'nyxera_demo_session';

export const VECTORVUE_DEMO_STEPS = [
  'welcome',
  'execution_list_intro',
  'open_execution',
  'signature_validation',
  'attestation_review',
  'policy_status',
  'export_report',
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

export function shouldStartTenantPortalDemo(storage) {
  return storage.getItem(VECTORVUE_ONBOARDED_KEY) !== 'true';
}

export function nextVectorVueDemoStep(current) {
  const idx = VECTORVUE_DEMO_STEPS.indexOf(current);
  if (idx < 0 || idx + 1 >= VECTORVUE_DEMO_STEPS.length) return VECTORVUE_DEMO_STEPS[VECTORVUE_DEMO_STEPS.length - 1];
  return VECTORVUE_DEMO_STEPS[idx + 1];
}

export function writeUnifiedDemoSession(storage, payload) {
  const next = {
    source: String(payload?.source ?? 'vectorvue'),
    step: String(payload?.step ?? 'welcome'),
    updated_at: String(payload?.updated_at ?? new Date().toISOString())
  };
  storage.setItem(NYXERA_DEMO_SESSION_KEY, JSON.stringify(next));
  return next;
}

export function readUnifiedDemoSession(storage) {
  try {
    const raw = storage.getItem(NYXERA_DEMO_SESSION_KEY);
    if (!raw) return null;
    return JSON.parse(raw);
  } catch {
    return null;
  }
}
