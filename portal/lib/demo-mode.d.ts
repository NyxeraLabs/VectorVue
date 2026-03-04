// Copyright (c) 2026 NyxeraLabs
// Licensed under BSL 1.1
// Change Date: 2033-02-22 -> Apache-2.0

export declare const SPECTRA_ONBOARDED_KEY: 'spectrastrike_onboarded';
export declare const VECTORVUE_ONBOARDED_KEY: 'vectorvue_onboarded';
export declare const NYXERA_DEMO_SESSION_KEY: 'nyxera_demo_session';
export declare const VECTORVUE_DEMO_STEPS: readonly [
  'welcome',
  'execution_list_intro',
  'open_execution',
  'signature_validation',
  'attestation_review',
  'policy_status',
  'export_report',
  'complete'
];
export declare function isDemoQuery(search: string): boolean;
export declare function buildSpectraReturnUrl(): string;
export declare function shouldStartSpectraDemo(storage: Pick<Storage, 'getItem'>): boolean;
export declare function shouldStartTenantPortalDemo(storage: Pick<Storage, 'getItem'>): boolean;
export declare function nextVectorVueDemoStep(current: (typeof VECTORVUE_DEMO_STEPS)[number]): (typeof VECTORVUE_DEMO_STEPS)[number];
export declare function writeUnifiedDemoSession(
  storage: Pick<Storage, 'setItem'>,
  payload: { source?: string; step?: string; updated_at?: string }
): { source: string; step: string; updated_at: string };
export declare function readUnifiedDemoSession(storage: Pick<Storage, 'getItem'>): Record<string, unknown> | null;
