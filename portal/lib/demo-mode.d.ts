// Copyright (c) 2026 NyxeraLabs
// Licensed under BSL 1.1
// Change Date: 2033-02-22 -> Apache-2.0

export declare const SPECTRA_ONBOARDED_KEY: 'spectrastrike_onboarded';
export declare const VECTORVUE_DEMO_STEPS: readonly [
  'intro',
  'envelope_intake',
  'signature_check',
  'attestation_verification',
  'measurement_hash',
  'policy_validation',
  'return_to_spectrastrike',
  'complete'
];
export declare function isDemoQuery(search: string): boolean;
export declare function buildSpectraReturnUrl(): string;
export declare function shouldStartSpectraDemo(storage: Pick<Storage, 'getItem'>): boolean;
export declare function nextVectorVueDemoStep(current: (typeof VECTORVUE_DEMO_STEPS)[number]): (typeof VECTORVUE_DEMO_STEPS)[number];
