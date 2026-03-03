// Copyright (c) 2026 NyxeraLabs
// Licensed under BSL 1.1
// Change Date: 2033-02-22 -> Apache-2.0

import test from 'node:test';
import assert from 'node:assert/strict';

import { buildSpectraReturnUrl, isDemoQuery, nextVectorVueDemoStep, shouldStartSpectraDemo } from '../lib/demo-mode.mjs';

test('demo-mode query parsing', () => {
  assert.equal(isDemoQuery('?demo=true&source=nexus'), true);
  assert.equal(isDemoQuery('?source=nexus'), false);
});

test('demo-mode builds explicit return url', () => {
  const url = buildSpectraReturnUrl();
  assert.ok(url.includes('/ui/dashboard'));
  assert.ok(url.includes('source=vectorvue'));
});

test('spectra onboarding guard', () => {
  assert.equal(shouldStartSpectraDemo({ getItem: () => null }), true);
  assert.equal(shouldStartSpectraDemo({ getItem: () => 'true' }), false);
});

test('vectorvue demo step machine advances deterministically', () => {
  assert.equal(nextVectorVueDemoStep('intro'), 'envelope_intake');
  assert.equal(nextVectorVueDemoStep('return_to_spectrastrike'), 'complete');
  assert.equal(nextVectorVueDemoStep('complete'), 'complete');
});
