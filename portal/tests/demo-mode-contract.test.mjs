// Copyright (c) 2026 NyxeraLabs
// Licensed under BSL 1.1
// Change Date: 2033-02-22 -> Apache-2.0

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  buildSpectraReturnUrl,
  isDemoQuery,
  nextVectorVueDemoStep,
  readUnifiedDemoSession,
  shouldStartSpectraDemo,
  shouldStartTenantPortalDemo,
  writeUnifiedDemoSession,
} from '../lib/demo-mode.mjs';

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
  assert.equal(nextVectorVueDemoStep('welcome'), 'execution_list_intro');
  assert.equal(nextVectorVueDemoStep('export_report'), 'complete');
  assert.equal(nextVectorVueDemoStep('complete'), 'complete');
});

test('tenant portal onboarding guard', () => {
  assert.equal(shouldStartTenantPortalDemo({ getItem: () => null }), true);
  assert.equal(shouldStartTenantPortalDemo({ getItem: () => 'true' }), false);
});

test('unified demo session read and write contracts', () => {
  const store = {
    _value: '',
    setItem(_k, value) {
      this._value = value;
    },
    getItem() {
      return this._value || null;
    },
  };
  writeUnifiedDemoSession(store, { source: 'vectorvue', step: 'policy_status', updated_at: '2026-03-04T00:00:00.000Z' });
  const session = readUnifiedDemoSession(store);
  assert.equal(session.source, 'vectorvue');
  assert.equal(session.step, 'policy_status');
});
