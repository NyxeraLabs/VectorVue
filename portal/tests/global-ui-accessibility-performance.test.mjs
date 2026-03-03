// Copyright (c) 2026 NyxeraLabs
// Licensed under BSL 1.1
// Change Date: 2033-02-22 -> Apache-2.0

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  accessibilityChecklist,
  keyboardShortcutTarget,
  reduceRenderBudget,
  roleCanExport
} from '../lib/global-ui.mjs';

test('global UI accessibility profile and role-based rendering defaults', () => {
  const checks = accessibilityChecklist();
  assert.ok(checks.length >= 4);
  assert.ok(checks.every((item) => item.status === 'pass'));

  assert.equal(keyboardShortcutTarget('1', true), '/portal/overview');
  assert.equal(keyboardShortcutTarget('3', true), '/portal/nexus');
  assert.equal(keyboardShortcutTarget('3', false), null);

  assert.equal(roleCanExport('auditor'), true);
  assert.equal(roleCanExport('blue_team'), false);
});

test('rendering budget benchmark remains bounded under large UI queues', () => {
  const rows = Array.from({ length: 5000 }, (_v, idx) => ({ id: idx + 1 }));
  const started = Date.now();
  const reduced = reduceRenderBudget(rows, 260);
  const elapsed = Date.now() - started;

  assert.equal(reduced.length, 260);
  assert.ok(elapsed < 300);
});
