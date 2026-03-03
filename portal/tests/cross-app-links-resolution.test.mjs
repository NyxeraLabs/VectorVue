// Copyright (c) 2026 NyxeraLabs
// Licensed under BSL 1.1
// Change Date: 2033-02-22 -> Apache-2.0

import test from 'node:test';
import assert from 'node:assert/strict';

import { getNexusUrl, getSpectraStrikeUrl, getVectorVueUrl } from '../lib/cross-app-links.mjs';

test('cross app link helpers resolve VITE env values first', () => {
  process.env.VITE_NEXUS_URL = 'https://nexus.test';
  process.env.VITE_VECTORVUE_URL = 'https://vectorvue.test';
  process.env.VITE_SPECTRASTRIKE_URL = 'https://spectrastrike.test';

  assert.equal(getNexusUrl(), 'https://nexus.test');
  assert.equal(getVectorVueUrl(), 'https://vectorvue.test');
  assert.equal(getSpectraStrikeUrl(), 'https://spectrastrike.test');

  delete process.env.VITE_NEXUS_URL;
  delete process.env.VITE_VECTORVUE_URL;
  delete process.env.VITE_SPECTRASTRIKE_URL;
});

test('cross app link helpers fall back and warn when env is missing', () => {
  const calls = [];
  const originalWarn = console.warn;
  console.warn = (msg) => calls.push(String(msg));

  assert.equal(getNexusUrl(), 'http://localhost:3001');
  assert.equal(getVectorVueUrl(), 'http://localhost:3002');
  assert.equal(getSpectraStrikeUrl(), 'http://localhost:3000');
  assert.equal(calls.length, 3);

  console.warn = originalWarn;
});
