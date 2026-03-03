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

  assert.equal(getNexusUrl(), 'https://127.0.0.1:18443');
  assert.equal(getVectorVueUrl(), 'https://127.0.0.1');
  assert.equal(getSpectraStrikeUrl(), 'https://127.0.0.1:18443');
  assert.equal(calls.length, 3);

  console.warn = originalWarn;
});

test('cross app link helpers upgrade insecure env urls to https', () => {
  const calls = [];
  const originalWarn = console.warn;
  console.warn = (msg) => calls.push(String(msg));

  process.env.VITE_NEXUS_URL = 'http://nexus.test';
  process.env.VITE_VECTORVUE_URL = 'http://vectorvue.test';
  process.env.VITE_SPECTRASTRIKE_URL = 'http://spectrastrike.test';

  assert.equal(getNexusUrl(), 'https://nexus.test');
  assert.equal(getVectorVueUrl(), 'https://vectorvue.test');
  assert.equal(getSpectraStrikeUrl(), 'https://spectrastrike.test');
  assert.equal(calls.length, 3);

  delete process.env.VITE_NEXUS_URL;
  delete process.env.VITE_VECTORVUE_URL;
  delete process.env.VITE_SPECTRASTRIKE_URL;
  console.warn = originalWarn;
});
