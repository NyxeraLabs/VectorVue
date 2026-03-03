import test from 'node:test';
import assert from 'node:assert/strict';

import {
  buildNexusContext,
  buildSpectraStrikeDeepLink,
  canAccessNexusArea,
  decodeNexusContext,
  encodeNexusContext
} from '../lib/nexus-context.mjs';

test('cross-module state synchronization keeps context stable across deep links', () => {
  const context = buildNexusContext({
    tenantId: 'tenant-001',
    tenantName: 'Acme Corp',
    role: 'auditor',
    campaignId: 'cmp-42',
    findingId: 'f-9001',
    ts: '2026-03-03T14:00:00Z'
  });

  const encoded = encodeNexusContext(context);
  const decoded = decodeNexusContext(encoded);
  assert.deepEqual(decoded, context);

  const link = buildSpectraStrikeDeepLink('https://spectrastrike.local', context);
  assert.ok(link.includes('/ui/dashboard/nexus?'));
  assert.ok(link.includes('tenant_id=tenant-001'));
  assert.equal(canAccessNexusArea('auditor', 'export'), true);
  assert.equal(canAccessNexusArea('operator', 'export'), false);
});
