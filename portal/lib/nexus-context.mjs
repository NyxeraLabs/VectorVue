/*
Copyright (c) 2026 NyxeraLabs
Author: José María Micoli
Licensed under BSL 1.1
Change Date: 2033-02-17 -> Apache-2.0
*/

const ROLE_PERMISSIONS = {
  operator: ['execution', 'detection'],
  analyst: ['detection', 'assurance'],
  auditor: ['assurance', 'export'],
  admin: ['execution', 'detection', 'assurance', 'export']
};

function clean(value) {
  return String(value ?? '').trim();
}

export function canAccessNexusArea(role, area) {
  const permissions = ROLE_PERMISSIONS[role] ?? ROLE_PERMISSIONS.operator;
  return permissions.includes(area);
}

export function buildNexusContext(input) {
  return {
    v: '1',
    tenantId: clean(input.tenantId),
    tenantName: clean(input.tenantName),
    role: input.role,
    campaignId: clean(input.campaignId || '') || undefined,
    findingId: clean(input.findingId || '') || undefined,
    ts: input.ts || new Date().toISOString()
  };
}

export function encodeNexusContext(context) {
  const params = new URLSearchParams();
  params.set('nexus_v', context.v);
  params.set('tenant_id', context.tenantId);
  params.set('tenant_name', context.tenantName);
  params.set('role', context.role);
  params.set('ts', context.ts);
  if (context.campaignId) params.set('campaign_id', context.campaignId);
  if (context.findingId) params.set('finding_id', context.findingId);
  return params.toString();
}

export function decodeNexusContext(search) {
  const raw = search.startsWith('?') ? search.slice(1) : search;
  const params = new URLSearchParams(raw);

  const v = clean(params.get('nexus_v'));
  const tenantId = clean(params.get('tenant_id'));
  const tenantName = clean(params.get('tenant_name'));
  const role = clean(params.get('role'));
  const ts = clean(params.get('ts'));

  if (v !== '1') return null;
  if (!tenantId || !tenantName || !ts || !ROLE_PERMISSIONS[role]) return null;

  const campaignId = clean(params.get('campaign_id')) || undefined;
  const findingId = clean(params.get('finding_id')) || undefined;

  return {
    v: '1',
    tenantId,
    tenantName,
    role,
    campaignId,
    findingId,
    ts
  };
}

function joinUrl(base, path) {
  const left = clean(base).replace(/\/$/, '');
  const right = path.startsWith('/') ? path : `/${path}`;
  return `${left}${right}`;
}

export function buildSpectraStrikeDeepLink(baseUrl, context) {
  return `${joinUrl(baseUrl, '/ui/dashboard/nexus')}?${encodeNexusContext(context)}`;
}

export function mergeUnifiedActivities(items) {
  return [...items].sort((a, b) => Date.parse(b.ts) - Date.parse(a.ts));
}

export function searchUnifiedActivities(items, query) {
  const q = clean(query).toLowerCase();
  if (!q) return items;
  return items.filter((item) => `${item.title} ${item.detail} ${item.type} ${item.source}`.toLowerCase().includes(q));
}

export function exportUnifiedValidationReport(context, activities, assurance) {
  const lines = [
    '# Unified Validation Report',
    '',
    `- Tenant: ${context.tenantName} (${context.tenantId})`,
    `- Role: ${context.role}`,
    `- Campaign: ${context.campaignId ?? 'n/a'}`,
    `- Finding: ${context.findingId ?? 'n/a'}`,
    `- Generated: ${new Date().toISOString()}`,
    '',
    '## Assurance Snapshot',
    `- Risk Score: ${assurance.riskScore.toFixed(2)}`,
    `- Open Tasks: ${assurance.openTasks}`,
    `- Containment Rate: ${assurance.containmentRate.toFixed(1)}%`,
    '',
    '## Unified Activity Feed'
  ];

  activities.forEach((item) => {
    lines.push(`- [${item.source}/${item.type}] ${item.ts} :: ${item.title} :: ${item.detail}`);
  });

  return lines.join('\n');
}
