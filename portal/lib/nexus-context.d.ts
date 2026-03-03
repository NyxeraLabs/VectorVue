export type NexusRole = 'operator' | 'analyst' | 'auditor' | 'admin';
export type NexusArea = 'execution' | 'detection' | 'assurance' | 'export';

export type NexusContext = {
  v: '1';
  tenantId: string;
  tenantName: string;
  role: NexusRole;
  campaignId?: string;
  findingId?: string;
  ts: string;
};

export declare function canAccessNexusArea(role: NexusRole, area: NexusArea): boolean;
export declare function buildNexusContext(input: Omit<NexusContext, 'v' | 'ts'> & { ts?: string }): NexusContext;
export declare function encodeNexusContext(context: NexusContext): string;
export declare function decodeNexusContext(search: string): NexusContext | null;
export declare function buildSpectraStrikeDeepLink(baseUrl: string, context: NexusContext): string;
export declare function mergeUnifiedActivities<T extends { ts: string }>(items: T[]): T[];
export declare function searchUnifiedActivities<T extends { title: string; detail: string; type: string; source: string }>(items: T[], query: string): T[];
export declare function exportUnifiedValidationReport(
  context: NexusContext,
  activities: Array<{ source: string; type: string; title: string; detail: string; ts: string }>,
  assurance: { riskScore: number; openTasks: number; containmentRate: number }
): string;
