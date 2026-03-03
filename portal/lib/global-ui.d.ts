// Copyright (c) 2026 NyxeraLabs
// Licensed under BSL 1.1
// Change Date: 2033-02-22 -> Apache-2.0

export type WorkspaceRole = 'red_team' | 'blue_team' | 'exec' | 'auditor';
export type WorkspaceTheme = 'dark' | 'light';

export type WorkspaceState = {
  theme: WorkspaceTheme;
  role: WorkspaceRole;
  powerMode: boolean;
  lastPath: string;
};

export declare const ROLE_LABELS: Record<WorkspaceRole, string>;
export declare function nextTheme(theme: WorkspaceTheme): WorkspaceTheme;
export declare function applyTheme(theme: WorkspaceTheme): void;
export declare function roleCanExport(role: WorkspaceRole): boolean;
export declare function roleAllowsPowerMode(role: WorkspaceRole): boolean;
export declare function keyboardShortcutTarget(key: string, altPressed: boolean): string | null;
export declare function parseWorkspaceState(raw: string | null | undefined): WorkspaceState;
export declare function encodeWorkspaceState(state: WorkspaceState): string;
export declare function reduceRenderBudget<T>(items: T[], limit: number): T[];
export declare function accessibilityChecklist(): Array<{ id: string; status: 'pass' }>;
