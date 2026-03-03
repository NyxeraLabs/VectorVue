/*
Copyright (c) 2026 NyxeraLabs
Author: José María Micoli
Licensed under BSL 1.1
Change Date: 2033-02-17 -> Apache-2.0
*/

export const ROLE_LABELS = {
  red_team: 'Red Team',
  blue_team: 'Blue Team',
  exec: 'Exec',
  auditor: 'Auditor'
};

export function nextTheme(theme) {
  return theme === 'dark' ? 'light' : 'dark';
}

export function applyTheme(theme) {
  if (typeof document === 'undefined') return;
  document.documentElement.setAttribute('data-theme', theme === 'light' ? 'light' : 'dark');
}

export function roleCanExport(role) {
  return role === 'auditor' || role === 'exec';
}

export function roleAllowsPowerMode(role) {
  return role === 'red_team' || role === 'blue_team' || role === 'exec';
}

export function keyboardShortcutTarget(key, altPressed) {
  if (!altPressed) return null;
  if (key === '1') return '/portal/overview';
  if (key === '2') return '/portal/analytics';
  if (key === '3') return '/portal/nexus';
  if (key === '4') return '/portal/risk';
  return null;
}

export function parseWorkspaceState(raw) {
  const fallback = {
    theme: 'dark',
    role: 'blue_team',
    powerMode: false,
    lastPath: '/portal/overview'
  };

  if (!raw) return fallback;
  try {
    const parsed = JSON.parse(raw);
    const role = Object.hasOwn(ROLE_LABELS, parsed.role) ? parsed.role : fallback.role;
    const theme = parsed.theme === 'light' ? 'light' : 'dark';
    const powerMode = parsed.powerMode === true;
    const lastPath = typeof parsed.lastPath === 'string' && parsed.lastPath.startsWith('/') ? parsed.lastPath : fallback.lastPath;
    return { theme, role, powerMode, lastPath };
  } catch {
    return fallback;
  }
}

export function encodeWorkspaceState(state) {
  return JSON.stringify(state);
}

export function reduceRenderBudget(items, limit) {
  const bounded = Math.max(10, Math.min(1200, Number(limit) || 120));
  return items.slice(0, bounded);
}

export function accessibilityChecklist() {
  return [
    { id: 'focus-visible', status: 'pass' },
    { id: 'keyboard-shortcuts', status: 'pass' },
    { id: 'aria-live-notifications', status: 'pass' },
    { id: 'color-contrast', status: 'pass' }
  ];
}
