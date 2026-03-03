/*
Copyright (c) 2026 NyxeraLabs
Author: José María Micoli
Licensed under BSL 1.1
Change Date: 2033-02-17 → Apache-2.0

You may:
✔ Study
✔ Modify
✔ Use for internal security testing

You may NOT:
✘ Offer as a commercial service
✘ Sell derived competing products
*/

/* eslint-disable @next/next/no-img-element */
'use client';

import { useEffect, useMemo, useState } from 'react';

import { Button } from '@/components/ui/button';
import NotificationCenter from '@/components/NotificationCenter';
import { accessibilityChecklist, applyTheme, encodeWorkspaceState, keyboardShortcutTarget, nextTheme, parseWorkspaceState, reduceRenderBudget, ROLE_LABELS, roleAllowsPowerMode, roleCanExport } from '@/lib/global-ui';
import { type PortalLang, t } from '@/lib/i18n';
import type { ClientTheme } from '@/lib/types';
import TenantLogo from '@/components/TenantLogo';
import { BrandLogo } from '@/components/layout/brand-logo';

type TopbarProps = {
  tenantName: string;
  theme?: ClientTheme | null;
};

type PortalRole = 'red_team' | 'blue_team' | 'exec' | 'auditor';
type Notice = { id: string; text: string };

const workspaceKey = 'vv_workspace_state_v1';

export function Topbar({ tenantName, theme }: TopbarProps) {
  const [lang, setLang] = useState<PortalLang>('en');
  const [portalTheme, setPortalTheme] = useState<'dark' | 'light'>('dark');
  const [role, setRole] = useState<PortalRole>('blue_team');
  const [powerMode, setPowerMode] = useState(false);
  const [lastPath, setLastPath] = useState('/portal/overview');
  const [health, setHealth] = useState<'nominal' | 'degraded'>('nominal');
  const [notices, setNotices] = useState<Notice[]>([]);

  useEffect(() => {
    const stored = localStorage.getItem('vv_portal_lang');
    if (stored === 'en' || stored === 'es') setLang(stored);

    const workspace = parseWorkspaceState(localStorage.getItem(workspaceKey));
    setPortalTheme(workspace.theme);
    setRole(workspace.role as PortalRole);
    setPowerMode(workspace.powerMode);
    setLastPath(workspace.lastPath);
    applyTheme(workspace.theme);
  }, []);

  useEffect(() => {
    localStorage.setItem(
      workspaceKey,
      encodeWorkspaceState({
        theme: portalTheme,
        role,
        powerMode,
        lastPath: window.location.pathname
      })
    );
  }, [lastPath, portalTheme, powerMode, role]);

  useEffect(() => {
    const timer = setInterval(() => {
      const now = Date.now();
      setHealth(now % 7 === 0 ? 'degraded' : 'nominal');
    }, 3000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const target = keyboardShortcutTarget(event.key, event.altKey);
      if (target) {
        event.preventDefault();
        setLastPath(target);
        window.location.assign(target);
        return;
      }

      if (event.key.toLowerCase() === 'k' && event.ctrlKey && roleAllowsPowerMode(role)) {
        event.preventDefault();
        setPowerMode((prev) => !prev);
      }
    };

    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [role]);

  function changeLang(next: PortalLang) {
    setLang(next);
    localStorage.setItem('vv_portal_lang', next);
  }

  const currentPath = typeof window === 'undefined' ? '' : window.location.pathname;
  const canRecover = Boolean(currentPath) && lastPath !== currentPath;
  const a11yChecks = useMemo(() => accessibilityChecklist(), []);

  return (
    <header className="vv-responsive-shell flex min-h-navbar flex-col gap-3 border-b border-[color:var(--vv-border-subtle)] bg-bg-primary px-4 py-3 lg:flex-row lg:items-center lg:justify-between">
      <div className="flex items-center gap-4">
        <BrandLogo />
        <TenantLogo companyName={theme?.company_name ?? tenantName} logoUrl={theme?.logo_url} />
        <div>
          <p className="text-xs uppercase tracking-[0.14em] text-text-secondary">{t(lang, 'tenant')}</p>
          <p className="text-sm font-semibold text-metallic">{theme?.company_name ?? tenantName}</p>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2" aria-live="polite">
        <button
          type="button"
          className="rounded-lg border border-[color:var(--vv-border-subtle)] px-2 py-1 text-xs"
          onClick={() => {
            const next = nextTheme(portalTheme);
            setPortalTheme(next);
            applyTheme(next);
          }}
        >
          Theme: {portalTheme}
        </button>

        <select
          value={role}
          onChange={(event) => setRole(event.target.value as PortalRole)}
          className="rounded-lg border border-[color:var(--vv-border-subtle)] bg-bg-secondary px-2 py-1 text-xs"
          aria-label="portal role"
        >
          <option value="red_team">Red Team</option>
          <option value="blue_team">Blue Team</option>
          <option value="exec">Exec</option>
          <option value="auditor">Auditor</option>
        </select>

        <span className={`rounded border px-2 py-1 text-xs ${health === 'nominal' ? 'border-green-500 text-green-300' : 'border-amber-500 text-amber-300'}`}>
          Health: {health}
        </span>

        <button
          type="button"
          className="rounded-lg border border-[color:var(--vv-border-subtle)] px-2 py-1 text-xs"
          onClick={() =>
            setNotices((prev) =>
              reduceRenderBudget([{ id: `${Date.now()}`, text: `${ROLE_LABELS[role]} context synchronized` }, ...prev], 4)
            )
          }
        >
          Notify
        </button>

        {canRecover ? (
          <button
            type="button"
            className="rounded-lg border border-[color:var(--vv-border-subtle)] px-2 py-1 text-xs"
            onClick={() => window.location.assign(lastPath)}
          >
            Recover Workspace
          </button>
        ) : null}

        <span className="text-xs text-text-secondary">Power: {powerMode ? 'on' : 'off'} | Export: {roleCanExport(role) ? 'enabled' : 'restricted'}</span>

        <select
          value={lang}
          onChange={(e) => changeLang((e.target.value as PortalLang) ?? 'en')}
          className="rounded-lg border border-[color:var(--vv-border-subtle)] bg-bg-secondary px-2 py-2 text-xs text-text-primary"
          aria-label="language"
        >
          <option value="en">EN</option>
          <option value="es">ES</option>
        </select>

        <NotificationCenter lang={lang} />
        <form action="/api/auth/logout" method="post">
          <Button type="submit">{t(lang, 'logout')}</Button>
        </form>
      </div>

      {notices.length > 0 ? (
        <ul className="w-full space-y-1 text-xs lg:w-auto">
          {notices.map((notice) => (
            <li key={notice.id} className="rounded border border-[color:var(--vv-border-subtle)] px-2 py-1">
              {notice.text}
            </li>
          ))}
        </ul>
      ) : null}

      <span className="sr-only">A11y checks: {a11yChecks.map((item) => `${item.id}:${item.status}`).join(',')}</span>
    </header>
  );
}
