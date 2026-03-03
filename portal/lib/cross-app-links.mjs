/*
Copyright (c) 2026 NyxeraLabs
Author: Jose Maria Micoli
Licensed under BSL 1.1
Change Date: 2033-02-17 -> Apache-2.0
*/

const DEFAULT_NEXUS_URL = 'https://127.0.0.1:18443';
const DEFAULT_VECTORVUE_URL = 'https://127.0.0.1';
const DEFAULT_SPECTRASTRIKE_URL = 'https://127.0.0.1:18443';

function clean(value) {
  return String(value ?? '').trim();
}

function env(name) {
  if (typeof process === 'undefined' || !process.env) return '';
  return clean(process.env[name]);
}

function warnMissing(name, fallback) {
  console.warn(`[cross-app-links] Missing env ${name}. Falling back to ${fallback}`);
}

function browserFallback(fallback, port) {
  if (typeof window === 'undefined') return fallback;
  const host = String(window.location?.hostname ?? '').trim();
  if (!host) return fallback;
  const suffix = port ? `:${port}` : '';
  return `https://${host}${suffix}`;
}

function enforceHttps(name, value) {
  const trimmed = String(value ?? '').trim();
  if (!trimmed) return trimmed;
  if (trimmed.startsWith('https://')) return trimmed;
  if (trimmed.startsWith('http://')) {
    const upgraded = `https://${trimmed.slice('http://'.length)}`;
    console.warn(`[cross-app-links] Insecure URL in ${name}. Upgrading to ${upgraded}`);
    return upgraded;
  }
  const upgraded = `https://${trimmed.replace(/^\/+/, '')}`;
  console.warn(`[cross-app-links] URL in ${name} missing scheme. Upgrading to ${upgraded}`);
  return upgraded;
}

export function getNexusUrl() {
  const configured = env('VITE_NEXUS_URL') || env('NEXT_PUBLIC_NEXUS_URL') || env('UI_NEXUS_BASE_URL');
  if (configured) return enforceHttps('VITE_NEXUS_URL', configured);
  const fallback = browserFallback(DEFAULT_NEXUS_URL, '18443');
  warnMissing('VITE_NEXUS_URL', fallback);
  return fallback;
}

export function getVectorVueUrl() {
  const configured = env('VITE_VECTORVUE_URL') || env('NEXT_PUBLIC_VECTORVUE_URL') || env('UI_VECTORVUE_BASE_URL');
  if (configured) return enforceHttps('VITE_VECTORVUE_URL', configured);
  const fallback = browserFallback(DEFAULT_VECTORVUE_URL, null);
  warnMissing('VITE_VECTORVUE_URL', fallback);
  return fallback;
}

export function getSpectraStrikeUrl() {
  const configured =
    env('VITE_SPECTRASTRIKE_URL') ||
    env('NEXT_PUBLIC_SPECTRASTRIKE_BASE_URL') ||
    env('UI_SPECTRASTRIKE_BASE_URL');
  if (configured) return enforceHttps('VITE_SPECTRASTRIKE_URL', configured);
  const fallback = browserFallback(DEFAULT_SPECTRASTRIKE_URL, '18443');
  warnMissing('VITE_SPECTRASTRIKE_URL', fallback);
  return fallback;
}
