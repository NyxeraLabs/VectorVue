/*
Copyright (c) 2026 NyxeraLabs
Author: Jose Maria Micoli
Licensed under BSL 1.1
Change Date: 2033-02-17 -> Apache-2.0
*/

const DEFAULT_NEXUS_URL = 'http://localhost:3001';
const DEFAULT_VECTORVUE_URL = 'http://localhost:3002';
const DEFAULT_SPECTRASTRIKE_URL = 'http://localhost:3000';

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

export function getNexusUrl() {
  const configured = env('VITE_NEXUS_URL') || env('NEXT_PUBLIC_NEXUS_URL') || env('UI_NEXUS_BASE_URL');
  if (configured) return configured;
  warnMissing('VITE_NEXUS_URL', DEFAULT_NEXUS_URL);
  return DEFAULT_NEXUS_URL;
}

export function getVectorVueUrl() {
  const configured = env('VITE_VECTORVUE_URL') || env('NEXT_PUBLIC_VECTORVUE_URL') || env('UI_VECTORVUE_BASE_URL');
  if (configured) return configured;
  warnMissing('VITE_VECTORVUE_URL', DEFAULT_VECTORVUE_URL);
  return DEFAULT_VECTORVUE_URL;
}

export function getSpectraStrikeUrl() {
  const configured =
    env('VITE_SPECTRASTRIKE_URL') ||
    env('NEXT_PUBLIC_SPECTRASTRIKE_BASE_URL') ||
    env('UI_SPECTRASTRIKE_BASE_URL');
  if (configured) return configured;
  warnMissing('VITE_SPECTRASTRIKE_URL', DEFAULT_SPECTRASTRIKE_URL);
  return DEFAULT_SPECTRASTRIKE_URL;
}
