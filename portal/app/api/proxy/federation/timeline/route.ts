/*
Copyright (c) 2026 NyxeraLabs
Author: Jose Maria Micoli
Licensed under BSL 1.1
Change Date: 2033-02-17 -> Apache-2.0
*/

import { NextRequest } from 'next/server';

import { proxyClientApi } from '@/lib/proxy';

export async function GET(request: NextRequest) {
  const q = request.nextUrl.searchParams.toString();
  return proxyClientApi(request, `/api/v1/client/federation/timeline${q ? `?${q}` : ''}`);
}
