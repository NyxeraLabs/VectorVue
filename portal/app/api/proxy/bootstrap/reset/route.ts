import { NextRequest } from 'next/server';

import { proxyClientApi } from '@/lib/proxy';

export async function POST(request: NextRequest) {
  const q = request.nextUrl.searchParams.toString();
  return proxyClientApi(request, `/api/v1/client/bootstrap/reset${q ? `?${q}` : ''}`);
}
