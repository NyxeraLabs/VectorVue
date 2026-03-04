import { NextRequest } from 'next/server';

import { proxyClientApi } from '@/lib/proxy';

export async function GET(request: NextRequest) {
  return proxyClientApi(request, '/api/v1/client/demo/session');
}

export async function PUT(request: NextRequest) {
  return proxyClientApi(request, '/api/v1/client/demo/session');
}

export async function DELETE(request: NextRequest) {
  return proxyClientApi(request, '/api/v1/client/demo/session');
}
