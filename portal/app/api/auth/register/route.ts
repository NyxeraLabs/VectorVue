/*
Copyright (c) 2026 NyxeraLabs
Author: José María Micoli
Licensed under BSL 1.1
Change Date: 2033-02-17 → Apache-2.0
*/

import { NextRequest, NextResponse } from 'next/server';

function externalBaseUrl(request: NextRequest): string {
  const proto = request.headers.get('x-forwarded-proto') ?? request.nextUrl.protocol.replace(':', '');
  const host = request.headers.get('x-forwarded-host') ?? request.headers.get('host') ?? request.nextUrl.host;
  return `${proto}://${host}`;
}

export async function POST(request: NextRequest) {
  const url = new URL('/login', externalBaseUrl(request));
  url.searchParams.set('error', 'registration_disabled');
  return NextResponse.redirect(url, { status: 303 });
}
