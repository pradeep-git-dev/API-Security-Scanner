import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const token = request.cookies.get('token')?.value;
  const url = request.nextUrl.clone();

  // If trying to access dashboard paths without a token cookie, redirect to login
  if (url.pathname.startsWith('/dashboard')) {
    if (!token) {
      url.pathname = '/login';
      return NextResponse.redirect(url);
    }
  }

  // If trying to access auth pages or landing while already logged in
  if (url.pathname === '/login' || url.pathname === '/register' || url.pathname === '/') {
    if (token) {
      url.pathname = '/dashboard';
      return NextResponse.redirect(url);
    }
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    '/dashboard/:path*',
    '/login',
    '/register',
    '/',
  ],
};
