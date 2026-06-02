import { NextResponse } from 'next/server';

export const config = {
    matcher: ['/', '/index.html', '/videos.html', '/dashboard.html', '/Enforcement-Administrator.html'],
};

export default function middleware(request) {
    const url = request.nextUrl.clone();
    const cookie = request.headers.get('cookie') || '';

    // 管理画面チェック
    if (url.pathname.startsWith('/dashboard.html') || url.pathname.startsWith('/Enforcement-Administrator.html')) {
        if (!cookie.includes('admin_token=')) {
            url.pathname = '/signin.html';
            url.search = '';
            return NextResponse.redirect(url, 307);
        }
        return NextResponse.next();
    }

    // 一般ユーザー画面チェック
    if (url.pathname === '/' || url.pathname.startsWith('/index.html') || url.pathname.startsWith('/videos.html')) {
        if (!cookie.includes('user_session_token=')) {
            const originalPath = url.pathname + url.search;
            url.pathname = '/Access.html';
            url.search = '?redirect=' + encodeURIComponent(originalPath);
            return NextResponse.redirect(url, 307);
        }
        return NextResponse.next();
    }

    return NextResponse.next();
}
