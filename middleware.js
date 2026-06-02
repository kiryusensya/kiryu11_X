export const config = {
    matcher: ['/', '/index.html', '/videos.html', '/dashboard.html', '/Enforcement-Administrator.html'],
};

export default function middleware(request) {
    const url = new URL(request.url);
    
    if (url.pathname.startsWith('/Access.html') || url.pathname.startsWith('/signin.html')) {
        return;
    }

    const cookie = request.headers.get('cookie') || '';

    if (url.pathname.startsWith('/dashboard.html') || url.pathname.startsWith('/Enforcement-Administrator.html')) {
        if (!cookie.includes('admin_token=')) {
            url.pathname = '/signin.html';
            return Response.redirect(url, 307);
        }
        return;
    }

    if (url.pathname === '/' || url.pathname.startsWith('/index.html') || url.pathname.startsWith('/videos.html')) {
        // ★ Cookieが無い場合、Access.htmlへリダイレクト（ただしauth=requiredは付けない）
        if (!cookie.includes('user_session_token=')) {
            const redirectUrl = new URL('/Access.html', request.url);
            // 元のパスとパラメータを引き継ぐ
            redirectUrl.searchParams.set('redirect', url.pathname + url.search);
            return Response.redirect(redirectUrl.toString(), 307);
        }
        return;
    }
}
