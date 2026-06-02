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
}export const config = {
    // index.html, ルートパス(/), videos.html, および管理画面群を門番の監視対象にする
    matcher: ['/', '/index.html', '/videos.html', '/dashboard.html', '/Enforcement-Administrator.html'],
};

export default function middleware(request) {
    const url = new URL(request.url);
    
    // 【無限ループ防止】ログイン系ページは絶対にスルーさせる
    if (url.pathname.startsWith('/Access.html') || url.pathname.startsWith('/signin.html')) {
        return;
    }

    // リクエストヘッダーからCookieを取得
    const cookie = request.headers.get('cookie') || '';

    // --- 1. 管理画面 (dashboard.html, Enforcement-Administrator.html) のチェック ---
    if (url.pathname.startsWith('/dashboard.html') || url.pathname.startsWith('/Enforcement-Administrator.html')) {
        if (!cookie.includes('admin_token=')) {
            url.pathname = '/signin.html';
            return Response.redirect(url, 307);
        }
        return; // admin_tokenがあれば通過
    }

    // --- 2. 一般ユーザー画面 (index.html, /, videos.html) のチェック ---
    if (url.pathname === '/' || url.pathname.startsWith('/index.html') || url.pathname.startsWith('/videos.html')) {
        // Cookieの中に user_session_token が存在するかチェック
        if (!cookie.includes('user_session_token=')) {
            url.pathname = '/Access.html';
            url.searchParams.set('auth', 'required');
            return Response.redirect(url.toString(), 307);
        }
        return; // user_session_tokenがあれば通過
    }
}
