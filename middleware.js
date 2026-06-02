export const config = {
    // 監視対象のパス
    matcher: ['/', '/index.html', '/videos.html', '/dashboard.html', '/Enforcement-Administrator.html'],
};

export default function middleware(request) {
    const url = new URL(request.url);
    
    // 【無限ループ防止】ログイン系ページは絶対にスルーさせる
    if (url.pathname.startsWith('/Access.html') || url.pathname.startsWith('/signin.html')) {
        return;
    }

    // --- 1. 管理画面のチェック ---
    if (url.pathname.startsWith('/dashboard.html') || url.pathname.startsWith('/Enforcement-Administrator.html')) {
        // Next.js環境の場合: request.cookies.has('admin_token') が最も安全
        // もし純粋なEdge標準環境なら正規表現で完全一致をチェック: /(?:^|; )admin_token=/.test(request.headers.get('cookie') || '')
        const hasAdminToken = request.cookies ? request.cookies.has('admin_token') : /(?:^|; )admin_token=/.test(request.headers.get('cookie') || '');
        
        if (!hasAdminToken) {
            const redirectUrl = new URL('/signin.html', request.url);
            return Response.redirect(redirectUrl.toString(), 307);
        }
        return;
    }

    // --- 2. 一般ユーザー画面のチェック ---
    if (url.pathname === '/' || url.pathname.startsWith('/index.html') || url.pathname.startsWith('/videos.html')) {
        const hasUserToken = request.cookies ? request.cookies.has('user_session_token') : /(?:^|; )user_session_token=/.test(request.headers.get('cookie') || '');

        if (!hasUserToken) {
            const redirectUrl = new URL('/Access.html', request.url);
            // ログイン後に元のページへ戻せるよう、元のパスとパラメータを引き継ぐ
            redirectUrl.searchParams.set('redirect', url.pathname + url.search);
            return Response.redirect(redirectUrl.toString(), 307);
        }
        return;
    }
}
