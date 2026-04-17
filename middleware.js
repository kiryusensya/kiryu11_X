export const config = {
    // 原則として dashboard.html のみに門番を配置
    matcher: ['/dashboard.html'],
};

export default function middleware(request) {
    const url = new URL(request.url);
    
    // 【超重要: 無限ループ防止】
    // もし今アクセスしようとしている先が「login.html」なら、絶対に門番をスルーさせる
    if (url.pathname.startsWith('/login.html')) {
        return; // 何もせずにそのまま通す
    }

    // 念のための保険: アクセス先が dashboard.html じゃない場合も素通りさせる
    if (!url.pathname.startsWith('/dashboard.html')) {
        return;
    }

    // リクエストヘッダーからCookieを取得
    const cookie = request.headers.get('cookie') || '';

    // Cookieの中に「admin_token=」が存在しない場合
    if (!cookie.includes('admin_token=')) {
        // 未認証ユーザーは login.html へ強制リダイレクト
        url.pathname = '/login.html';
        return Response.redirect(url, 307);
    }
}
