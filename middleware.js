// どのパスでこのミドルウェア（門番）を起動するかを指定
export const config = {
    matcher: ['/dashboard.html'],
};

export default function middleware(request) {
    // 現在アクセスされているURL情報を取得
    const url = new URL(request.url);
    
    // リクエストヘッダーからCookieを取得
    const cookie = request.headers.get('cookie') || '';

    // Cookieの中に「admin_token=」が存在しない場合
    if (!cookie.includes('admin_token=')) {
        // 未認証ユーザーは login.html へ強制リダイレクト
        url.pathname = '/login.html';
        return Response.redirect(url, 307);
    }

    // トークンが存在して認証OKな場合、ここで何もreturnしなければ
    // Vercelは「アクセス許可」と判断し、そのまま dashboard.html を表示します
}
