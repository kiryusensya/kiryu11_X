// middleware.js
import { NextResponse } from 'next/server';

export function middleware(request) {
    // アクセスされたURLが dashboard.html かどうかを判定
    if (request.nextUrl.pathname.startsWith('/dashboard.html')) {
        
        // リクエストのCookieからトークンを取得
        const token = request.cookies.get('admin_token')?.value;

        // トークンが存在しない場合
        if (!token) {
            // サーバー側で強制的にログイン画面へリダイレクト（HTMLは一切渡さない）
            const loginUrl = new URL('/login.html', request.url);
            return NextResponse.redirect(loginUrl);
        }
        
        // ※本来はここでJWTの署名検証を行い、偽装されたトークンも弾くのがベストです
    }

    // トークンがある、または関係ないページへのアクセスならそのまま通す
    return NextResponse.next();
}

// このMiddlewareをどのパスで実行するか指定
export const config = {
    matcher: ['/dashboard.html'],
};
