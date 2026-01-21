import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

// Redis/Ratelimitの初期化 (環境変数がなければスキップするガードを追加推奨ですが、ここではそのまま)
const redis = Redis.fromEnv();
const ratelimit = new Ratelimit({
  redis: redis,
  limiter: Ratelimit.slidingWindow(5, "60 s"),
});

export default async function handler(req, res) {
  // 1. セキュリティチェック
  try {
    const identifier = (req.headers['x-forwarded-for'] || 'ip').split(',')[0];
    const { success } = await ratelimit.limit(identifier);

    if (!success) {
      return res.status(429).json({ 
        success: false,
        message: 'Too many requests. Please try again later.' 
      });
    }
  } catch (err) {
    console.error("Redis Error:", err);
    // Redisエラー時は通過させる
  }

  // 2. URL振り分け
  const requestParams = {
    ...(req.query || {}),
    ...(req.body || {})
  };

  const type = requestParams.type;
  let targetGasUrl = "";

  if (type === 'instagram_auth' || type === 'service_status') {
    targetGasUrl = process.env.GAS_URL_Support;
  } else {
    // アクティベーション含むその他すべて
    targetGasUrl = process.env.GAS_URL_Main;
  }

  if (!targetGasUrl) {
    return res.status(500).json({ success: false, message: 'Server Config Error: GAS URL missing' });
  }

  // クエリパラメータの構築
  const params = new URLSearchParams(requestParams);
  const finalUrl = `${targetGasUrl}?${params.toString()}`;

  // 3. GASへのリクエスト実行
  try {
    // GASへのFetchはデフォルトでGET扱いになります
    const response = await fetch(finalUrl, {
      method: 'GET', // 明示的にGET
      redirect: 'follow' // リダイレクトを追跡(GASのお約束)
    });

    // Content-Typeチェック
    const contentType = response.headers.get("content-type");
    if (!contentType || !contentType.includes("application/json")) {
      // JSON以外が返ってきた場合はGAS側でHTMLエラーが発生している
      const text = await response.text();
      console.error("GAS Error Response (HTML):", text.substring(0, 200)); // ログに冒頭を表示
      throw new Error("Invalid response from verification server.");
    }

    const data = await response.json();
    return res.status(200).json(data);

  } catch (error) {
    console.error("Proxy Fetch Error:", error);
    return res.status(500).json({ 
      success: false, 
      message: 'Authentication failed.',
      debug: error.message 
    });
  }
}
