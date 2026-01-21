import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

// 1. レートリミットの準備
const redis = Redis.fromEnv();
const ratelimit = new Ratelimit({
  redis: redis,
  limiter: Ratelimit.slidingWindow(5, "60 s"), // 60秒に5回まで
});

export default async function handler(req, res) {
  // -------------------------------------------------------
  // 1. セキュリティチェック（レートリミット）
  // -------------------------------------------------------
  try {
    const identifier = req.headers['x-forwarded-for'] ? req.headers['x-forwarded-for'].split(',')[0] : 'ip';
    const { success } = await ratelimit.limit(identifier);

    if (!success) {
      return res.status(429).json({ 
        error: 'Too Many Requests',
        message: '試行回数が多すぎます。しばらく待ってから再試行してください。' 
      });
    }
  } catch (err) {
    console.error("Redis Error:", err);
    // Redisエラー時は無視して通す（あるいはエラーを返す設定にする）
  }

  // -------------------------------------------------------
  // 2. URLの振り分け
  // -------------------------------------------------------
  
  // パラメータを整理
  const requestParams = {
    ...(req.query || {}),
    ...(req.body || {})
  };

  const type = requestParams.type; // リクエストの種類を取得
  let targetGasUrl = "";

  // ★★★ 修正箇所: service_status も Support用GASに向ける ★★★
  if (type === 'instagram_auth' || type === 'service_status') {
    // Instagram認証 または サービスステータス確認 は「Support用」へ
    targetGasUrl = process.env.GAS_URL_Support;
  } else {
    // それ以外（アクティベーション、ニュース等）は「Main用」へ
    targetGasUrl = process.env.GAS_URL_Main;
  }

  // 環境変数が設定されていない場合のエラーハンドリング
  if (!targetGasUrl) {
    console.error(`Error: GAS URL not configured for type: ${type}`);
    return res.status(500).json({ error: 'Server configuration error (GAS URL missing)' });
  }

  // GAS向けパラメータの作成
  const params = new URLSearchParams(requestParams);
  const finalUrl = `${targetGasUrl}?${params.toString()}`;

  // -------------------------------------------------------
  // 3. GASへの問い合わせ実行
  // -------------------------------------------------------
  try {
    const response = await fetch(finalUrl);
    // レスポンスがJSONでない場合のエラーハンドリングを追加
    const contentType = response.headers.get("content-type");
    if (!contentType || !contentType.includes("application/json")) {
        throw new Error("GAS returned non-JSON response");
    }
    const data = await response.json();
    return res.status(200).json(data);
  } catch (error) {
    console.error("Fetch Error:", error);
    return res.status(500).json({ error: 'Authentication failed or GAS error', details: error.message });
  }
}
