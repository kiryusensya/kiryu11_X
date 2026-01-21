export default async function handler(req, res) {
  // -------------------------------------------------------
  // 1. パラメータの整理 (GET/POST両対応)
  // -------------------------------------------------------
  const requestParams = {
    ...(req.query || {}),
    ...(req.body || {})
  };

  // -------------------------------------------------------
  // 2. 接続先GASの決定 (一本化)
  // -------------------------------------------------------
  // "GAS_URL_Support" は廃止し、すべて "GAS_URL_Main" を使用します。
  // Vercelの環境変数に "GAS_URL_Main" が正しく設定されている必要があります。
  const targetGasUrl = process.env.GAS_URL_Main;

  // 環境変数チェック
  if (!targetGasUrl) {
    console.error("Error: GAS_URL_Main is not set in Vercel Environment Variables.");
    return res.status(500).json({ 
      success: false, 
      message: 'Server Configuration Error: GAS_URL_Main missing.' 
    });
  }

  // GASへ送るURLを組み立て
  const params = new URLSearchParams(requestParams);
  const finalUrl = `${targetGasUrl}?${params.toString()}`;

  // -------------------------------------------------------
  // 3. GASへのリクエスト実行
  // -------------------------------------------------------
  try {
    // GASは基本的にGETでリクエストを受け取り、redirect: 'follow' が必須
    const response = await fetch(finalUrl, {
      method: 'GET',
      redirect: 'follow',
      headers: {
        "Content-Type": "application/json"
      }
    });

    // レスポンスがJSONかどうかチェック (GASのエラー画面などが返ってきていないか)
    const contentType = response.headers.get("content-type");
    if (!contentType || !contentType.includes("application/json")) {
      const text = await response.text();
      console.error("GAS returned HTML/Text instead of JSON:", text.substring(0, 500));
      throw new Error("Invalid response from GAS (Received HTML/Text). Check GAS deployment permissions.");
    }

    const data = await response.json();
    return res.status(200).json(data);

  } catch (error) {
    console.error("Proxy Fetch Error:", error);
    return res.status(500).json({ 
      success: false, 
      message: 'Connection to GAS failed.', 
      debug: error.message 
    });
  }
}
