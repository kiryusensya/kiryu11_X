import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
// ★Vercelの環境変数に JWT_SECRET を必ず設定してください
const JWT_SECRET = process.env.JWT_SECRET || 'your-fallback-secret-key';
const supabase = createClient(supabaseUrl, supabaseKey);

const ADMIN_ID = "admin_kiryu-sensya";
const ADMIN_PASS = "-GTA6xaxijIl-v4.2xs-2";

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');

  if (req.method === 'OPTIONS') return res.status(200).end();

  const params = req.method === 'POST' ? req.body : req.query;
  const type = params.type;
  const lang = params.lang || 'ja';

  // ==========================================
  // ★認証情報の抽出（フロントからの自己申告は無視する）
  // ==========================================
  let authUserId = null;
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    try {
      // トークンが本物か検証し、中身のuserIdを取り出す
      const decoded = jwt.verify(token, JWT_SECRET);
      authUserId = decoded.userId;
    } catch (e) {
      // トークンが不正、または有効期限切れの場合は無視（authUserIdはnullのまま）
    }
  }

  try {
    // 1. ユーザー登録
    if (type === 'register') {
      const { email, password } = params;
      if (!email || !password) return res.status(200).json({ success: false, message: "Missing credentials" });
      const { data: existing } = await supabase.from('users').select('id').eq('email', email).maybeSingle();
      if (existing) return res.status(200).json({ success: false, message: "Exists" });
      const { data: newUser, error } = await supabase.from('users').insert([{ email, password: hashPassword(password), points: 0 }]).select().single();
      if (error) throw error;
      return res.status(200).json({ success: true, userId: newUser.id, message: "OK" });
    }

    // ==========================================
    // ★ 管理者用 新規ユーザー強制作成
    // ==========================================
    if (type === 'admin_create_user') {
      const { email, password } = params;
      if (!email || !password) return res.status(200).json({ success: false, message: "Missing credentials" });
      
      const { data: existing } = await supabase.from('users').select('id').eq('email', email).maybeSingle();
      if (existing) return res.status(200).json({ success: false, message: "そのIDは既に存在します" });
      
      const hashedPass = hashPassword(password);
      const { data: newUser, error } = await supabase.from('users').insert([{ 
          email, 
          password: hashedPass, 
          points: 0,
          needs_password_change: true 
      }]).select().single();
      
      if (error) throw error;
      return res.status(200).json({ success: true, message: "OK" });
    }

    // ==========================================
    // ★ 管理者用 パスワード強制リセット
    // ==========================================
    if (type === 'admin_reset_password') {
      const { adminUser, adminPass, targetEmail, newPassword } = params;
      
      if (adminUser !== ADMIN_ID || adminPass !== ADMIN_PASS) {
         return res.status(200).json({ success: false, message: "権限がありません" });
      }

      const { data: targetUser } = await supabase.from('users').select('id').eq('email', targetEmail).maybeSingle();
      if (!targetUser) {
          return res.status(200).json({ success: false, message: "指定されたユーザーが見つかりません" });
      }

      const hashedNewPass = hashPassword(newPassword);
      const { error: updateError } = await supabase.from('users').update({ 
          password: hashedNewPass,
          needs_password_change: true 
      }).eq('id', targetUser.id);

      if (updateError) {
          return res.status(200).json({ success: false, message: "データベースの更新に失敗しました" });
      }
      return res.status(200).json({ success: true, message: "Password reset successful" });
    }

    // ==========================================
    // ★ 管理者用 ユーザー履歴検索
    // ==========================================
    if (type === 'admin_search') {
      const { adminUser, adminPass, targetEmail } = params;
      if (adminUser !== ADMIN_ID || adminPass !== ADMIN_PASS) {
        return res.status(200).json({ success: false, message: "権限がありません" });
      }
      if (!targetEmail) return res.status(200).json({ success: false, message: "対象のメールアドレスを指定してください" });

      const { data: targetUser } = await supabase.from('users').select('id, email').eq('email', targetEmail).maybeSingle();
      if (!targetUser) return res.status(200).json({ success: false, message: "指定されたユーザーが見つかりません" });

      const { data: histories, error: searchError } = await supabase.from('histories')
        .select(`created_at, codes (*)`).eq('user_id', targetUser.id).order('created_at', { ascending: false });

      if (searchError) {
          console.error(searchError);
          return res.status(200).json({ success: false, message: "履歴の取得に失敗しました" });
      }

      const historyData = (histories || []).map(h => ({
        code: h.codes ? h.codes["アクティベーションコード"] : "不明",
        title: h.codes ? (h.codes["タイトル(jp)"] || "不明なコンテンツ") : "不明なコンテンツ",
        date: new Date(h.created_at).toLocaleString('ja-JP')
      }));
      return res.status(200).json({ success: true, userId: targetUser.email, history: historyData });
    }

    // ==========================================
    // 2. ユーザーログイン (★JWTトークン発行)
    // ==========================================
    if (type === 'user_login') {
      const { email, password } = params;
      // 管理者ログイン判定
      if (email === ADMIN_ID && password === ADMIN_PASS) {
        return res.status(200).json({ success: true, isAdmin: true });
      }
      
      const { data: user } = await supabase.from('users').select('*').eq('email', email).maybeSingle();
      if (user && user.password === hashPassword(password)) {
        if (user.needs_password_change) {
            // パスワード変更が必要な場合は、特別な一時トークン（またはフロントでメアド保持）を返す
            // 今回は既存のロジックに合わせてuserIdだけを返します
            return res.status(200).json({ success: true, requirePasswordChange: true, userId: user.id });
        }
        
        // ★パスワードが合っていれば、ユーザーIDを封入したJWTトークンを発行 (有効期限24時間)
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '24h' });
        
        return res.status(200).json({ success: true, token: token, userId: user.id, points: user.points, history: [] });
      }
      return res.status(200).json({ success: false, message: "Invalid" });
    }

    // ==========================================
    // ★ パスワード強制変更・通常変更処理
    // ==========================================
    if (type === 'change_password') {
      const { userId, oldPassword, newPassword } = params;
      // 強制変更画面からは未ログイン状態で来るため、ここでは特例として params.userId を受け入れる
      // （※本来はリセット用の一時トークンを発行すべきですが、今回は簡易的に許可します）
      const targetId = authUserId || userId; 
      
      const { data: user } = await supabase.from('users').select('*').eq('id', targetId).maybeSingle();
      
      if (user && user.password === hashPassword(oldPassword)) {
          await supabase.from('users').update({
              password: hashPassword(newPassword),
              needs_password_change: false
          }).eq('id', targetId);
          return res.status(200).json({ success: true });
      }
      return res.status(200).json({ success: false, message: "現在のパスワードが間違っています。" });
    }

    // ==========================================
    // セッション復帰時の最新情報取得
    // ==========================================
    if (type === 'get_user_info') {
      if (!authUserId) return res.status(401).json({ success: false, message: "Unauthorized" });
      
      const { data: user, error } = await supabase.from('users').select('points').eq('id', authUserId).single();
      if (error || !user) {
        return res.status(200).json({ success: false, message: "User not found" });
      }
      return res.status(200).json({ success: true, points: user.points });
    }

    // 3. 利用可能なコンテンツ一覧 (Store)
    if (type === 'get_available') {
      // フロントエンドからの自己申告（params.userId）が GUEST でない場合、
      // トークンから復号した authUserId を本物のユーザーIDとして使用する
      const isGuest = (!params.userId || params.userId === "GUEST");
      const targetId = isGuest ? null : authUserId; 
      
      const { data: allCodes } = await supabase.from('codes').select('*');
      
      let ownedCodeIds = new Set();
      let ownedGroupIds = new Set();

      // targetId が存在する場合（ログイン中）のみ履歴を取得
      if (targetId) {
        const { data: history } = await supabase.from('histories').select('code_id').eq('user_id', targetId);
        if (history) {
            const codeIds = history.map(h => h.code_id);
            ownedCodeIds = new Set(codeIds);
            if (codeIds.length > 0) {
                const { data: ownedCodes } = await supabase.from('codes').select('重複').in('id', codeIds);
                if(ownedCodes) ownedGroupIds = new Set(ownedCodes.map(c => c["重複"]).filter(Boolean));
            }
        }
      }

      const lMap = { ja: 'jp', en: 'en', zh: 'SC', 'zh-TW': 'TC', ko: 'ko', ru: 'ru' };
      const suffix = lMap[lang] || 'jp';

      const filteredCodes = (allCodes || []).filter(c => {
          const isActive = c["有効/無効"] === true || String(c["有効/無効"]).toUpperCase() === 'TRUE';
          const isShow = String(c["show/ hide"] || "").trim().toLowerCase() === 'show';
          const cType = String(c.Types || "").trim().toUpperCase();
          if (!isActive || !isShow || cType === 'POINT') return false;
          const isOnce = (cType === 'ONCE' || cType === '');
          const isUsed = c["USED?"] === true || String(c["USED?"]).trim().toUpperCase() === 'TRUE';
          if (isOnce && isUsed) return false;
          return true;
      });

      const items = filteredCodes.map(code => {
        const isOwned = ownedCodeIds.has(code.id) || (code["重複"] && ownedGroupIds.has(code["重複"]));
        return {
          code: code["アクティベーションコード"],
          title: code[`タイトル(${suffix})`] || code["タイトル(jp)"],
          message: code[`メッセージ(${suffix})`] || code["メッセージ(jp)"],
          extraInfo: code[`詳細(${suffix})`] || code["詳細(jp)"],
          imageUrl: code.Imag_Url,
          url: code.Action_url,
          releaseDateIso: code["解禁時間"],
          icon: code.アイコン || 'download',
          groupId: code["重複"],
          buttonLabel: code[`ボタン(${suffix})`] || code["ボタン(jp)"],
          price: code["価格"] || 0,
          isOwned: isOwned
        };
      });
      return res.status(200).json({ success: true, items });
    }

    // 4. ユーザー履歴の取得
    if (type === 'get_history') {
      if (!authUserId) return res.status(401).json({ success: false, message: "Unauthorized" });
      
      const { data: user, error: userErr } = await supabase.from('users').select('points').eq('id', authUserId).maybeSingle();
      if (userErr || !user) return res.status(200).json({ success: false, message: "User not found" });

      const { data: histories } = await supabase.from('histories').select(`created_at, codes (*)`).eq('user_id', authUserId).order('created_at', { ascending: false });

      const lMap = { ja: 'jp', en: 'en', zh: 'SC', 'zh-TW': 'TC', ko: 'ko', ru: 'ru' };
      const suffix = lMap[lang] || 'jp';

      const historyData = (histories || []).map(h => {
        const c = h.codes;
        if(!c) return null;
        return {
          code: c["アクティベーションコード"],
          date: h.created_at,
          title: c[`タイトル(${suffix})`] || c["タイトル(jp)"],
          message: c[`メッセージ(${suffix})`] || c["メッセージ(jp)"],
          url: c.Action_url,
          imageUrl: c.Imag_Url,
          icon: c.アイコン || 'download',
          releaseDateIso: c["解禁時間"],
          extraInfo: c[`詳細(${suffix})`] || c["詳細(jp)"],
          groupId: c["重複"],
          buttonLabel: c[`ボタン(${suffix})`] || c["ボタン(jp)"]
        };
      }).filter(Boolean);
      return res.status(200).json({ success: true, points: user.points, history: historyData });
    }

    // 5. ポイントでの購入
    if (type === 'purchase') {
      const { code } = params;
      if (!authUserId) return res.status(401).json({ success: false, message: "Unauthorized" });
      
      const { data: master } = await supabase.from('codes').select('*').eq('アクティベーションコード', code).maybeSingle();
      if (!master) return res.status(200).json({ success: false, message: "Item not found" });
      
      const { data: user } = await supabase.from('users').select('points').eq('id', authUserId).maybeSingle();
      if (!user) return res.status(200).json({ success: false, message: "User not found" });

      const { data: existingHist } = await supabase.from('histories').select('codes(重複)').eq('user_id', authUserId);
      let alreadyOwned = false;
      if (existingHist) {
         alreadyOwned = existingHist.some(h => h.codes && (h.codes["アクティベーションコード"] === code || (master["重複"] && h.codes["重複"] === master["重複"])));
      }
      if (alreadyOwned) return res.status(200).json({ success: false, message: "Already owned" });

      const price = master["価格"] || 0;
      if (user.points < price) return res.status(200).json({ success: false, message: "Not enough points" });
      
      await supabase.from('users').update({ points: user.points - price }).eq('id', authUserId);
      await supabase.from('histories').insert([{ user_id: authUserId, code_id: master.id }]);
      return res.status(200).json({ success: true, remainingPoints: user.points - price });
    }

    // ==========================================
    // 6. コードの確認(check) と 引き換え(redeem)
    // ==========================================
    if (type === 'check' || type === 'redeem') {
      const { key, mode } = params;
      const targetId = authUserId; // 未ログインならnull

      const safeCode = (key || "").replace(/[^A-Z0-9\-]/gi, "").toUpperCase();
      const { data: master, error } = await supabase.from('codes').select('*').eq('アクティベーションコード', safeCode).maybeSingle();

      if (error || !master) {
          return res.status(200).json({ success: false, message: "This code is invalid." });
      }

      const isActive = master["有効/無効"] === true || String(master["有効/無効"]).trim().toUpperCase() === 'TRUE';
      if (!isActive) {
        return res.status(200).json({ success: false, message: "This code is invalid." });
      }

      const now = new Date();
      if (master["有効時間"] && now > new Date(master["有効時間"])) {
        return res.status(200).json({ success: false, message: "This code is invalid." });
      }

      const codeType = (master.Types || "").trim().toUpperCase();
      const isOnce = (codeType === 'ONCE' || codeType === '');
      const rawUsed = master["USED?"];
      const isCodeUsed = rawUsed === true || String(rawUsed).trim().toUpperCase() === 'TRUE';

      if ((isOnce || codeType === 'POINT') && isCodeUsed) {
        return res.status(200).json({ success: false, message: "This code has already been used." });
      }
      
      const lMap = { ja: 'jp', en: 'en', zh: 'SC', 'zh-TW': 'TC', ko: 'ko', ru: 'ru' };
      const suffix = lMap[lang] || 'jp';

      const txt = {
        btnLabel: master[`ボタン(${suffix})`] || master["ボタン(jp)"],
        bundle:   master[`バンドル(${suffix})`] || master["バンドル(jp)"],
        message:  master[`メッセージ(${suffix})`] || master["メッセージ(jp)"],
        title:    master[`タイトル(${suffix})`] || master["タイトル(jp)"],
        desc:     master[`詳細(${suffix})`] || master["詳細(jp)"]
      };

      if (mode === 'check') {
        return res.status(200).json({
          success: true,
          bundleLabel: txt.bundle,
          message: txt.message,
          detailedTitle: txt.title,
          detailedDesc: txt.desc,
          buttonLabel: txt.btnLabel,
          imageUrl: master.Imag_Url,
          icon: master.アイコン || 'download',
          groupId: master["重複"]
        });
      }

      if (codeType === 'POINT') {
        if (!targetId) return res.status(200).json({ success: false, message: "Login required" });
        const { data: user } = await supabase.from('users').select('points').eq('id', targetId).maybeSingle();
        if (user) {
           await supabase.from('users').update({ points: user.points + (master["Point PPP"] || 0) }).eq('id', targetId);
           await supabase.from('codes').update({ "USED?": true }).eq('アクティベーションコード', safeCode);
        }
        return res.status(200).json({ success: true, isPointMode: true, addedPoints: master["Point PPP"] || 0, message: `${master["Point PPP"] || 0} pt`, title: txt.title || "ポイントチャージ完了" });
      }

      if (codeType !== 'POINT') {
        let isOwned = false;
        if (targetId) {
          const { data: existingHist } = await supabase.from('histories').select('codes(アクティベーションコード, 重複)').eq('user_id', targetId);
          if (existingHist) {
            isOwned = existingHist.some(h => h.codes && (h.codes["アクティベーションコード"] === safeCode || (master["重複"] && h.codes["重複"] === master["重複"])));
          }
        }
        if (isOwned) return res.status(200).json({ success: false, isAlreadyOwned: true, message: "Already owned" });

        const isRelease = !master["解禁時間"] || (now >= new Date(master["解禁時間"]));
        const retUrl = isRelease ? master.Action_url : "";

        if (targetId) {
           const { error: histErr } = await supabase.from('histories').insert([{ user_id: targetId, code_id: master.id }]);
           if(histErr) console.error("履歴追加エラー:", histErr);
        }
        if (isOnce) {
           const { error: updErr } = await supabase.from('codes').update({ "USED?": true }).eq('アクティベーションコード', safeCode);
           if(updErr) console.error("使用済み更新エラー:", updErr);
        }

        return res.status(200).json({
          success: true, actionUrl: retUrl, bundleLabel: txt.bundle, message: txt.message,         
          detailedTitle: txt.title, detailedDesc: txt.desc, buttonLabel: txt.btnLabel,
          imageUrl: master.Imag_Url, isReleaseDateReached: isRelease, releaseDateIso: master["解禁時間"],
          btnIcon: master.アイコン || 'download', groupId: master["重複"]
        });
      }
    }
    return res.status(200).json({ success: false, message: "Invalid request" });
  } catch (error) {
    console.error("API Error:", error);
    return res.status(500).json({ success: false, message: "Internal Server Error" });
  }
}import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto'; 

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY; // ←ここを変更！
const supabase = createClient(supabaseUrl, supabaseKey);
const ADMIN_ID = "admin_kiryu-sensya";
const ADMIN_PASS = "-GTA6xaxijIl-v4.2xs-2";

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');

  if (req.method === 'OPTIONS') return res.status(200).end();

  const params = req.method === 'POST' ? req.body : req.query;
  const type = params.type;
  const lang = params.lang || 'ja';

  try {
    // 1. ユーザー登録
    if (type === 'register') {
      const { email, password } = params;
      if (!email || !password) return res.status(200).json({ success: false, message: "Missing credentials" });
      const { data: existing } = await supabase.from('users').select('id').eq('email', email).maybeSingle();
      if (existing) return res.status(200).json({ success: false, message: "Exists" });
      const { data: newUser, error } = await supabase.from('users').insert([{ email, password: hashPassword(password), points: 0 }]).select().single();
      if (error) throw error;
      return res.status(200).json({ success: true, userId: newUser.id, message: "OK" });
    }

    // ==========================================
    // ★ 管理者用 新規ユーザー強制作成
    // ==========================================
    if (type === 'admin_create_user') {
      const { email, password } = params;
      if (!email || !password) return res.status(200).json({ success: false, message: "Missing credentials" });
      
      const { data: existing } = await supabase.from('users').select('id').eq('email', email).maybeSingle();
      if (existing) return res.status(200).json({ success: false, message: "そのIDは既に存在します" });
      
      // パスワードを暗号化して保存し、初回変更フラグをtrueにする
      const hashedPass = hashPassword(password);
      const { data: newUser, error } = await supabase.from('users').insert([{ 
          email, 
          password: hashedPass, 
          points: 0,
          needs_password_change: true 
      }]).select().single();
      
      if (error) throw error;
      return res.status(200).json({ success: true, message: "OK" });
    }

    // ==========================================
    // ★ 管理者用 パスワード強制リセット
    // ==========================================
    if (type === 'admin_reset_password') {
      const { adminUser, adminPass, targetEmail, newPassword } = params;
      
      if (adminUser !== ADMIN_ID || adminPass !== ADMIN_PASS) {
         return res.status(200).json({ success: false, message: "権限がありません" });
      }

      const { data: targetUser } = await supabase.from('users').select('id').eq('email', targetEmail).maybeSingle();
      if (!targetUser) {
          return res.status(200).json({ success: false, message: "指定されたユーザーが見つかりません" });
      }

      const hashedNewPass = hashPassword(newPassword);
      const { error: updateError } = await supabase.from('users').update({ 
          password: hashedNewPass,
          needs_password_change: true 
      }).eq('id', targetUser.id);

      if (updateError) {
          return res.status(200).json({ success: false, message: "データベースの更新に失敗しました" });
      }

      return res.status(200).json({ success: true, message: "Password reset successful" });
    }

    // ==========================================
    // ★ 管理者用 ユーザー履歴検索
    // ==========================================
    if (type === 'admin_search') {
      const { adminUser, adminPass, targetEmail } = params;
      
      if (adminUser !== ADMIN_ID || adminPass !== ADMIN_PASS) {
        return res.status(200).json({ success: false, message: "権限がありません" });
      }
      if (!targetEmail) return res.status(200).json({ success: false, message: "対象のメールアドレスを指定してください" });

      const { data: targetUser } = await supabase.from('users').select('id, email').eq('email', targetEmail).maybeSingle();
      if (!targetUser) return res.status(200).json({ success: false, message: "指定されたユーザーが見つかりません" });

      const { data: histories, error: searchError } = await supabase.from('histories')
        .select(`created_at, codes (*)`).eq('user_id', targetUser.id).order('created_at', { ascending: false });

      if (searchError) {
          console.error(searchError);
          return res.status(200).json({ success: false, message: "履歴の取得に失敗しました" });
      }

      const historyData = (histories || []).map(h => ({
        code: h.codes ? h.codes["アクティベーションコード"] : "不明",
        title: h.codes ? (h.codes["タイトル(jp)"] || "不明なコンテンツ") : "不明なコンテンツ",
        date: new Date(h.created_at).toLocaleString('ja-JP')
      }));

      return res.status(200).json({ success: true, userId: targetUser.email, history: historyData });
    }

    // ==========================================
    // 2. ユーザーログイン (暗号化＆初回チェック対応)
    // ==========================================
    if (type === 'user_login') {
      const { email, password } = params;
      if (email === ADMIN_ID && password === ADMIN_PASS) {
        return res.status(200).json({ success: true, isAdmin: true });
      }
      const { data: user } = await supabase.from('users').select('*').eq('email', email).maybeSingle();
      
      if (user && user.password === hashPassword(password)) {
        if (user.needs_password_change) {
            return res.status(200).json({ success: true, requirePasswordChange: true, userId: user.id });
        }
        return res.status(200).json({ success: true, userId: user.id, points: user.points, history: [] });
      }
      return res.status(200).json({ success: false, message: "Invalid" });
    }

    // ==========================================
    // ★ パスワード強制変更処理
    // ==========================================
    if (type === 'change_password') {
      const { userId, oldPassword, newPassword } = params;
      const { data: user } = await supabase.from('users').select('*').eq('id', userId).maybeSingle();
      
      if (user && user.password === hashPassword(oldPassword)) {
          await supabase.from('users').update({
              password: hashPassword(newPassword),
              needs_password_change: false
          }).eq('id', userId);
          return res.status(200).json({ success: true });
      }
      return res.status(200).json({ success: false, message: "現在のパスワードが間違っています。" });
    }

    // ==========================================
    // セッション復帰時の最新情報取得
    // ==========================================
    if (type === 'get_user_info') {
      const { userId } = params;
      if (!userId) return res.status(200).json({ success: false, message: "Missing userId" });
      
      const { data: user, error } = await supabase.from('users').select('points').eq('id', userId).single();
      if (error || !user) {
        return res.status(200).json({ success: false, message: "User not found" });
      }
      return res.status(200).json({ success: true, points: user.points });
    }

    // 3. 利用可能なコンテンツ一覧 (Store)
    if (type === 'get_available') {
      const userId = params.userId;
      const { data: allCodes } = await supabase.from('codes').select('*');
      
      let ownedCodeIds = new Set();
      let ownedGroupIds = new Set();

      if (userId && userId !== "GUEST") {
        const { data: history } = await supabase.from('histories').select('code_id').eq('user_id', userId);
        if (history) {
            const codeIds = history.map(h => h.code_id);
            ownedCodeIds = new Set(codeIds);
            if (codeIds.length > 0) {
                const { data: ownedCodes } = await supabase.from('codes').select('重複').in('id', codeIds);
                if(ownedCodes) ownedGroupIds = new Set(ownedCodes.map(c => c["重複"]).filter(Boolean));
            }
        }
      }

      const lMap = { ja: 'jp', en: 'en', zh: 'SC', 'zh-TW': 'TC', ko: 'ko', ru: 'ru' };
      const suffix = lMap[lang] || 'jp';

      const filteredCodes = (allCodes || []).filter(c => {
          const isActive = c["有効/無効"] === true || String(c["有効/無効"]).toUpperCase() === 'TRUE';
          const isShow = String(c["show/ hide"] || "").trim().toLowerCase() === 'show';
          const cType = String(c.Types || "").trim().toUpperCase();
          if (!isActive || !isShow || cType === 'POINT') return false;
          const isOnce = (cType === 'ONCE' || cType === '');
          const isUsed = c["USED?"] === true || String(c["USED?"]).trim().toUpperCase() === 'TRUE';
          if (isOnce && isUsed) return false;
          return true;
      });

      const items = filteredCodes.map(code => {
        const isOwned = ownedCodeIds.has(code.id) || (code["重複"] && ownedGroupIds.has(code["重複"]));
        return {
          code: code["アクティベーションコード"],
          title: code[`タイトル(${suffix})`] || code["タイトル(jp)"],
          message: code[`メッセージ(${suffix})`] || code["メッセージ(jp)"],
          extraInfo: code[`詳細(${suffix})`] || code["詳細(jp)"],
          imageUrl: code.Imag_Url,
          url: code.Action_url,
          releaseDateIso: code["解禁時間"],
          icon: code.アイコン || 'download',
          groupId: code["重複"],
          buttonLabel: code[`ボタン(${suffix})`] || code["ボタン(jp)"],
          price: code["価格"] || 0,
          isOwned: isOwned
        };
      });
      return res.status(200).json({ success: true, items });
    }

    // 4. ユーザー履歴の取得
    if (type === 'get_history') {
      const userId = params.userId;
      if (!userId || userId === "GUEST") return res.status(200).json({ success: false, message: "No User ID" });
      const { data: user, error: userErr } = await supabase.from('users').select('points').eq('id', userId).maybeSingle();
      if (userErr || !user) return res.status(200).json({ success: false, message: "User not found" });

      const { data: histories } = await supabase.from('histories').select(`created_at, codes (*)`).eq('user_id', userId).order('created_at', { ascending: false });

      const lMap = { ja: 'jp', en: 'en', zh: 'SC', 'zh-TW': 'TC', ko: 'ko', ru: 'ru' };
      const suffix = lMap[lang] || 'jp';

      const historyData = (histories || []).map(h => {
        const c = h.codes;
        if(!c) return null;
        return {
          code: c["アクティベーションコード"],
          date: h.created_at,
          title: c[`タイトル(${suffix})`] || c["タイトル(jp)"],
          message: c[`メッセージ(${suffix})`] || c["メッセージ(jp)"],
          url: c.Action_url,
          imageUrl: c.Imag_Url,
          icon: c.アイコン || 'download',
          releaseDateIso: c["解禁時間"],
          extraInfo: c[`詳細(${suffix})`] || c["詳細(jp)"],
          groupId: c["重複"],
          buttonLabel: c[`ボタン(${suffix})`] || c["ボタン(jp)"]
        };
      }).filter(Boolean);
      return res.status(200).json({ success: true, points: user.points, history: historyData });
    }

    // 5. ポイントでの購入
    if (type === 'purchase') {
      const { userId, code } = params;
      if (!userId || userId === "GUEST") return res.status(200).json({ success: false, message: "Login required" });
      const { data: master } = await supabase.from('codes').select('*').eq('アクティベーションコード', code).maybeSingle();
      if (!master) return res.status(200).json({ success: false, message: "Item not found" });
      const { data: user } = await supabase.from('users').select('points').eq('id', userId).maybeSingle();
      if (!user) return res.status(200).json({ success: false, message: "User not found" });

      const { data: existingHist } = await supabase.from('histories').select('codes(重複)').eq('user_id', userId);
      let alreadyOwned = false;
      if (existingHist) {
         alreadyOwned = existingHist.some(h => h.codes && (h.codes["アクティベーションコード"] === code || (master["重複"] && h.codes["重複"] === master["重複"])));
      }
      if (alreadyOwned) return res.status(200).json({ success: false, message: "Already owned" });

      const price = master["価格"] || 0;
      if (user.points < price) return res.status(200).json({ success: false, message: "Not enough points" });
      await supabase.from('users').update({ points: user.points - price }).eq('id', userId);
      await supabase.from('histories').insert([{ user_id: userId, code_id: master.id }]);
      return res.status(200).json({ success: true, remainingPoints: user.points - price });
    }

    // ==========================================
    // 6. コードの確認(check) と 引き換え(redeem)
    // ==========================================
    if (type === 'check' || type === 'redeem') {
      const { key, userId, mode } = params;
      const safeCode = (key || "").replace(/[^A-Z0-9\-]/gi, "").toUpperCase();

      const { data: master, error } = await supabase.from('codes').select('*').eq('アクティベーションコード', safeCode).maybeSingle();

      if (error || !master) {
          return res.status(200).json({ success: false, message: "This code is invalid." });
      }

      const isActive = master["有効/無効"] === true || String(master["有効/無効"]).trim().toUpperCase() === 'TRUE';
      if (!isActive) {
        return res.status(200).json({ success: false, message: "This code is invalid." });
      }

      const now = new Date();
      if (master["有効時間"] && now > new Date(master["有効時間"])) {
        return res.status(200).json({ success: false, message: "This code is invalid." });
      }

      const codeType = (master.Types || "").trim().toUpperCase();
      const isOnce = (codeType === 'ONCE' || codeType === '');
      const rawUsed = master["USED?"];
      const isCodeUsed = rawUsed === true || String(rawUsed).trim().toUpperCase() === 'TRUE';

      if ((isOnce || codeType === 'POINT') && isCodeUsed) {
        return res.status(200).json({ success: false, message: "This code has already been used." });
      }
      const lMap = { ja: 'jp', en: 'en', zh: 'SC', 'zh-TW': 'TC', ko: 'ko', ru: 'ru' };
      const suffix = lMap[lang] || 'jp';

      const txt = {
        btnLabel: master[`ボタン(${suffix})`] || master["ボタン(jp)"],
        bundle:   master[`バンドル(${suffix})`] || master["バンドル(jp)"],
        message:  master[`メッセージ(${suffix})`] || master["メッセージ(jp)"],
        title:    master[`タイトル(${suffix})`] || master["タイトル(jp)"],
        desc:     master[`詳細(${suffix})`] || master["詳細(jp)"]
      };

      if (mode === 'check') {
        return res.status(200).json({
          success: true,
          bundleLabel: txt.bundle,
          message: txt.message,
          detailedTitle: txt.title,
          detailedDesc: txt.desc,
          buttonLabel: txt.btnLabel,
          imageUrl: master.Imag_Url,
          icon: master.アイコン || 'download',
          groupId: master["重複"]
        });
      }

      if (codeType === 'POINT') {
        if (!userId || userId === "GUEST") return res.status(200).json({ success: false, message: "Login required" });
        const { data: user } = await supabase.from('users').select('points').eq('id', userId).maybeSingle();
        if (user) {
           await supabase.from('users').update({ points: user.points + (master["Point PPP"] || 0) }).eq('id', userId);
           await supabase.from('codes').update({ "USED?": true }).eq('アクティベーションコード', safeCode);
        }
        return res.status(200).json({ success: true, isPointMode: true, addedPoints: master["Point PPP"] || 0, message: `${master["Point PPP"] || 0} pt`, title: txt.title || "ポイントチャージ完了" });
      }

      if (codeType !== 'POINT') {
        let isOwned = false;
        if (userId && userId !== "GUEST") {
          const { data: existingHist } = await supabase.from('histories').select('codes(アクティベーションコード, 重複)').eq('user_id', userId);
          if (existingHist) {
            isOwned = existingHist.some(h => h.codes && (h.codes["アクティベーションコード"] === safeCode || (master["重複"] && h.codes["重複"] === master["重複"])));
          }
        }
        if (isOwned) return res.status(200).json({ success: false, isAlreadyOwned: true, message: "Already owned" });

        const isRelease = !master["解禁時間"] || (now >= new Date(master["解禁時間"]));
        const retUrl = isRelease ? master.Action_url : "";

        if (userId && userId !== "GUEST") {
           const { error: histErr } = await supabase.from('histories').insert([{ user_id: userId, code_id: master.id }]);
           if(histErr) console.error("履歴追加エラー:", histErr);
        }
        if (isOnce) {
           const { error: updErr } = await supabase.from('codes').update({ "USED?": true }).eq('アクティベーションコード', safeCode);
           if(updErr) console.error("使用済み更新エラー:", updErr);
        }

        return res.status(200).json({
          success: true, actionUrl: retUrl, bundleLabel: txt.bundle, message: txt.message,         
          detailedTitle: txt.title, detailedDesc: txt.desc, buttonLabel: txt.btnLabel,
          imageUrl: master.Imag_Url, isReleaseDateReached: isRelease, releaseDateIso: master["解禁時間"],
          btnIcon: master.アイコン || 'download', groupId: master["重複"]
        });
      }
    }
    return res.status(200).json({ success: false, message: "Invalid request" });
  } catch (error) {
    console.error("API Error:", error);
    return res.status(500).json({ success: false, message: "Internal Server Error" });
  }
}
