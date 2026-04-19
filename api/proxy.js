import { createClient } from '@supabase/supabase-js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const requestCounts = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000; // 1分間
const MAX_REQUESTS = 100; // 安全のため少し緩和

// 必須の環境変数を取得
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

if (!supabaseUrl || !supabaseKey || !JWT_SECRET) {
  throw new Error("FATAL ERROR: 必須の環境変数（Supabase設定またはJWT_SECRET）が設定されていません。");
}

const supabase = createClient(supabaseUrl, supabaseKey);

const ALLOWED_ORIGINS = [
  'https://kiryu10-standard.vercel.app',
  'https://kiryu10-enterprise.vercel.app',
  'http://localhost:3000'
];

export default async function handler(req, res) {
  // CORS設定
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') return res.status(200).end();

  try {
    // --- 1. レートリミット (安全なIP取得) ---
    // サーバーレス環境で req.socket が無い場合のエラーを回避 (?. を使用)
    const ip = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown';
    const now = Date.now();
    if (!requestCounts.has(ip)) {
        requestCounts.set(ip, { count: 1, startTime: now });
    } else {
        const data = requestCounts.get(ip);
        if (now - data.startTime > RATE_LIMIT_WINDOW) {
            requestCounts.set(ip, { count: 1, startTime: now });
        } else {
            data.count++;
            if (data.count > MAX_REQUESTS) {
                return res.status(429).json({ success: false, message: "リクエストが多すぎます。しばらく待ってから再試行してください。" });
            }
        }
    }

    // --- 2. ボディの安全なパース ---
    let params = {};
    if (req.method === 'POST') {
        if (typeof req.body === 'string') {
            try { params = JSON.parse(req.body); } catch(e) { params = {}; }
        } else {
            params = req.body || {};
        }
    } else {
        params = req.query || {};
    }
    // undefinedによる .startsWith クラッシュを防ぐため空文字をフォールバック
    const type = params.type || ''; 
    const lang = params.lang || 'ja';

    // --- 3. HttpOnly Cookie と Header からトークンを安全に取得 ---
    let authUserId = null;
    let isAdmin = false;
    let token = null;

    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.split(' ')[1];
    }

    const cookieHeader = req.headers.cookie;
    if (cookieHeader) {
        // 空白の有無に左右されない堅牢なCookieパース
        const cookies = {};
        cookieHeader.split(';').forEach(c => {
            const parts = c.split('=');
            if (parts.length >= 2) {
                cookies[parts[0].trim()] = parts[1].trim();
            }
        });
        if (cookies.admin_token) token = cookies.admin_token;
    }

    if (token) {
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        authUserId = decoded.userId;
        isAdmin = decoded.isAdmin || false;
      } catch (e) {
        // トークン無効時はそのまま続行（後の権限チェックで弾く）
      }
    }

    // --- 4. 監査ログ関数 (エラーを握りつぶす安全設計) ---
    const logAudit = async (actionType, targetUser, details) => {
        try {
            if (isAdmin && authUserId) {
                await supabase.from('admin_audit_logs').insert([{
                    admin_id: authUserId,
                    action_type: actionType,
                    target_user: targetUser,
                    details: details
                }]);
            }
        } catch (e) {
            console.error("Audit Log Error:", e);
            // ログ記録に失敗してもメイン処理を止めない
        }
    };

    // ==========================================
    // 認証系処理
    // ==========================================
    
    // ユーザー登録
    if (type === 'register') {
      const { email, password } = params;
      if (!email || !password) return res.status(200).json({ success: false, message: "Missing credentials" });
      const { data: existing } = await supabase.from('users').select('id').eq('email', email).maybeSingle();
      if (existing) return res.status(200).json({ success: false, message: "Exists" });
      
      const hashedPassword = await bcrypt.hash(password, 10);
      const { data: newUser, error } = await supabase.from('users').insert([{ email, password: hashedPassword, points: 0 }]).select().single();
      if (error) throw error;
      return res.status(200).json({ success: true, userId: newUser.id, message: "OK" });
    }

    // ユーザーログイン
    if (type === 'user_login') {
      const { email, password } = params;
      const { data: user } = await supabase.from('users').select('*').eq('email', email).maybeSingle();
      
      if (user && await bcrypt.compare(password, user.password)) {
          const isUserAdmin = user.is_admin === true;
          if (user.needs_password_change && !isUserAdmin) {
              return res.status(200).json({ success: true, requirePasswordChange: true, userId: user.id });
          }

          const tokenStr = jwt.sign({ userId: user.id, isAdmin: isUserAdmin }, JWT_SECRET, { expiresIn: '24h' });
          
          if (isUserAdmin) {
              const isProd = process.env.NODE_ENV === 'production';
              const secure = isProd ? 'Secure;' : '';
              res.setHeader('Set-Cookie', [
                  `admin_token=${tokenStr}; HttpOnly; ${secure} SameSite=Strict; Path=/; Max-Age=86400`,
                  `admin_logged_in=true; ${secure} SameSite=Strict; Path=/; Max-Age=86400`
              ]);
          }
          
          return res.status(200).json({ success: true, isAdmin: isUserAdmin, token: tokenStr, userId: user.id });
      }
      return res.status(200).json({ success: false, message: "Invalid" });
    }

    // ログアウト
    if (type === 'admin_logout') {
        res.setHeader('Set-Cookie', [
            `admin_token=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`,
            `admin_logged_in=; SameSite=Strict; Path=/; Max-Age=0`
        ]);
        return res.status(200).json({ success: true });
    }

    // ==========================================
    // 管理者用機能 (厳格なトークン権限チェック)
    // ==========================================
    if (type.startsWith('admin_')) {
        if (!isAdmin) {
            return res.status(401).json({ success: false, message: "管理者権限がありません" });
        }

        if (type === 'admin_create_user') {
            const { email, password } = params;
            if (!email || !password) return res.status(200).json({ success: false, message: "Missing credentials" });
            const { data: existing } = await supabase.from('users').select('id').eq('email', email).maybeSingle();
            if (existing) return res.status(200).json({ success: false, message: "そのIDは既に存在します" });
            
            const hashedPassword = await bcrypt.hash(password, 10);
            const { error } = await supabase.from('users').insert([{ email, password: hashedPassword, points: 0, needs_password_change: true }]);
            if (error) throw error;
            await logAudit('CREATE_USER', email, {});
            return res.status(200).json({ success: true, message: "OK" });
        }

        if (type === 'admin_reset_password') {
            const { targetEmail, newPassword } = params;
            const { data: targetUser } = await supabase.from('users').select('id').eq('email', targetEmail).maybeSingle();
            if (!targetUser) return res.status(200).json({ success: false, message: "ユーザーが見つかりません" });

            const hashedNewPass = await bcrypt.hash(newPassword, 10);
            const { error } = await supabase.from('users').update({ password: hashedNewPass, needs_password_change: true }).eq('id', targetUser.id);
            if (error) return res.status(200).json({ success: false, message: "データベースの更新に失敗しました" });
            await logAudit('RESET_PASSWORD', targetEmail, {});
            return res.status(200).json({ success: true, message: "Password reset successful" });
        }

        if (type === 'admin_search') {
            const { targetEmail } = params;
            const { data: targetUser } = await supabase.from('users').select('id, email, points').eq('email', targetEmail).maybeSingle();
            if (!targetUser) return res.status(200).json({ success: false, message: "ユーザーが見つかりません" });

            const { data: histories } = await supabase.from('histories').select(`created_at, codes (*)`).eq('user_id', targetUser.id).order('created_at', { ascending: false });

            const historyData = (histories || []).map(h => ({
              code: h.codes ? h.codes["アクティベーションコード"] : "不明",
              title: h.codes ? (h.codes["タイトル(jp)"] || "不明なコンテンツ") : "不明なコンテンツ",
              date: new Date(h.created_at).toLocaleString('ja-JP')
            }));
            
            return res.status(200).json({ success: true, userId: targetUser.email, points: targetUser.points || 0, history: historyData });
        }

        if (type === 'admin_check_code') {
            const { code } = params;
            if (!code) return res.status(200).json({ success: false, message: "コードを指定してください" });

            const safeCode = String(code).replace(/[^A-Z0-9\-]/gi, "").toUpperCase();
            const { data: master, error } = await supabase.from('codes').select('*').eq('アクティベーションコード', safeCode).maybeSingle();
            
            if (error || !master) {
                return res.status(200).json({ success: false, message: "指定されたコードはデータベースに存在しません" });
            }

            const isUsed = master["USED?"] === true || String(master["USED?"]).trim().toUpperCase() === 'TRUE';
            let usedTime = null;
            let usedBy = null;

            if (isUsed) {
                const { data: history } = await supabase.from('histories').select('created_at, users(email)').eq('code_id', master.id).order('created_at', { ascending: false }).limit(1).maybeSingle();
                if (history) {
                    usedTime = history.created_at;
                    usedBy = history.users ? history.users.email : '不明なユーザー';
                }
            }

            return res.status(200).json({ success: true, code: master["アクティベーションコード"], title: master["タイトル(jp)"] || master["バンドル(jp)"] || "不明", isUsed: isUsed, usedTime: usedTime, usedBy: usedBy });
        }

        if (type === 'admin_reset_code') {
            const { code } = params;
            const safeCode = String(code).replace(/[^A-Z0-9\-]/gi, "").toUpperCase();
            const { error } = await supabase.from('codes').update({ "USED?": false }).eq('アクティベーションコード', safeCode);
            if (error) return res.status(200).json({ success: false, message: "データベースの更新に失敗しました" });
            await logAudit('RESET_CODE', null, { code: safeCode });
            return res.status(200).json({ success: true, message: "OK" });
        }

        if (type === 'admin_set_points') {
            const { targetEmail, amount } = params;
            const { data: targetUser } = await supabase.from('users').select('id').eq('email', targetEmail).maybeSingle();
            if (!targetUser) return res.status(200).json({ success: false, message: "対象のユーザーが見つかりません" });

            const newPoints = Math.max(0, amount);
            const { error } = await supabase.from('users').update({ points: newPoints }).eq('id', targetUser.id);
            if (error) return res.status(200).json({ success: false, message: "ポイントの更新に失敗しました" });
            
            await logAudit('SET_POINTS', targetEmail, { amount: newPoints });
            return res.status(200).json({ success: true, message: "OK" });
        }

        if (type === 'admin_delete_user') {
            const { targetEmail } = params;
            const { data: targetUser } = await supabase.from('users').select('id').eq('email', targetEmail).maybeSingle();
            if (!targetUser) return res.status(200).json({ success: false, message: "ユーザーが見つかりません" });

            await supabase.from('histories').delete().eq('user_id', targetUser.id);
            const { error } = await supabase.from('users').delete().eq('id', targetUser.id);
            if (error) return res.status(200).json({ success: false, message: "アカウントの削除に失敗しました" });
            
            await logAudit('DELETE_USER', targetEmail, {});
            return res.status(200).json({ success: true, message: "OK" });
        }

        if (type === 'admin_save_code') {
            const { payload } = params;
            if (!payload || !payload["アクティベーションコード"]) return res.status(200).json({ success: false, message: "コードが指定されていません" });

            const safeCode = String(payload["アクティベーションコード"]).replace(/[^A-Z0-9\-]/gi, "").toUpperCase();
            payload["アクティベーションコード"] = safeCode;
            payload["有効/無効"] = true; 

            const { data: existing } = await supabase.from('codes').select('id').eq('アクティベーションコード', safeCode).maybeSingle();

            let error;
            if (existing) {
                const res = await supabase.from('codes').update(payload).eq('id', existing.id);
                error = res.error;
            } else {
                const res = await supabase.from('codes').insert([payload]);
                error = res.error;
            }

            if (error) return res.status(200).json({ success: false, message: "データベースの保存に失敗しました" });
            await logAudit('SAVE_CODE', null, { code: safeCode });
            return res.status(200).json({ success: true, message: "OK" });
        }
    }

    // ==========================================
    // 一般ユーザー用機能
    // ==========================================
    if (type === 'revoke_content') {
      const { code } = params;
      if (!authUserId) return res.status(401).json({ success: false, message: "Unauthorized" });

      const { data: targetCode } = await supabase.from('codes').select('id').eq('アクティベーションコード', code).maybeSingle();
      if (!targetCode) return res.status(200).json({ success: false, message: "対象のコードが見つかりません" });

      const { error: deleteError } = await supabase.from('histories').delete().match({ user_id: authUserId, code_id: targetCode.id });
      if (deleteError) return res.status(200).json({ success: false, message: "データベースの削除に失敗しました" });
      return res.status(200).json({ success: true, message: "Revoked successfully" });
    }

    if (type === 'change_password') {
      const { userId, oldPassword, newPassword } = params;
      const targetId = userId || authUserId;
      
      // ① IDがフロントエンドから正しく届いているかチェック
      if (!targetId) {
          return res.status(200).json({ success: false, message: "システムエラー: ユーザーIDが認識できません" });
      }

      const { data: user, error: userError } = await supabase.from('users').select('*').eq('id', targetId).maybeSingle();
      
      // ② ユーザーがDBに存在するかチェック
      if (userError || !user) {
          return res.status(200).json({ success: false, message: "システムエラー: 対象のユーザーが見つかりません" });
      }

      // ③ パスワードの照合
      const isValidOldPass = await bcrypt.compare(oldPassword, user.password);
      if (isValidOldPass) {
          const hashedNewPass = await bcrypt.hash(newPassword, 10);
          const { error: updateError } = await supabase.from('users').update({ 
              password: hashedNewPass, 
              needs_password_change: false 
          }).eq('id', targetId);
          
          if (updateError) {
              return res.status(200).json({ success: false, message: "データベースの更新に失敗しました" });
          }
          
          return res.status(200).json({ success: true });
      }
      
      // ④ 本当にパスワードが違う場合のみエラーを出す
      return res.status(200).json({ success: false, message: "現在のパスワードが間違っています。" });
    }

    if (type === 'get_user_info') {
      if (!authUserId) return res.status(401).json({ success: false, message: "Unauthorized" });
      const { data: user, error } = await supabase.from('users').select('points').eq('id', authUserId).single();
      if (error || !user) return res.status(200).json({ success: false, message: "User not found" });
      return res.status(200).json({ success: true, points: user.points });
    }

    if (type === 'get_available') {
      const isGuest = (!params.userId || params.userId === "GUEST");
      const targetId = isGuest ? null : authUserId; 
      
      const { data: allCodes } = await supabase.from('codes').select('*').order('id', { ascending: true });
      let ownedCodeIds = new Set(); let ownedGroupIds = new Set();

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
          code: code["アクティベーションコード"], title: code[`タイトル(${suffix})`] || code["タイトル(jp)"],
          message: code[`メッセージ(${suffix})`] || code["メッセージ(jp)"], extraInfo: code[`詳細(${suffix})`] || code["詳細(jp)"],
          imageUrl: code.Imag_Url, url: code.Action_url, releaseDateIso: code["解禁時間"], icon: code.アイコン || 'download',
          groupId: code["重複"], buttonLabel: code[`ボタン(${suffix})`] || code["ボタン(jp)"], price: code["価格"] || 0, isOwned: isOwned
        };
      });
      return res.status(200).json({ success: true, items });
    }

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
          code: c["アクティベーションコード"], date: h.created_at, title: c[`タイトル(${suffix})`] || c["タイトル(jp)"],
          message: c[`メッセージ(${suffix})`] || c["メッセージ(jp)"], url: c.Action_url, imageUrl: c.Imag_Url,
          icon: c.アイコン || 'download', releaseDateIso: c["解禁時間"], extraInfo: c[`詳細(${suffix})`] || c["詳細(jp)"],
          groupId: c["重複"], buttonLabel: c[`ボタン(${suffix})`] || c["ボタン(jp)"]
        };
      }).filter(Boolean);
      return res.status(200).json({ success: true, points: user.points, history: historyData });
    }

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

    if (type === 'check' || type === 'redeem') {
      const key = params.code || params.key; 
      const mode = params.mode || type;
      const targetId = authUserId; 

      const safeCode = (key || "").replace(/[^A-Z0-9\-]/gi, "").toUpperCase();
      const { data: master, error } = await supabase.from('codes').select('*').eq('アクティベーションコード', safeCode).maybeSingle();

      if (error || !master) {
          return res.status(200).json({ success: false, message: "Invalid code" });
      }

      const isActive = master["有効/無効"] === true || String(master["有効/無効"]).trim().toUpperCase() === 'TRUE';
      if (!isActive) return res.status(200).json({ success: false, message: "Invalid code" });

      const now = new Date();
      if (master["有効時間"] && now > new Date(master["有効時間"])) {
        return res.status(200).json({ success: false, message: "Invalid code" });
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
        btnLabel: master[`ボタン(${suffix})`] || master["ボタン(jp)"], bundle: master[`バンドル(${suffix})`] || master["バンドル(jp)"],
        message: master[`メッセージ(${suffix})`] || master["メッセージ(jp)"], title: master[`タイトル(${suffix})`] || master["タイトル(jp)"],
        desc: master[`詳細(${suffix})`] || master["詳細(jp)"]
      };

      if (mode === 'check') {
        return res.status(200).json({
          success: true, bundleLabel: txt.bundle, message: txt.message, detailedTitle: txt.title, detailedDesc: txt.desc,
          buttonLabel: txt.btnLabel, imageUrl: master.Imag_Url, icon: master.アイコン || 'download', groupId: master["重複"]
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

    // どの条件にも合致しなかった場合
    return res.status(200).json({ success: false, message: "Invalid request" });

  } catch (error) {
    // 全体を包むキャッチブロックで確実にエラーを捉える
    console.error("Critical API Error:", error);
    return res.status(500).json({ success: false, message: "Internal Server Error" });
  }
}
