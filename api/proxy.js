import { createClient } from '@supabase/supabase-js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const requestCounts = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000;
const MAX_REQUESTS = 100;

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

if (!supabaseUrl || !supabaseKey || !JWT_SECRET) {
  throw new Error("FATAL ERROR: 必須の環境変数が設定されていません。");
}

const supabase = createClient(supabaseUrl, supabaseKey);

const ALLOWED_ORIGINS = [
  'https://kiryu10-standard.vercel.app',
  'https://kiryu10-enterprise.vercel.app',
  'http://localhost:3000'
];

export default async function handler(req, res) {
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') return res.status(200).end();

  try {
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
    
    const type = params.type || ''; 
    const lang = params.lang || 'ja';

    let authUserId = null;
    let isAdmin = false;
    let token = null;

    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.split(' ')[1];
    }

    const cookieHeader = req.headers.cookie;
    if (cookieHeader) {
        const cookies = {};
        cookieHeader.split(';').forEach(c => {
            const parts = c.split('=');
            if (parts.length >= 2) {
                cookies[parts[0].trim()] = parts[1].trim();
            }
        });
      if (!token && cookies.admin_token) {
            token = cookies.admin_token;
        }
    }

    if (token) {
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        authUserId = decoded.userId;
        isAdmin = decoded.isAdmin || false;
      } catch (e) {
      }
    }
    // ==========================================
    // ▼ 追加: 全アクセスログの記録処理 ▼
    // ==========================================
    const userAgent = req.headers['user-agent'] || 'unknown';
    const safeType = type || 'unknown';
    
    // ▼ ログに記録したくないアクション名をリストアップ ▼
    const ignoredActions = ['get_history', 'get_available', 'error_search', 'admin_get_access_logs', 'admin_search', 'admin_set_points'];
    
    // ★入力されたコードを取得するための変数を追加
    let targetCode = null;
    if (safeType === 'check' || safeType === 'redeem') {
        targetCode = params.code || params.key || null; 
    }
    
    // 除外リストに含まれていない場合のみログを保存する
    if (!ignoredActions.includes(safeType)) {
        try {
            await supabase.from('access_logs').insert([{
                ip_address: ip,
                action_type: safeType,
                user_id: authUserId || null,
                user_agent: userAgent,
                target_code: targetCode // ★変数として正しく認識される
            }]);
        } catch (logError) {
            console.error("Access Log Insert Error:", logError);
        }
    }
    
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
        }
    };

    // ==========================================
    // 認証系処理
    // ==========================================
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
    if (type === 'change_password') {
      const { userId, oldPassword, newPassword } = params;
      if (!userId || !oldPassword || !newPassword) {
          return res.status(200).json({ success: false, message: "Missing fields" });
      }

      // ユーザーの存在確認と、古いパスワードが合っているかチェック
      const { data: user } = await supabase.from('users').select('*').eq('id', userId).maybeSingle();
      if (!user) return res.status(200).json({ success: false, message: "User not found" });

      const isMatch = await bcrypt.compare(oldPassword, user.password);
      if (!isMatch) return res.status(200).json({ success: false, message: "Invalid current password" });

      // 新しいパスワードを暗号化して保存 ＆ パスワード変更要求（needs_password_change）を解除
      const hashedNewPassword = await bcrypt.hash(newPassword, 10);
      const { error } = await supabase.from('users').update({ 
          password: hashedNewPassword, 
          needs_password_change: false 
      }).eq('id', userId);

      if (error) {
          return res.status(200).json({ success: false, message: "Database update failed" });
      }

      return res.status(200).json({ success: true, message: "Password updated successfully" });
    }

    if (type === 'admin_logout') {
        res.setHeader('Set-Cookie', [
            `admin_token=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`,
            `admin_logged_in=; SameSite=Strict; Path=/; Max-Age=0`
        ]);
        return res.status(200).json({ success: true });
    }

    // ==========================================
    // 管理者用機能
    // ==========================================
    if (type.startsWith('admin_')) {
        if (!isAdmin) return res.status(401).json({ success: false, message: "管理者権限がありません" });
      if (type === 'admin_get_access_logs') {
            const limit = params.limit || 100;
            
            const { data: logs, error } = await supabase.from('access_logs')
                .select(`
                    id, 
                    created_at, 
                    ip_address, 
                    action_type, 
                    user_agent,
                    target_code,
                    user_id
                `)
                .neq('action_type', 'admin_get_access_logs') // ★この1行を追加して除外する
                .order('created_at', { ascending: false })
                .limit(limit);

            if (error) {
                // エラーの詳細な理由もフロントエンドに返すように強化
                return res.status(200).json({ success: false, message: "ログの取得に失敗しました", error: error.message });
            }

            const formattedLogs = (logs || []).map(log => ({
                id: log.id,
                date: new Date(log.created_at).toLocaleString('ja-JP'),
                ip: log.ip_address,
                type: log.action_type,
                code: log.target_code || '-',
                // ▼ メールアドレスの代わりに、エラーが起きないユーザーIDを表示します
                email: log.user_id ? `ID: ${log.user_id.substring(0, 8)}...` : '未ログイン (GUEST)',
                userAgent: log.user_agent
            }));

            return res.status(200).json({ success: true, logs: formattedLogs });
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

        if (type === 'admin_revoke_content') {
            const { targetEmail, code } = params;
            if (!targetEmail || !code) return res.status(200).json({ success: false, message: "対象ユーザーまたはコードが指定されていません" });

            const { data: targetUser } = await supabase.from('users').select('id').eq('email', targetEmail).maybeSingle();
            if (!targetUser) return res.status(200).json({ success: false, message: "ユーザーが見つかりません" });

            const safeCode = String(code).replace(/[^A-Z0-9\-]/gi, "").toUpperCase();
            const { data: targetCode } = await supabase.from('codes').select('id').eq('アクティベーションコード', safeCode).maybeSingle();
            if (!targetCode) return res.status(200).json({ success: false, message: "対象のコードが見つかりません" });

            const { error: deleteError } = await supabase.from('histories').delete().match({ user_id: targetUser.id, code_id: targetCode.id });
            if (deleteError) return res.status(200).json({ success: false, message: "データベースの更新に失敗しました" });

            await logAudit('REVOKE_CONTENT', targetEmail, { code: safeCode });
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

            const { data: histories } = await supabase.from('histories').select(`created_at, codes (*, contents(*))`).eq('user_id', targetUser.id).order('created_at', { ascending: false });

            const historyData = (histories || []).map(h => {
              const cInfo = h.codes?.contents || {};
              return {
                code: h.codes ? h.codes["アクティベーションコード"] : "不明",
                title: cInfo["タイトル(jp)"] || "不明なコンテンツ",
                date: new Date(h.created_at).toLocaleString('ja-JP')
              };
            });
            
            return res.status(200).json({ success: true, userId: targetUser.email, points: targetUser.points || 0, history: historyData });
        }

        if (type === 'admin_check_code') {
            const { code } = params;
            const safeCode = String(code).replace(/[^A-Z0-9\-]/gi, "").toUpperCase();
            const { data: master, error } = await supabase.from('codes').select('*, contents(*)').eq('アクティベーションコード', safeCode).maybeSingle();
            
            if (error || !master) return res.status(200).json({ success: false, message: "存在しません" });

            const isUsed = master["USED?"] === true || String(master["USED?"]).trim().toUpperCase() === 'TRUE';
            let usedTime = null;
            let usedBy = null;

            if (isUsed) {
                const { data: history } = await supabase.from('histories').select('created_at, users(email)').eq('code_id', master.id).order('created_at', { ascending: false }).limit(1).maybeSingle();
                if (history) {
                    usedTime = history.created_at;
                    usedBy = history.users ? history.users.email : '不明';
                }
            }
            
            const cInfo = master.contents || {};
            return res.status(200).json({ success: true, code: master["アクティベーションコード"], title: cInfo["タイトル(jp)"] || cInfo["バンドル(jp)"] || "不明", isUsed, usedTime, usedBy });
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

        // ✅ コンテンツの保存処理（旧 admin_save_code と差し替えた部分）
        if (type === 'admin_save_content') {
            const { payload } = params;
            const contentId = payload.id;
            delete payload.id; 

            let error, data;
            if (contentId) {
                const res = await supabase.from('contents').update(payload).eq('id', contentId).select('id').single();
                error = res.error; data = res.data;
            } else {
                const res = await supabase.from('contents').insert([payload]).select('id').single();
                error = res.error; data = res.data;
            }
            
            if (error) return res.status(200).json({ success: false, message: error.message });
            await logAudit('SAVE_CONTENT', null, { id: data ? data.id : contentId });
            return res.status(200).json({ success: true, message: `OK`, contentId: data ? data.id : contentId });
        }

        // ✅ コードの新規作成処理
        if (type === 'admin_create_code') {
            const { contentId, code, codeType, pointPpp, isActive } = params;
            if (!contentId || !code) return res.status(200).json({ success: false, message: "必須項目が不足しています" });
            
            const safeCode = String(code).replace(/[^A-Z0-9\-]/gi, "").toUpperCase();
            
            const { error } = await supabase.from('codes').insert([{
                content_id: contentId,
                "アクティベーションコード": safeCode,
                "Types": codeType || 'ONCE',
                "Point PPP": pointPpp || 0,
                "USED?": false,
                "有効/無効": isActive
            }]);
            
            if (error) return res.status(200).json({ success: false, message: "データベースの保存に失敗しました: " + error.message });
            await logAudit('CREATE_CODE', null, { code: safeCode });
            return res.status(200).json({ success: true, message: "OK" });
        }
    }

    // ==========================================
    // 一般ユーザー用機能
    // ==========================================
    
    // get_available：ストア一覧の取得
    if (type === 'get_available') {
      const isGuest = (!params.userId || params.userId === "GUEST");
      const targetId = isGuest ? null : authUserId; 
      
      const { data: allContents } = await supabase.from('contents').select('*').order('id', { ascending: true });
      let ownedContentIds = new Set(); 
      let ownedGroupIds = new Set();

      if (targetId) {
        const { data: history } = await supabase.from('histories').select('codes(content_id)').eq('user_id', targetId);
        if (history) {
            const contentIds = history.map(h => h.codes?.content_id).filter(Boolean);
            ownedContentIds = new Set(contentIds);
            if (contentIds.length > 0) {
                const { data: ownedContents } = await supabase.from('contents').select('重複').in('id', contentIds);
                if(ownedContents) ownedGroupIds = new Set(ownedContents.map(c => c["重複"]).filter(Boolean));
            }
        }
      }

      const lMap = { ja: 'jp', en: 'en', zh: 'zh', 'zh-TW': 'zh-TW', ko: 'ko', ru: 'ru' };
      const suffix = lMap[lang] || 'jp';

      const filteredContents = (allContents || []).filter(c => {
          const isShow = String(c["show/ hide"] || "").trim().toLowerCase() === 'show';
          if (!isShow) return false;
          return true;
      });

      const items = filteredContents.map(content => {
        const isOwned = ownedContentIds.has(content.id) || (content["重複"] && ownedGroupIds.has(content["重複"]));
        return {
          code: content.id, // ✅ IDを "code" としてフロントエンドに渡す
          title: content[`タイトル(${suffix})`] || content["タイトル(jp)"],
          message: content[`メッセージ(${suffix})`] || content["メッセージ(jp)"], 
          extraInfo: content[`詳細(${suffix})`] || content["詳細(jp)"],
          imageUrl: content.Imag_Url, url: content.Action_url, releaseDateIso: content["解禁時間"], expireDateIso: content["有効時間"], icon: content.アイコン || 'download',
          groupId: content["重複"], buttonLabel: content[`ボタン(${suffix})`] || content["ボタン(jp)"], price: content["価格"] || 0, isOwned: isOwned
        };
      });
      return res.status(200).json({ success: true, items });
    }
    if (type === 'error_search') {
      const { code } = params;
      if (!code) return res.status(200).json({ success: false, message: "Code is required" });

      // Supabaseの「errors」テーブルを参照（必要に応じてテーブル名を変更してください）
      // カラム構成例: code, ja, en, zh, zh_TW, ko, ru
      const { data: errData, error } = await supabase.from('errors').select('*').eq('code', code).maybeSingle();

      if (error || !errData) {
        return res.status(200).json({ success: false, message: "Error code not found" });
      }

      // クライアントの言語に応じたカラムへマッピング
      const langColMap = { ja: 'ja', en: 'en', zh: 'zh', 'zh-TW': 'zh_TW', ko: 'ko', ru: 'ru' };
      const colIdx = langColMap[lang] || 'ja';

      // 指定言語のテキストがない場合は、強制的に日本語(ja)へフォールバック
      const msg = errData[colIdx] || errData['ja'] || errData.message || "エラー詳細が見つかりません。";

      return res.status(200).json({ success: true, code: errData.code, errorMessage: msg });
    }

    // get_history：履歴取得
    if (type === 'get_history') {
      if (!authUserId) return res.status(401).json({ success: false, message: "Unauthorized" });
      const { data: user } = await supabase.from('users').select('points').eq('id', authUserId).maybeSingle();
      if (!user) return res.status(200).json({ success: false, message: "User not found" });
      const { data: histories } = await supabase.from('histories').select(`created_at, codes (*, contents(*))`).eq('user_id', authUserId).order('created_at', { ascending: false });
      
      const lMap = { ja: 'jp', en: 'en', zh: 'zh', 'zh-TW': 'zh-TW', ko: 'ko', ru: 'ru' };
      const suffix = lMap[lang] || 'jp';

      const historyData = (histories || []).map(h => {
        const codeRec = h.codes;
        if(!codeRec) return null;
        const c = codeRec.contents; 
        if(!c) return null;

        return {
          code: codeRec["アクティベーションコード"], date: h.created_at, title: c[`タイトル(${suffix})`] || c["タイトル(jp)"],
          message: c[`メッセージ(${suffix})`] || c["メッセージ(jp)"], url: c.Action_url, imageUrl: c.Imag_Url,
          icon: c.アイコン || 'download', releaseDateIso: c["解禁時間"], expireDateIso: c["有効時間"], extraInfo: c[`詳細(${suffix})`]
          groupId: c["重複"], buttonLabel: c[`ボタン(${suffix})`] || c["ボタン(jp)"],
          price: c["価格"] || 0
        };
      }).filter(Boolean);
      return res.status(200).json({ success: true, points: user?.points || 0, history: historyData });
    }

    // purchase：ストアでのポイント購入（※在庫を消費せず、無限に買える方式）
    if (type === 'purchase') {
      const contentId = params.code; // ✅ フロントエンドからは商品IDが 'code' という名前で届く
      if (!authUserId) return res.status(401).json({ success: false, message: "Unauthorized" });
      
      const { data: contentMaster } = await supabase.from('contents').select('*').eq('id', contentId).maybeSingle();
      if (!contentMaster) return res.status(200).json({ success: false, message: "Item not found" });
      
      const { data: user } = await supabase.from('users').select('points').eq('id', authUserId).maybeSingle();
      
      // 所持チェック
      const { data: existingHist } = await supabase.from('histories').select('codes(content_id)').eq('user_id', authUserId);
      let alreadyOwned = false;
      if (existingHist) {
         alreadyOwned = existingHist.some(h => h.codes && String(h.codes.content_id) === String(contentId));
      }
      if (alreadyOwned) return res.status(200).json({ success: false, message: "Already owned" });

      const price = contentMaster["価格"] || 0;
      if (user.points < price) return res.status(200).json({ success: false, message: "Not enough points" });

      // 在庫を探すのではなく、「購入者専用のシステムコード」を裏側で自動発行する
      const systemCode = `STORE-BUY-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
      const { data: newCode, error: codeErr } = await supabase.from('codes')
          .insert([{
              content_id: contentId,
              "アクティベーションコード": systemCode,
              "USED?": true,  // 発行と同時に使用済みにする（他人が使えないようにするため）
              "有効/無効": true
          }])
          .select('id')
          .single();

      if (codeErr || !newCode) {
          return res.status(200).json({ success: false, message: "システムエラーにより購入に失敗しました" });
      }
      
      // ポイントを減らし、自動発行したコードをユーザーの履歴に登録
      await supabase.from('users').update({ points: user.points - price }).eq('id', authUserId);
      await supabase.from('histories').insert([{ user_id: authUserId, code_id: newCode.id }]);
      
      return res.status(200).json({ success: true, remainingPoints: user.points - price });
    }

    // check / redeem：手入力でのコード認証
    if (type === 'check' || type === 'redeem') {
      const key = params.code || params.key; 
      const mode = params.mode || type;
      const targetId = authUserId; 

      const safeCode = (key || "").replace(/[^A-Z0-9\-]/gi, "").toUpperCase();
      
      const { data: master, error } = await supabase.from('codes').select('*, contents(*)').eq('アクティベーションコード', safeCode).maybeSingle();

      // 削除またはコメントアウト
      // const unifiedErrorMessage = "The code is invalid or has already been used.";

      // 修正後：エラーの種類に応じて明確に分離
      if (error || !master || !master.contents) {
          return res.status(200).json({ success: false, message: "Invalid code" });
      }

      const content = master.contents;
      const isActive = master["有効/無効"] === true || String(master["有効/無効"]).trim().toUpperCase() === 'TRUE';
      if (!isActive) {
          return res.status(200).json({ success: false, message: "Invalid code" });
      }

      const now = new Date();
      if (content["有効時間"] && now > new Date(content["有効時間"])) {
        return res.status(200).json({ success: false, message: "Invalid code" });
      }

      const codeType = (master.Types || "").trim().toUpperCase();
      const isOnce = (codeType === 'ONCE' || codeType === '');
      const rawUsed = master["USED?"];
      const isCodeUsed = rawUsed === true || String(rawUsed).trim().toUpperCase() === 'TRUE';

      // ここで「使用済み」のステータスを明確に分離して返す
      if ((isOnce || codeType === 'POINT') && isCodeUsed) {
        return res.status(200).json({ success: false, message: "This code has already been used." });
      }
      
      const lMap = { ja: 'jp', en: 'en', zh: 'zh', 'zh-TW': 'zh-TW', ko: 'ko', ru: 'ru' };
      const suffix = lMap[lang] || 'jp';

      const txt = {
        btnLabel: content[`ボタン(${suffix})`] || content["ボタン(jp)"], bundle: content[`バンドル(${suffix})`] || content["バンドル(jp)"],
        message: content[`メッセージ(${suffix})`] || content["メッセージ(jp)"], title: content[`タイトル(${suffix})`] || content["タイトル(jp)"],
        desc: content[`詳細(${suffix})`] || content["詳細(jp)"]
      };

      if (mode === 'check') {
        return res.status(200).json({
          success: true, bundleLabel: txt.bundle, message: txt.message, detailedTitle: txt.title, detailedDesc: txt.desc,
          buttonLabel: txt.btnLabel, imageUrl: content.Imag_Url, icon: content.アイコン || 'download', groupId: content["重複"]
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
          const { data: existingHist } = await supabase.from('histories').select('codes(content_id, contents("重複"))').eq('user_id', targetId);
          if (existingHist) {
            isOwned = existingHist.some(h => {
                if (!h.codes) return false;
                return h.codes.content_id === content.id || 
                      (content["重複"] && h.codes.contents && h.codes.contents["重複"] === content["重複"]);
            });
          }
        }
        if (isOwned) return res.status(200).json({ success: false, isAlreadyOwned: true, message: "Already owned" });

        const isRelease = !content["解禁時間"] || (now >= new Date(content["解禁時間"]));
        const retUrl = content.Action_url;

        if (targetId) {
           await supabase.from('histories').insert([{ user_id: targetId, code_id: master.id }]);
        }
        if (isOnce) {
           await supabase.from('codes').update({ "USED?": true }).eq('アクティベーションコード', safeCode);
        }

        return res.status(200).json({
          success: true, actionUrl: retUrl, bundleLabel: txt.bundle, message: txt.message,         
          detailedTitle: txt.title, detailedDesc: txt.desc, buttonLabel: txt.btnLabel,
          imageUrl: content.Imag_Url, isReleaseDateReached: isRelease, releaseDateIso: content["解禁時間"],
          expireDateIso: content["有効時間"],
          btnIcon: content.アイコン || 'download', groupId: content["重複"]
        });
      }
    }
    return res.status(200).json({ success: false, message: "Invalid request" });

  } catch (error) {
    console.error("Critical API Error:", error);
    return res.status(500).json({ success: false, message: "Internal Server Error" });
  }
}
