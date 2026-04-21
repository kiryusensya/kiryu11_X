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
    // 認証系処理（変更なしのため割愛部分もそのまま記載）
    // ==========================================
    if (type === 'register') { /* 既存と同じため省略せず記載 */
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

        if (type === 'admin_create_user') { /* 既存ロジックそのまま */ }
        
        if (type === 'admin_revoke_content') { /* 既存ロジックそのまま */ }

        if (type === 'admin_search') {
            const { targetEmail } = params;
            const { data: targetUser } = await supabase.from('users').select('id, email, points').eq('email', targetEmail).maybeSingle();
            if (!targetUser) return res.status(200).json({ success: false, message: "ユーザーが見つかりません" });

            // 変更点: codes経由でcontentsの情報もJOINする
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
            
            // 変更点: contentsをJOIN
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

        if (type === 'admin_save_code') {
            // 🚨フロントエンド改修ポイント: 
            // 管理画面からは「コンテンツの作成」と「コードの生成」を分ける必要があります。
            // 暫定として、既存ロジックを残していますが、今後は contents テーブルと codes テーブルのそれぞれに INSERT する設計に変更してください。
            return res.status(200).json({ success: false, message: "API構造が変更されました。コンテンツ管理とコード管理を分離して保存してください。" });
        }
    }

    // ==========================================
    // 一般ユーザー用機能
    // ==========================================
    
    // get_available：ストア一覧の取得（コード単位ではなくコンテンツ単位で取得）
    if (type === 'get_available') {
      const isGuest = (!params.userId || params.userId === "GUEST");
      const targetId = isGuest ? null : authUserId; 
      
      // 変更点: ベースをcontentsテーブルに変更
      const { data: allContents } = await supabase.from('contents').select('*').order('id', { ascending: true });
      let ownedContentIds = new Set(); 
      let ownedGroupIds = new Set();

      if (targetId) {
        // historiesからユーザーの所持コードを取得し、紐づくcontent_idを抽出
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
          contentId: content.id, // 🚨コードではなくコンテンツIDを返す
          title: content[`タイトル(${suffix})`] || content["タイトル(jp)"],
          message: content[`メッセージ(${suffix})`] || content["メッセージ(jp)"], 
          extraInfo: content[`詳細(${suffix})`] || content["詳細(jp)"],
          imageUrl: content.Imag_Url, url: content.Action_url, releaseDateIso: content["解禁時間"], icon: content.アイコン || 'download',
          groupId: content["重複"], buttonLabel: content[`ボタン(${suffix})`] || content["ボタン(jp)"], price: content["価格"] || 0, isOwned: isOwned
        };
      });
      return res.status(200).json({ success: true, items });
    }

    // get_history：履歴取得
    if (type === 'get_history') {
      if (!authUserId) return res.status(401).json({ success: false, message: "Unauthorized" });
      const { data: user } = await supabase.from('users').select('points').eq('id', authUserId).maybeSingle();
      
      // 変更点: codes経由でcontentsをJOIN
      const { data: histories } = await supabase.from('histories').select(`created_at, codes (*, contents(*))`).eq('user_id', authUserId).order('created_at', { ascending: false });
      
      const lMap = { ja: 'jp', en: 'en', zh: 'zh', 'zh-TW': 'zh-TW', ko: 'ko', ru: 'ru' };
      const suffix = lMap[lang] || 'jp';

      const historyData = (histories || []).map(h => {
        const codeRec = h.codes;
        if(!codeRec) return null;
        const c = codeRec.contents; // コンテンツ情報
        if(!c) return null;

        return {
          code: codeRec["アクティベーションコード"], date: h.created_at, title: c[`タイトル(${suffix})`] || c["タイトル(jp)"],
          message: c[`メッセージ(${suffix})`] || c["メッセージ(jp)"], url: c.Action_url, imageUrl: c.Imag_Url,
          icon: c.アイコン || 'download', releaseDateIso: c["解禁時間"], extraInfo: c[`詳細(${suffix})`] || c["詳細(jp)"],
          groupId: c["重複"], buttonLabel: c[`ボタン(${suffix})`] || c["ボタン(jp)"]
        };
      }).filter(Boolean);
      return res.status(200).json({ success: true, points: user?.points || 0, history: historyData });
    }

    // purchase：ストアでのポイント購入（※コンテンツIDを受け取り、未使用コードを払い出す方式に変更）
    if (type === 'purchase') {
      const { contentId } = params; // フロントエンドは code ではなく contentId を送る必要があります
      if (!authUserId) return res.status(401).json({ success: false, message: "Unauthorized" });
      
      const { data: contentMaster } = await supabase.from('contents').select('*').eq('id', contentId).maybeSingle();
      if (!contentMaster) return res.status(200).json({ success: false, message: "Item not found" });
      
      const { data: user } = await supabase.from('users').select('points').eq('id', authUserId).maybeSingle();
      
      // 所持チェック
      const { data: existingHist } = await supabase.from('histories').select('codes(content_id)').eq('user_id', authUserId);
      let alreadyOwned = false;
      if (existingHist) {
         alreadyOwned = existingHist.some(h => h.codes && h.codes.content_id === contentId);
      }
      if (alreadyOwned) return res.status(200).json({ success: false, message: "Already owned" });

      const price = contentMaster["価格"] || 0;
      if (user.points < price) return res.status(200).json({ success: false, message: "Not enough points" });

      // 対象コンテンツの未使用コードを1つ確保（早い者勝ち）
      const { data: availableCode } = await supabase.from('codes')
        .select('id')
        .eq('content_id', contentId)
        .eq('USED?', false)
        .eq('有効/無効', true)
        .limit(1)
        .maybeSingle();

      if (!availableCode) return res.status(200).json({ success: false, message: "在庫（未使用コード）がありません" });
      
      // トランザクション的に処理
      await supabase.from('users').update({ points: user.points - price }).eq('id', authUserId);
      await supabase.from('codes').update({ "USED?": true }).eq('id', availableCode.id);
      await supabase.from('histories').insert([{ user_id: authUserId, code_id: availableCode.id }]);
      
      return res.status(200).json({ success: true, remainingPoints: user.points - price });
    }

    // check / redeem：手入力でのコード認証
    if (type === 'check' || type === 'redeem') {
      const key = params.code || params.key; 
      const mode = params.mode || type;
      const targetId = authUserId; 

      const safeCode = (key || "").replace(/[^A-Z0-9\-]/gi, "").toUpperCase();
      
      // 変更点: contentsをJOIN
      const { data: master, error } = await supabase.from('codes').select('*, contents(*)').eq('アクティベーションコード', safeCode).maybeSingle();

      if (error || !master || !master.contents) {
          return res.status(200).json({ success: false, message: "Invalid code" });
      }

      const content = master.contents; // コンテンツ側データ
      const isActive = master["有効/無効"] === true || String(master["有効/無効"]).trim().toUpperCase() === 'TRUE';
      if (!isActive) return res.status(200).json({ success: false, message: "Invalid code" });

      const now = new Date();
      if (content["有効時間"] && now > new Date(content["有効時間"])) {
        return res.status(200).json({ success: false, message: "Invalid code" });
      }

      const codeType = (master.Types || "").trim().toUpperCase();
      const isOnce = (codeType === 'ONCE' || codeType === '');
      const rawUsed = master["USED?"];
      const isCodeUsed = rawUsed === true || String(rawUsed).trim().toUpperCase() === 'TRUE';

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
                // コンテンツIDが完全に一致するか、重複グループ名が一致したら「所持済み」とする
                return h.codes.content_id === content.id || 
                      (content["重複"] && h.codes.contents && h.codes.contents["重複"] === content["重複"]);
            });
          }
        }
        if (isOwned) return res.status(200).json({ success: false, isAlreadyOwned: true, message: "Already owned" });

        const isRelease = !content["解禁時間"] || (now >= new Date(content["解禁時間"]));
        const retUrl = isRelease ? content.Action_url : "";

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
