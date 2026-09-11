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
  'https://kiryu11.vercel.app',
  'https://kiryu11-x.vercel.app',
  'http://localhost:3000'
];

export default async function handler(req, res) {
  const origin = req.headers.origin || '';
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') return res.status(200).end();

  const originalJson = res.json;
  res.json = function(body) {
    if (body && typeof body === 'object' && !Array.isArray(body)) {
        body.serverTime = Date.now();
    }
    return originalJson.call(this, body);
  };

  try {
    // レートリミット
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

    // パラメータ取得
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
    const appTier = 'enterprise'; 

    // JWT Token Verification
    let authUserId = null;
    let isAdmin = false;
    let token = null;

    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.split(' ')[1];
    }
    if (!token && params.token) token = params.token;
    
    const cookieHeader = req.headers.cookie;
    if (cookieHeader) {
        const cookies = {};
        cookieHeader.split(';').forEach(c => {
            const parts = c.split('=');
            if (parts.length >= 2) cookies[parts[0].trim()] = parts[1].trim();
        });
      if (!token && cookies.admin_token) token = cookies.admin_token;
    }

    if (token) {
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const { data: revoked } = await supabase.from('revoked_tokens').select('id').eq('token', token).maybeSingle();
        if (revoked) throw new Error("Token has been revoked");

        authUserId = decoded.userId;
        isAdmin = decoded.isAdmin || false;
      } catch (e) {
        token = null;
        authUserId = null;
        isAdmin = false;
      }
    }

    // BAN判定
    let isBanned = false;
    if (authUserId) {
        const { data: banCheckUser } = await supabase.from('users').select('banned_until, is_admin').eq('id', authUserId).maybeSingle();
        if (banCheckUser && banCheckUser.banned_until && !banCheckUser.is_admin) {
            const bDate = new Date(banCheckUser.banned_until);
            if (bDate > new Date()) {
                isBanned = true;
            }
        }
    }
    
    if (type === 'check_ban_status') {
      if (!authUserId) {
        return res.status(200).json({ success: false, isBanned: false, message: "Unauthorized" });
      }
      return res.status(200).json({ success: true, isBanned });
    }

    const restrictedActions = ['purchase', 'check', 'redeem', 'change_password', 'get_video_url', 'get_available', 'get_history'];
    if (isBanned && restrictedActions.includes(type)) {
        return res.status(200).json({ success: false, isBanned: true, message: "アクセスが禁止されています。" });
    }
    if (isBanned && type === 'download') {
        return res.status(403).send("Forbidden: アクセスが禁止されています。");
    }

    // エラー検索機能
    if (type === 'error_search') {
      const { code } = params;
      if (!code) return res.status(200).json({ success: false, message: "Code is required" });

      const { data: errData, error } = await supabase.from('errors').select('*').eq('code', code).maybeSingle();
      if (error || !errData) {
        return res.status(200).json({ success: false, message: "Error code not found" });
      }

      const langColMap = { ja: 'ja', en: 'en', zh: 'zh', 'zh-TW': 'zh_TW', ko: 'ko', ru: 'ru' };
      const colIdx = langColMap[lang] || 'ja';
      const msg = errData[colIdx] || errData['ja'] || errData.message || "エラー詳細が見つかりません。";

      return res.status(200).json({ success: true, code: errData.code, errorMessage: msg });
    }

    // ダウンロード処理
    if (type === 'download') {
        const { code, target } = params;
        if (!authUserId) return res.status(401).send("Unauthorized: ログインが必要です。");

        const { data: userHistories } = await supabase
            .from('histories')
            .select('id, codes(id, content_id, アクティベーションコード, target_tier, contents(Action_url, "有効時間", "解禁時間", target_tier))')
            .eq('user_id', authUserId);

        if (!userHistories || userHistories.length === 0) return res.status(403).send("Forbidden: 履歴が存在しません。");

        const cleanTargetCode = String(code).replace(/[^A-Z0-9]/gi, "").toUpperCase();
        const matchedHistory = userHistories.find(h => {
            if (!h.codes) return false;
            const dbContentId = String(h.codes.content_id);
            const cleanDbCode = String(h.codes["アクティベーションコード"]).replace(/[^A-Z0-9]/gi, "").toUpperCase();
            return dbContentId === String(code) || cleanDbCode === cleanTargetCode;
        });

        if (!matchedHistory || !matchedHistory.codes || !matchedHistory.codes.contents) {
            return res.status(403).send("Forbidden: このコンテンツを所有していません。");
        }

        const content = matchedHistory.codes.contents;
        const checkNow = new Date();
        if (content["有効時間"] && checkNow > new Date(content["有効時間"])) return res.status(403).send("Forbidden: 有効期限が切れています。");
        if (content["解禁時間"] && checkNow < new Date(content["解禁時間"])) return res.status(403).send("Forbidden: まだ解禁されていません。");

        let downloadTargetUrl = content.Action_url;
        if (target) {
            let rawTarget = decodeURIComponent(target);
            if (rawTarget.startsWith('__MASKED_URL__:')) {
                const idx = parseInt(rawTarget.split(':')[1], 10) || 0;
                const strUrl = String(content.Action_url).trim();
                
                if (strUrl.startsWith('[')) {
                    try {
                        const arr = JSON.parse(strUrl);
                        if (arr[idx] && arr[idx].url) {
                            downloadTargetUrl = arr[idx].url;
                        }
                    } catch(e) {}
                }
            } else {
                downloadTargetUrl = rawTarget;
            }
        }
        
        if (!downloadTargetUrl || downloadTargetUrl.startsWith('__MASKED_URL__')) {
            return res.status(404).send("Not Found: ダウンロードURLが設定されていません。");
        }

        try {
            const fetchResponse = await fetch(downloadTargetUrl);
            if (!fetchResponse.ok) return res.status(fetchResponse.status).send(`Error fetching file: ${fetchResponse.statusText}`);

            const contentType = fetchResponse.headers.get('content-type');
            const contentDisposition = fetchResponse.headers.get('content-disposition');
            if (contentType) res.setHeader('Content-Type', contentType);
            if (contentDisposition) res.setHeader('Content-Disposition', contentDisposition);
            else res.setHeader('Content-Disposition', 'attachment');

            if (fetchResponse.body) {
                return fetchResponse.body.pipeTo(new WritableStream({
                    write(chunk) { res.write(chunk); },
                    close() { res.end(); }
                }));
            } else {
                 const buffer = await fetchResponse.arrayBuffer();
                 return res.send(Buffer.from(buffer));
            }
        } catch (downloadError) {
            return res.status(500).send("Internal Server Error: ファイルの取得に失敗しました。");
        }
    }

    // アクセスログ記録
    const userAgent = req.headers['user-agent'] || 'unknown';
    const safeType = type || 'unknown';
    const ignoredActions = ['get_history', 'get_available', 'error_search', 'admin_get_access_logs', 'admin_search', 'admin_set_points', 'get_video_url'];
    
    let targetCode = null;
    if (safeType === 'check' || safeType === 'redeem') {
        targetCode = params.code || params.key || null; 
    }
    
    if (!ignoredActions.includes(safeType)) {
        try {
            await supabase.from('access_logs').insert([{
                ip_address: ip, action_type: safeType, user_id: authUserId || null,
                user_agent: userAgent, target_code: targetCode,
                app_tier: appTier
            }]);
        } catch (logError) {}
    }
    
    const logAudit = async (actionType, targetUser, details) => {
        try {
            if (isAdmin && authUserId) {
                await supabase.from('admin_audit_logs').insert([{
                    admin_id: authUserId, action_type: actionType,
                    target_user: targetUser, details: details
                }]);
            }
        } catch (e) {}
    };

    // 認証系処理
    if (type === 'register') {
      const { email, password } = params;
      if (!email || !password) return res.status(200).json({ success: false, message: "Missing credentials" });
      
      const { data: existing } = await supabase.from('users').select('id').eq('email', email).maybeSingle();
      if (existing) return res.status(200).json({ success: false, message: "Exists" });
      
      const hashedPassword = await bcrypt.hash(password, 10);
      const { data: newUser, error } = await supabase.from('users').insert([{ email, password: hashedPassword, points: 0, app_tier: appTier }]).select().single();
      if (error) throw error;
      return res.status(200).json({ success: true, userId: newUser.id, message: "OK" });
    }

    if (type === 'user_login') {
      const { email, password } = params;
      const { data: user } = await supabase.from('users').select('*').eq('email', email).maybeSingle();
      
      if (user && await bcrypt.compare(password, user.password)) {
          const userTier = String(user.app_tier || 'standard').toLowerCase();
          if (appTier === 'enterprise' && userTier !== 'enterprise') {
              return res.status(200).json({ success: false, message: "Invalid" });
          }

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
      if (!userId || !oldPassword || !newPassword) return res.status(200).json({ success: false, message: "Missing fields" });

      const { data: user } = await supabase.from('users').select('*').eq('id', userId).maybeSingle();
      if (!user) return res.status(200).json({ success: false, message: "User not found" });

      const isMatch = await bcrypt.compare(oldPassword, user.password);
      if (!isMatch) return res.status(200).json({ success: false, message: "Invalid current password" });

      const hashedNewPassword = await bcrypt.hash(newPassword, 10);
      const { error } = await supabase.from('users').update({ password: hashedNewPassword, needs_password_change: false }).eq('id', userId);
      if (error) return res.status(200).json({ success: false, message: "Database update failed" });

      return res.status(200).json({ success: true, message: "Password updated successfully" });
    }

    if (type === 'admin_logout') {
        if (token) {
            try {
                const decoded = jwt.decode(token);
                if (decoded && decoded.exp) {
                    const expiresAt = new Date(decoded.exp * 1000).toISOString();
                    await supabase.from('revoked_tokens').insert([{ token: token, expires_at: expiresAt }]);
                }
            } catch (e) {}
        }
        res.setHeader('Set-Cookie', [
            `admin_token=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`,
            `admin_logged_in=; SameSite=Strict; Path=/; Max-Age=0`
        ]);
        return res.status(200).json({ success: true });
    }

    if (type === 'admin_verify') {
        if (!isAdmin || !authUserId) return res.status(401).json({ success: false, message: "Unauthorized" });
        const { data: adminUser } = await supabase.from('users').select('is_admin').eq('id', authUserId).maybeSingle();
        if (!adminUser || !adminUser.is_admin) return res.status(401).json({ success: false, message: "管理者権限が取り消されています" });
        
        return res.status(200).json({ success: true });
    }

    if (type === 'get_account_details') {
      if (!authUserId) return res.status(401).json({ success:false, message:'Unauthorized' });
      const { data:user, error:userError } = await supabase.from('users').select('id,email,points,app_tier,banned_until').eq('id',authUserId).maybeSingle();
      if (userError || !user) return res.status(404).json({ success:false, message:'User not found' });
      const { data:rows, error:historyError } = await supabase.from('histories').select('created_at,codes(アクティベーションコード,contents(*))').eq('user_id',authUserId).order('created_at',{ascending:false}).limit(50);
      if (historyError) return res.status(500).json({ success:false, message:'History fetch failed' });
      const map={ja:'jp',en:'en',zh:'zh','zh-TW':'zh-TW',ko:'ko',ru:'ru'}, suffix=map[lang]||'jp';
      const history=(rows||[]).map(row=>{const code=row.codes||{},c=code.contents||{};return {title:c[`タイトル(${suffix})`]||c['タイトル(jp)']||'',code:code['アクティベーションコード']||'',icon:c['アイコン']||'package-check',date:row.created_at};});
      const bannedUntil=user.banned_until||null, isBanned=Boolean(bannedUntil&&new Date(bannedUntil)>new Date()), isPermanent=Boolean(isBanned&&new Date(bannedUntil).getUTCFullYear()>=2099);
      return res.status(200).json({success:true,userId:user.id,email:user.email,points:user.points||0,tier:user.app_tier||'standard',isBanned,bannedUntil,isPermanent,history});
    }

    // 管理者用機能
    if (type.startsWith('admin_')) {
        if (!isAdmin) return res.status(401).json({ success: false, message: "管理者権限がありません" });
        
        if (type === 'admin_get_access_logs') {
            const limit = params.limit || 100;
            const { data: logs, error } = await supabase.from('access_logs')
                .select(`id, created_at, ip_address, action_type, user_agent, target_code, user_id, app_tier`)
                .neq('action_type', 'admin_get_access_logs')
                .order('created_at', { ascending: false })
                .limit(limit);

            if (error) return res.status(200).json({ success: false, message: "ログの取得に失敗しました", error: error.message });

            const formattedLogs = (logs || []).map(log => ({
                id: log.id,
                date: new Date(log.created_at).toLocaleString('ja-JP', { timeZone: 'Asia/Tokyo' }),
                ip: log.ip_address,
                type: log.action_type,
                code: log.target_code || '-',
                email: log.user_id ? `ID: ${log.user_id.substring(0, 8)}...` : '未ログイン (GUEST)',
                userAgent: log.user_agent,
                appTier: log.app_tier || '不明'
            }));
            return res.status(200).json({ success: true, logs: formattedLogs });
        }
        
        if (type === 'admin_create_user') {
            const { email, password, target_tier } = params; 
            const tierToAssign = target_tier || 'standard';
            if (!email || !password) return res.status(200).json({ success: false, message: "Missing credentials" });
            const { data: existing } = await supabase.from('users').select('id').eq('email', email).maybeSingle();
            if (existing) return res.status(200).json({ success: false, message: "そのIDは既に存在します" });
            
            const hashedPassword = await bcrypt.hash(password, 10);
            const { error } = await supabase.from('users').insert([{ email, password: hashedPassword, points: 0, needs_password_change: true, app_tier: tierToAssign }]);
            if (error) return res.status(200).json({ success: false, message: error.message });
            await logAudit('CREATE_USER', email, { tier: tierToAssign });
            return res.status(200).json({ success: true, message: "OK" });
        }

        if (type === 'admin_reset_password') {
            const { targetEmail, newPassword } = params;
            if (!targetEmail || !newPassword) return res.status(200).json({ success: false, message: "Missing credentials" });
            const hashedPassword = await bcrypt.hash(newPassword, 10);
            const { error } = await supabase.from('users').update({ password: hashedPassword, needs_password_change: true }).eq('email', targetEmail);
            if (error) return res.status(200).json({ success: false, message: error.message });
            await logAudit('RESET_PASSWORD', targetEmail, {});
            return res.status(200).json({ success: true });
        }

        if (type === 'admin_ban_user') {
            const { targetEmail, banType, banUntil } = params;
            if (!targetEmail || !banType) return res.status(200).json({ success: false, message: "Missing parameters" });

            let targetDate = null;
            if (banType === 'temporary' && banUntil) {
                targetDate = new Date(banUntil + '+09:00').toISOString();
            } else if (banType === 'permanent') {
                targetDate = '2099-12-31T23:59:59.000Z';
            }

            const { error } = await supabase.from('users').update({ banned_until: targetDate }).eq('email', targetEmail);
            if (error) return res.status(200).json({ success: false, message: error.message });

            await logAudit('BAN_USER', targetEmail, { banType, targetDate });
            return res.status(200).json({ success: true, message: "アカウントのアクセス制限を適用しました" });
        }

        if (type === 'admin_search') {
            const { targetEmail } = params;
            const { data: user, error } = await supabase.from('users').select('id, email, points, app_tier, banned_until').eq('email', targetEmail).maybeSingle();
            if (error || !user) return res.status(200).json({ success: false, message: "ユーザーが見つかりません" });

            const { data: histories } = await supabase.from('histories')
                .select('created_at, codes(*, contents(*))')
                .eq('user_id', user.id)
                .order('created_at', { ascending: false });

            const historyList = (histories || []).map(h => {
                const codeData = h.codes || {};
                const contentData = codeData.contents || {};
                return {
                    title: contentData['タイトル(jp)'] || '不明なコンテンツ',
                    code: codeData['アクティベーションコード'] || '-',
                    date: new Date(h.created_at).toLocaleString('ja-JP', { timeZone: 'Asia/Tokyo' })
                };
            });

            return res.status(200).json({ 
                success: true, 
                userId: user.email, 
                points: user.points, 
                tier: user.app_tier, 
                bannedUntil: user.banned_until,
                history: historyList 
            });
        }

        if (type === 'admin_set_points') {
            const { targetEmail, amount } = params;
            const { error } = await supabase.from('users').update({ points: amount }).eq('email', targetEmail);
            if (error) return res.status(200).json({ success: false, message: error.message });
            await logAudit('SET_POINTS', targetEmail, { amount });
            return res.status(200).json({ success: true });
        }

        if (type === 'admin_set_tier') {
            const { targetEmail, targetTier } = params;
            if (!targetEmail || !targetTier) {
                return res.status(200).json({ success: false, message: "必要なパラメータが不足しています" });
            }
            const safeTier = targetTier === 'enterprise' ? 'enterprise' : 'standard';
            const { error } = await supabase.from('users').update({ app_tier: safeTier }).eq('email', targetEmail);
            if (error) return res.status(200).json({ success: false, message: error.message });
            await logAudit('SET_TIER', targetEmail, { newTier: safeTier });
            return res.status(200).json({ success: true, message: `権限を ${safeTier} に変更しました` });
        }

        if (type === 'admin_delete_user') {
            const { targetEmail, adminPassword } = params;
            if (!adminPassword) return res.status(200).json({ success: false, message: "再認証のため管理者パスワードが必要です" });
            const { data: adminUser } = await supabase.from('users').select('password').eq('id', authUserId).maybeSingle();
            if (!adminUser || !(await bcrypt.compare(adminPassword, adminUser.password))) {
                return res.status(200).json({ success: false, message: "管理者パスワードが間違っています。操作は取り消されました" });
            }

            const { data: user } = await supabase.from('users').select('id').eq('email', targetEmail).maybeSingle();
            if (!user) return res.status(200).json({ success: false, message: "ユーザーが見つかりません" });
            const { error } = await supabase.from('users').delete().eq('email', targetEmail);
            if (error) return res.status(200).json({ success: false, message: error.message });
            await logAudit('DELETE_USER', targetEmail, {});
            return res.status(200).json({ success: true });
        }

        if (type === 'admin_revoke_content') {
            const { targetEmail, code } = params;
            const { data: user } = await supabase.from('users').select('id').eq('email', targetEmail).maybeSingle();
            if (!user) return res.status(200).json({ success: false, message: "ユーザーが見つかりません" });

            const { data: codeData } = await supabase.from('codes').select('id').eq('アクティベーションコード', code).maybeSingle();
            if (codeData) {
                const { error } = await supabase.from('histories').delete().eq('user_id', user.id).eq('code_id', codeData.id);
                if (error) return res.status(200).json({ success: false, message: error.message });
            }
            await logAudit('REVOKE_CONTENT', targetEmail, { code });
            return res.status(200).json({ success: true });
        }

        if (type === 'admin_save_content') {
            const { payload } = params;
            if (!payload) return res.status(200).json({ success: false, message: "データがありません" });
            
            let result;
            if (payload.id) {
                result = await supabase.from('contents').update(payload).eq('id', payload.id).select().single();
            } else {
                result = await supabase.from('contents').insert([payload]).select().single();
            }
            if (result.error) return res.status(200).json({ success: false, message: result.error.message });
            await logAudit('SAVE_CONTENT', 'system', { contentId: result.data.id });
            return res.status(200).json({ success: true, contentId: result.data.id });
        }

        if (type === 'admin_create_code') {
            const { contentId, code, codeType, pointPpp, isActive, targetTier } = params;
            const { error } = await supabase.from('codes').insert([{
                content_id: contentId,
                'アクティベーションコード': code,
                Types: codeType,
                'Point PPP': pointPpp,
                '有効/無効': isActive,
                'USED?': false,
                target_tier: targetTier
            }]);
            if (error) return res.status(200).json({ success: false, message: error.message });
            await logAudit('CREATE_CODE', 'system', { code });
            return res.status(200).json({ success: true });
        }

        if (type === 'admin_check_code') {
            const { code } = params;
            const { data: codeData, error } = await supabase.from('codes').select('*, contents("タイトル(jp)", target_tier)').eq('アクティベーションコード', code).maybeSingle();
            if (error || !codeData) return res.status(200).json({ success: false, message: "コードが見つかりません" });

            let usedTime = null;
            let usedBy = null;

            if (codeData['USED?']) {
                const { data: hist } = await supabase.from('histories').select('created_at, users(email)').eq('code_id', codeData.id).maybeSingle();
                if (hist) {
                    usedTime = hist.created_at;
                    usedBy = hist.users?.email;
                }
            }
            
            const tTier = codeData.target_tier || codeData.contents?.target_tier || 'all';

            return res.status(200).json({
                success: true,
                code: codeData['アクティベーションコード'],
                title: codeData.contents?.['タイトル(jp)'],
                isUsed: codeData['USED?'],
                usedTime,
                usedBy,
                targetTier: tTier
            });
        }

        if (type === 'admin_reset_code') {
            const { code } = params;
            const { data: codeData } = await supabase.from('codes').select('id').eq('アクティベーションコード', code).maybeSingle();
            if (!codeData) return res.status(200).json({ success: false, message: "コードが見つかりません" });

            await supabase.from('histories').delete().eq('code_id', codeData.id);
            const { error } = await supabase.from('codes').update({ 'USED?': false }).eq('id', codeData.id);
            
            if (error) return res.status(200).json({ success: false, message: error.message });
            await logAudit('RESET_CODE', 'system', { code });
            return res.status(200).json({ success: true });
        }
    }

    // 動画視聴用URL
    if (type === 'get_video_url') {
        const { code, target } = params;
        if (!authUserId) return res.status(401).json({ success: false, message: "Unauthorized" });

        const { data: userHistories } = await supabase.from('histories')
            .select('id, codes(id, content_id, アクティベーションコード, contents(Action_url, "有効時間", "解禁時間"))')
            .eq('user_id', authUserId);

        if (!userHistories || userHistories.length === 0) return res.status(403).json({ success: false, message: "Forbidden" });

        const cleanTargetCode = String(code).replace(/[^A-Z0-9]/gi, "").toUpperCase();
        const matchedHistory = userHistories.find(h => {
            if (!h.codes) return false;
            const dbContentId = String(h.codes.content_id);
            const cleanDbCode = String(h.codes["アクティベーションコード"]).replace(/[^A-Z0-9]/gi, "").toUpperCase();
            return dbContentId === String(code) || cleanDbCode === cleanTargetCode;
        });

        if (!matchedHistory || !matchedHistory.codes || !matchedHistory.codes.contents) return res.status(403).json({ success: false, message: "Forbidden" });

        const content = matchedHistory.codes.contents;
        const checkNow = new Date();

        if (content["有効時間"] && checkNow > new Date(content["有効時間"])) return res.status(403).json({ success: false, message: "Expired" });
        if (content["解禁時間"] && checkNow < new Date(content["解禁時間"])) return res.status(403).json({ success: false, message: "Locked" });

        let videoUrl = content.Action_url;
        if (target) {
            videoUrl = decodeURIComponent(target);
        } else {
            try {
                if (videoUrl && String(videoUrl).trim().startsWith('[')) {
                    const parsedArr = JSON.parse(videoUrl);
                    const ytItem = parsedArr.find(obj => obj.url && (obj.url.includes('youtube.com') || obj.url.includes('youtu.be')));
                    if (ytItem) videoUrl = ytItem.url;
                }
            } catch (e) {}
        }

        let embedUrl = "";
        try {
            const urlStr = String(videoUrl);
            if (urlStr.includes('youtube.com/watch')) {
                const videoId = new URL(urlStr).searchParams.get('v');
                if (videoId) embedUrl = `https://www.youtube.com/embed/${videoId}?rel=0`;
            } else if (urlStr.includes('youtu.be/')) {
                const videoId = urlStr.split('youtu.be/')[1].split('?')[0];
                if (videoId) embedUrl = `https://www.youtube.com/embed/${videoId}?rel=0`;
            }
        } catch (e) {}

        if (!embedUrl) return res.status(400).json({ success: false, message: "Invalid YouTube URL" });
        return res.status(200).json({ success: true, embedUrl: embedUrl });
    }

    const maskActionUrl = (rawUrl) => {
      if (!rawUrl) return null;
      let strUrl = String(rawUrl).trim();
      if (strUrl.startsWith('[')) {
          try {
              const arr = JSON.parse(strUrl);
              const maskedArr = arr.map((item, index) => {
                  const isYouTube = item.url && (item.url.includes('youtube.com') || item.url.includes('youtu.be'));
                  return {
                      ...item,
                      url: isYouTube ? item.url : `__MASKED_URL__:${index}`
                  };
              });
              return JSON.stringify(maskedArr);
          } catch (e) {
              return `__MASKED_URL__:0`;
          }
      }
      const isYouTube = strUrl.includes('youtube.com') || strUrl.includes('youtu.be');
      if (isYouTube) return strUrl; 
      return `__MASKED_URL__:0`;
    };

    // サポートリンク集機能
    if (type === 'get_support_links') {
        const { data: links, error } = await supabase
            .from('support_links')
            .select('*')
            .eq('is_active', true)
            .order('sort_order', { ascending: true });

        if (error) {
            return res.status(500).json({ success: false, message: "リンクの取得に失敗しました。" });
        }
        return res.status(200).json({ success: true, links: links || [] });
    }

    // ★ Instagram 認証＆ブラックリスト検証 (reasonカラムの取得と返却)
    if (type === 'auth_instagram') {
        const { username } = params;
        if (!username) return res.status(200).json({ success: false, message: "ユーザー名を入力してください" });

        // Supabaseのブラックリストを検索 (username & reason を取得)
        const { data: blockedUser, error } = await supabase
            .from('blocked_instagram_users')
            .select('username, reason')
            .ilike('username', username)
            .maybeSingle();

        // ブラックリストに登録されている場合 -> 403とともに reason を返して拒否
        if (blockedUser) {
            await logAudit('INSTAGRAM_AUTH_BLOCKED', username, { status: 'blocked', reason: blockedUser.reason });
            return res.status(403).json({ 
                success: false, 
                message: "このアカウントからのアクセスは制限されています。",
                reason: blockedUser.reason || null
            });
        }

        // 登録されていない場合 -> 通過
        const redirectUrl = params.targetUrl || "https://ig.me/m/your_support_account";
        await logAudit('INSTAGRAM_AUTH_SUCCESS', username, { status: 'passed' });

        return res.status(200).json({ success: true, redirectUrl });
    }

    if (type === 'get_available') {
      const targetId = (!params.userId || params.userId === "GUEST") ? null : authUserId; 
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
          if (c["有効時間"] && new Date(c["有効時間"]).getTime() <= Date.now()) return false;
          return true;
      });

      const items = filteredContents.map(content => {
        const isOwned = ownedContentIds.has(content.id) || (content["重複"] && ownedGroupIds.has(content["重複"]));
        const now = Date.now();
        const releaseTime = content["解禁時間"] ? new Date(content["解禁時間"]).getTime() : null;
        const isLocked = releaseTime && releaseTime > now;
        const safeUrl = (isOwned && !isLocked) ? maskActionUrl(content.Action_url) : null;

        return {
          code: content.id,
          title: content[`タイトル(${suffix})`] || content["タイトル(jp)"],
          message: content[`メッセージ(${suffix})`] || content["メッセージ(jp)"], 
          extraInfo: content[`詳細(${suffix})`] || content["詳細(jp)"],
          imageUrl: content.Imag_Url, 
          url: safeUrl,
          releaseDateIso: content["解禁時間"], expireDateIso: content["有効時間"], icon: content.アイコン || 'download',
          groupId: content["重複"], buttonLabel: content[`ボタン(${suffix})`] || content["ボタン(jp)"], price: content["価格"] || 0, isOwned: isOwned
        };
      });
      return res.status(200).json({ success: true, items });
    }

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

        const now = Date.now();
        const releaseTime = c["解禁時間"] ? new Date(c["解禁時間"]).getTime() : null;
        const expireTime = c["有効時間"] ? new Date(c["有効時間"]).getTime() : null;
        
        const isLocked = releaseTime && releaseTime > now;
        const isExpired = expireTime && expireTime <= now;
        
        const safeUrl = (isLocked || isExpired) ? null : maskActionUrl(c.Action_url);

        return {
          code: codeRec["アクティベーションコード"], date: h.created_at, title: c[`タイトル(${suffix})`] || c["タイトル(jp)"],
          message: c[`メッセージ(${suffix})`] || c["メッセージ(jp)"], 
          url: safeUrl,
          imageUrl: c.Imag_Url,
          icon: c.アイコン || 'download', releaseDateIso: c["解禁時間"], expireDateIso: c["有効時間"], extraInfo: c[`詳細(${suffix})`] || c["詳細(jp)"],
          groupId: c["重複"], buttonLabel: c[`ボタン(${suffix})`] || c["ボタン(jp)"], price: c["価格"] || 0
        };
      }).filter(Boolean);
      return res.status(200).json({ success: true, points: user?.points || 0, history: historyData });
    }

    if (type === 'purchase') {
      const contentId = params.code; 
      if (!authUserId) return res.status(401).json({ success: false, message: "Unauthorized" });
      
      const { data: contentMaster } = await supabase.from('contents').select('*').eq('id', contentId).maybeSingle();
      if (!contentMaster) return res.status(200).json({ success: false, message: "Item not found" });
      
      const { data: user } = await supabase.from('users').select('points').eq('id', authUserId).maybeSingle();
      const { data: existingHist } = await supabase.from('histories').select('codes(content_id)').eq('user_id', authUserId);
      
      let alreadyOwned = false;
      if (existingHist) alreadyOwned = existingHist.some(h => h.codes && String(h.codes.content_id) === String(contentId));
      if (alreadyOwned) return res.status(200).json({ success: false, message: "Already owned" });

      const price = contentMaster["価格"] || 0;
      if (user.points < price) return res.status(200).json({ success: false, message: "Not enough points" });

      const systemCode = `STORE-BUY-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
      const { data: newCode, error: codeErr } = await supabase.from('codes').insert([{
              content_id: contentId,
              "アクティベーションコード": systemCode,
              "USED?": true,
              "有効/無効": true
          }]).select('id').single();

      if (codeErr || !newCode) return res.status(200).json({ success: false, message: "システムエラーにより購入に失敗しました" });
      
      await supabase.from('users').update({ points: user.points - price }).eq('id', authUserId);
      await supabase.from('histories').insert([{ user_id: authUserId, code_id: newCode.id }]);
      
      return res.status(200).json({ success: true, remainingPoints: user.points - price });
    }

    if (type === 'check' || type === 'redeem') {
      const key = params.code || params.key; 
      const mode = params.mode || type;
      const targetId = authUserId; 

      const safeCode = (key || "").replace(/[^A-Z0-9\-]/gi, "").toUpperCase();
      const { data: master, error } = await supabase.from('codes').select('*, contents(*)').eq('アクティベーションコード', safeCode).maybeSingle();

      if (error || !master || !master.contents) return res.status(200).json({ success: false, message: "Invalid code" });

      const content = master.contents;
      const isActive = master["有効/無効"] === true || String(master["有効/無効"]).trim().toUpperCase() === 'TRUE';
      if (!isActive) return res.status(200).json({ success: false, message: "Invalid code" });

      const checkNow = new Date();
      if (content["有効時間"] && checkNow > new Date(content["有効時間"])) return res.status(200).json({ success: false, message: "Invalid code" });

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
          buttonLabel: txt.btnLabel, imageUrl: content.Imag_Url, icon: content.アイコン || 'download', groupId: content["重複"],
          isRare: content.is_rare || false
        });
      }

      if (codeType === 'POINT') {
        if (!targetId) return res.status(200).json({ success: false, message: "Login required" });
        const { data: user } = await supabase.from('users').select('points').eq('id', targetId).maybeSingle();
        if (user) {
           await supabase.from('codes').update({ "USED?": true }).eq('id', master.id);
           await supabase.from('users').update({ points: user.points + (master["Point PPP"] || 0) }).eq('id', targetId);
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
                return h.codes.content_id === content.id || (content["重複"] && h.codes.contents && h.codes.contents["重複"] === content["重複"]);
            });
          }
        }
        if (isOwned) return res.status(200).json({ success: false, isAlreadyOwned: true, message: "Already owned" });

        const isRelease = !content["解禁時間"] || (checkNow >= new Date(content["解禁時間"]));
        const retUrl = isRelease ? maskActionUrl(content.Action_url) : null;

        if (isOnce) {
           await supabase.from('codes').update({ "USED?": true }).eq('id', master.id);
        }

        if (targetId) {
           const { count } = await supabase.from('histories').select('id', { count: 'exact', head: true }).eq('code_id', master.id);
           if (count === 0) {
               await supabase.from('histories').insert([{ user_id: targetId, code_id: master.id }]);
           } else if (isOnce) {
               return res.status(200).json({ success: false, message: "This code has already been used." });
           }
        }

        return res.status(200).json({
          success: true, actionUrl: retUrl, bundleLabel: txt.bundle, message: txt.message,         
          detailedTitle: txt.title, detailedDesc: txt.desc, buttonLabel: txt.btnLabel,
          imageUrl: content.Imag_Url, isReleaseDateReached: isRelease, releaseDateIso: content["解禁時間"],
          expireDateIso: content["有効時間"], btnIcon: content.アイコン || 'download', groupId: content["重複"],
          isRare: content.is_rare || false
        });
      }
    }
    
    return res.status(200).json({ success: false, message: "Invalid request" });

  } catch (error) {
    console.error("Critical API Error:", error);
    return res.status(500).json({ success: false, message: "Internal Server Error" });
  }
}
