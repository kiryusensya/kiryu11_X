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
  throw new Error("FATAL ERROR: å¿…é ˆã®ç’°å¢ƒå¤‰æ•°ãŒè¨­å®šã•ã‚Œã¦ã„ã¾ã›ã‚“ã€‚");
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
        // ã‚µãƒ¼ãƒãƒ¼è‡ªèº«ã®æ­£ç¢ºãªæ™‚åˆ»ï¼ˆUTCãƒ™ãƒ¼ã‚¹ã®ã‚¨ãƒãƒƒã‚¯ãƒŸãƒªç§’ï¼‰ã‚’ä»˜ä¸Ž
        body.serverTime = Date.now();
    }
    return originalJson.call(this, body);
  };

  try {
    // ==========================================
    // ãƒ¬ãƒ¼ãƒˆãƒªãƒŸãƒƒãƒˆ (Rate Limiting)
    // ==========================================
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
                return res.status(429).json({ success: false, message: "ãƒªã‚¯ã‚¨ã‚¹ãƒˆãŒå¤šã™ãŽã¾ã™ã€‚ã—ã°ã‚‰ãå¾…ã£ã¦ã‹ã‚‰å†è©¦è¡Œã—ã¦ãã ã•ã„ã€‚" });
            }
        }
    }

    // ==========================================
    // ãƒ‘ãƒ©ãƒ¡ãƒ¼ã‚¿å–å¾—
    // ==========================================
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
    
    // ==========================================
    // â˜…å®Œå…¨ã«å›ºå®š: ã‚¨ãƒ³ã‚¿ãƒ¼ãƒ—ãƒ©ã‚¤ã‚ºç‰ˆAPI
    // ==========================================
    const appTier = 'enterprise'; 

    // ==========================================
    // èªè¨¼ (JWT Token Verification)
    // ==========================================
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
        // ãƒ–ãƒ©ãƒƒã‚¯ãƒªã‚¹ãƒˆï¼ˆãƒ­ã‚°ã‚¢ã‚¦ãƒˆæ¸ˆã¿ï¼‰ã«ç™»éŒ²ã•ã‚Œã¦ã„ã‚‹ã‹ç¢ºèª
        const { data: revoked } = await supabase.from('revoked_tokens').select('id').eq('token', token).maybeSingle();
        if (revoked) throw new Error("Token has been revoked");

        authUserId = decoded.userId;
        isAdmin = decoded.isAdmin || false;
      } catch (e) {
        token = null; // ç„¡åŠ¹åŒ–
        authUserId = null;
        isAdmin = false;
      }
    }

    // â–¼â–¼â–¼ ã“ã“ã‹ã‚‰è¿½åŠ : ã‚¢ã‚«ã‚¦ãƒ³ãƒˆBANã®åˆ¤å®šã¨ãƒ–ãƒ­ãƒƒã‚¯ â–¼â–¼â–¼
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
    
// âœ… è¿½åŠ ï¼šBANçŠ¶æ…‹ã ã‘è¿”ã™ï¼ˆè§£é™¤æ¤œçŸ¥ç”¨ï¼‰
if (type === 'check_ban_status') {
  // æœªãƒ­ã‚°ã‚¤ãƒ³ãªã‚‰BANåˆ¤å®šã§ããªã„
  if (!authUserId) {
    return res.status(200).json({ success: false, isBanned: false, message: "Unauthorized" });
  }
  return res.status(200).json({ success: true, isBanned });
}


    // BANã•ã‚Œã¦ã„ã‚‹å ´åˆã€ä¸»è¦ãªãƒ¦ãƒ¼ã‚¶ãƒ¼ã‚¢ã‚¯ã‚·ãƒ§ãƒ³ã§ã€ŒisBanned: trueã€ã‚’è¿”ã—ã¦ãƒ•ãƒ­ãƒ³ãƒˆã§ãƒ¢ãƒ¼ãƒ€ãƒ«ã‚’å‡ºã•ã›ã‚‹
    const restrictedActions = ['purchase', 'check', 'redeem', 'change_password', 'get_video_url', 'get_available', 'get_history'];
    if (isBanned && restrictedActions.includes(type)) {
        return res.status(200).json({ success: false, isBanned: true, message: "ã‚¢ã‚¯ã‚»ã‚¹ãŒç¦æ­¢ã•ã‚Œã¦ã„ã¾ã™ã€‚" });
    }
    // ç›´æŽ¥ãƒ•ã‚¡ã‚¤ãƒ«ã‚’å–å¾—ã™ã‚‹ãƒ€ã‚¦ãƒ³ãƒ­ãƒ¼ãƒ‰ã‚¨ãƒ³ãƒ‰ãƒã‚¤ãƒ³ãƒˆã¯403ã§å¼¾ã
    if (isBanned && type === 'download') {
        return res.status(403).send("Forbidden: ã‚¢ã‚¯ã‚»ã‚¹ãŒç¦æ­¢ã•ã‚Œã¦ã„ã¾ã™ã€‚");
    }
    // â–²â–²â–² ã“ã“ã¾ã§è¿½åŠ  â–²â–²â–²

    // ==========================================
    // â–¼ ã‚¨ãƒ©ãƒ¼æ¤œç´¢æ©Ÿèƒ½ (error.htmlç”¨) â–¼
    // ==========================================
    if (type === 'error_search') {
      const { code } = params;
      if (!code) return res.status(200).json({ success: false, message: "Code is required" });

      const { data: errData, error } = await supabase.from('errors').select('*').eq('code', code).maybeSingle();
      
      if (error || !errData) {
        return res.status(200).json({ success: false, message: "Error code not found" });
      }

      const langColMap = { ja: 'ja', en: 'en', zh: 'zh', 'zh-TW': 'zh_TW', ko: 'ko', ru: 'ru' };
      const colIdx = langColMap[lang] || 'ja';
      const msg = errData[colIdx] || errData['ja'] || errData.message || "ã‚¨ãƒ©ãƒ¼è©³ç´°ãŒè¦‹ã¤ã‹ã‚Šã¾ã›ã‚“ã€‚";

      return res.status(200).json({ success: true, code: errData.code, errorMessage: msg });
    }

    // ==========================================
    // â–¼ ãƒ€ã‚¦ãƒ³ãƒ­ãƒ¼ãƒ‰ï¼ˆãƒ—ãƒ­ã‚­ã‚·ï¼‰å‡¦ç† â–¼
    // ==========================================
    if (type === 'download') {
        const { code, target } = params;
        if (!authUserId) return res.status(401).send("Unauthorized: ãƒ­ã‚°ã‚¤ãƒ³ãŒå¿…è¦ã§ã™ã€‚");

        const { data: userHistories } = await supabase
            .from('histories')
            .select('id, codes(id, content_id, ã‚¢ã‚¯ãƒ†ã‚£ãƒ™ãƒ¼ã‚·ãƒ§ãƒ³ã‚³ãƒ¼ãƒ‰, target_tier, contents(Action_url, "æœ‰åŠ¹æ™‚é–“", "è§£ç¦æ™‚é–“", target_tier))')
            .eq('user_id', authUserId);

        if (!userHistories || userHistories.length === 0) return res.status(403).send("Forbidden: å±¥æ­´ãŒå­˜åœ¨ã—ã¾ã›ã‚“ã€‚");

        const cleanTargetCode = String(code).replace(/[^A-Z0-9]/gi, "").toUpperCase();
        const matchedHistory = userHistories.find(h => {
            if (!h.codes) return false;
            const dbContentId = String(h.codes.content_id);
            const cleanDbCode = String(h.codes["ã‚¢ã‚¯ãƒ†ã‚£ãƒ™ãƒ¼ã‚·ãƒ§ãƒ³ã‚³ãƒ¼ãƒ‰"]).replace(/[^A-Z0-9]/gi, "").toUpperCase();
            return dbContentId === String(code) || cleanDbCode === cleanTargetCode;
        });

        if (!matchedHistory || !matchedHistory.codes || !matchedHistory.codes.contents) {
            return res.status(403).send("Forbidden: ã“ã®ã‚³ãƒ³ãƒ†ãƒ³ãƒ„ã‚’æ‰€æœ‰ã—ã¦ã„ã¾ã›ã‚“ã€‚");
        }

        const content = matchedHistory.codes.contents;
        
        // â˜… ã‚¨ãƒ³ã‚¿ãƒ¼ãƒ—ãƒ©ã‚¤ã‚ºç‰ˆAPIã®ãŸã‚ã€ãƒ–ãƒ­ãƒƒã‚¯å‡¦ç†ã¯ãƒã‚¤ãƒ‘ã‚¹(é€šéŽ)ã•ã›ã¾ã™

        const checkNow = new Date();
        if (content["æœ‰åŠ¹æ™‚é–“"] && checkNow > new Date(content["æœ‰åŠ¹æ™‚é–“"])) return res.status(403).send("Forbidden: æœ‰åŠ¹æœŸé™ãŒåˆ‡ã‚Œã¦ã„ã¾ã™ã€‚");
        if (content["è§£ç¦æ™‚é–“"] && checkNow < new Date(content["è§£ç¦æ™‚é–“"])) return res.status(403).send("Forbidden: ã¾ã è§£ç¦ã•ã‚Œã¦ã„ã¾ã›ã‚“ã€‚");

        // â˜… URLå¾©å…ƒãƒ»å­˜åœ¨ãƒã‚§ãƒƒã‚¯
        let downloadTargetUrl = content.Action_url;
        if (target) {
            let rawTarget = decodeURIComponent(target);
            // é€ã‚‰ã‚Œã¦ããŸã®ãŒãƒ€ãƒŸãƒ¼æ–‡å­—ãªã‚‰ã€ãƒ‡ãƒ¼ã‚¿ãƒ™ãƒ¼ã‚¹ã®æœ¬æ¥ã®URLã‚’å¾©å…ƒã™ã‚‹
            if (rawTarget.startsWith('__MASKED_URL__:')) {
                const idx = parseInt(rawTarget.split(':')[1], 10) || 0;
                const strUrl = String(content.Action_url).trim();
                
                if (strUrl.startsWith('[')) {
                    try {
                        const arr = JSON.parse(strUrl);
                        if (arr[idx] && arr[idx].url) {
                            downloadTargetUrl = arr[idx].url;
                        }
                    } catch(e) {
                        // ãƒ‘ãƒ¼ã‚¹å¤±æ•—æ™‚ã¯ãƒ•ã‚©ãƒ¼ãƒ«ãƒãƒƒã‚¯
                    }
                }
            } else {
                // ãƒ€ãƒŸãƒ¼æ–‡å­—ä»¥å¤–ï¼ˆYouTubeç­‰ï¼‰ãŒé€ã‚‰ã‚Œã¦ããŸå ´åˆã¯ãã®ã¾ã¾ä½¿ç”¨
                downloadTargetUrl = rawTarget;
            }
        }
        
        // ãƒ€ãƒŸãƒ¼æ–‡å­—ã®ã¾ã¾å¾©å…ƒã§ããªã‹ã£ãŸã‚Šã€URLãŒå­˜åœ¨ã—ãªã„å ´åˆã¯ã‚¨ãƒ©ãƒ¼
        if (!downloadTargetUrl || downloadTargetUrl.startsWith('__MASKED_URL__')) {
            return res.status(404).send("Not Found: ãƒ€ã‚¦ãƒ³ãƒ­ãƒ¼ãƒ‰URLãŒè¨­å®šã•ã‚Œã¦ã„ã¾ã›ã‚“ã€‚");
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
            return res.status(500).send("Internal Server Error: ãƒ•ã‚¡ã‚¤ãƒ«ã®å–å¾—ã«å¤±æ•—ã—ã¾ã—ãŸã€‚");
        }
    }

    // ==========================================
    // â–¼ ã‚¢ã‚¯ã‚»ã‚¹ãƒ­ã‚°ãƒ»ç›£æŸ»ãƒ­ã‚° â–¼
    // ==========================================
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

    // ==========================================
    // â–¼ èªè¨¼ç³»å‡¦ç† â–¼
    // ==========================================
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
          
          // â˜… ã‚¢ã‚«ã‚¦ãƒ³ãƒˆã®äº’æ›æ€§ãƒã‚§ãƒƒã‚¯ï¼ˆã‚¨ãƒ³ã‚¿ãƒ¼ãƒ—ãƒ©ã‚¤ã‚ºç‰ˆã¯ã‚¹ã‚¿ãƒ³ãƒ€ãƒ¼ãƒ‰ã‚¢ã‚«ã‚¦ãƒ³ãƒˆã‚’å¼¾ãï¼‰
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
                    // ãƒ–ãƒ©ãƒƒã‚¯ãƒªã‚¹ãƒˆã«ç™»éŒ²
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

    // proxy.js ã® typeåˆ¤å®šã®ä¸¦ã³ï¼ˆadmin_logoutã®ä¸‹ãªã©ï¼‰ã«è¿½åŠ 
    if (type === 'admin_verify') {
        if (!isAdmin || !authUserId) return res.status(401).json({ success: false, message: "Unauthorized" });
        // å¿…è¦ã«å¿œã˜ã¦ãƒ‡ãƒ¼ã‚¿ãƒ™ãƒ¼ã‚¹ä¸Šã§ç¾åœ¨ã‚‚ç®¡ç†è€…æ¨©é™ã‚’æŒã£ã¦ã„ã‚‹ã‹å†ç¢ºèªã™ã‚‹
        const { data: adminUser } = await supabase.from('users').select('is_admin').eq('id', authUserId).maybeSingle();
        if (!adminUser || !adminUser.is_admin) return res.status(401).json({ success: false, message: "ç®¡ç†è€…æ¨©é™ãŒå–ã‚Šæ¶ˆã•ã‚Œã¦ã„ã¾ã™" });
        
        return res.status(200).json({ success: true });
    }

    // ==========================================
    // â–¼ ç®¡ç†è€…ç”¨æ©Ÿèƒ½ (å®Œå…¨å®Ÿè£…) â–¼
    // ==========================================
    if (type.startsWith('admin_')) {
        if (!isAdmin) return res.status(401).json({ success: false, message: "ç®¡ç†è€…æ¨©é™ãŒã‚ã‚Šã¾ã›ã‚“" });
        
        // 1. ã‚¢ã‚¯ã‚»ã‚¹ãƒ­ã‚°å–å¾—
        if (type === 'admin_get_access_logs') {
            const limit = params.limit || 100;
            const { data: logs, error } = await supabase.from('access_logs')
                .select(`id, created_at, ip_address, action_type, user_agent, target_code, user_id, app_tier`)
                .neq('action_type', 'admin_get_access_logs')
                .order('created_at', { ascending: false })
                .limit(limit);

            if (error) return res.status(200).json({ success: false, message: "ãƒ­ã‚°ã®å–å¾—ã«å¤±æ•—ã—ã¾ã—ãŸ", error: error.message });

            const formattedLogs = (logs || []).map(log => ({
                id: log.id,
                // â˜… ä¿®æ­£: æ—¥æœ¬æ™‚é–“ã«å›ºå®šã—ã¦å‡ºåŠ›
                date: new Date(log.created_at).toLocaleString('ja-JP', { timeZone: 'Asia/Tokyo' }),
                ip: log.ip_address,
                type: log.action_type,
                code: log.target_code || '-',
                email: log.user_id ? `ID: ${log.user_id.substring(0, 8)}...` : 'æœªãƒ­ã‚°ã‚¤ãƒ³ (GUEST)',
                userAgent: log.user_agent,
                appTier: log.app_tier || 'ä¸æ˜Ž'
            }));
            return res.status(200).json({ success: true, logs: formattedLogs });
        }
        
        // 2. ãƒ¦ãƒ¼ã‚¶ãƒ¼ä½œæˆ
        if (type === 'admin_create_user') {
            const { email, password, target_tier } = params; 
            const tierToAssign = target_tier || 'standard'; // â˜…è¿½åŠ : HTMLã‹ã‚‰å—ã‘å–ã£ãŸTier
            if (!email || !password) return res.status(200).json({ success: false, message: "Missing credentials" });
            const { data: existing } = await supabase.from('users').select('id').eq('email', email).maybeSingle();
            if (existing) return res.status(200).json({ success: false, message: "ãã®IDã¯æ—¢ã«å­˜åœ¨ã—ã¾ã™" });
            
            const hashedPassword = await bcrypt.hash(password, 10);
            const { error } = await supabase.from('users').insert([{ email, password: hashedPassword, points: 0, needs_password_change: true, app_tier: tierToAssign }]);
            if (error) return res.status(200).json({ success: false, message: error.message });
            await logAudit('CREATE_USER', email, { tier: tierToAssign });
            return res.status(200).json({ success: true, message: "OK" });
        }

        // 3. ãƒ‘ã‚¹ãƒ¯ãƒ¼ãƒ‰ãƒªã‚»ãƒƒãƒˆ
        if (type === 'admin_reset_password') {
            const { targetEmail, newPassword } = params;
            if (!targetEmail || !newPassword) return res.status(200).json({ success: false, message: "Missing credentials" });
            const hashedPassword = await bcrypt.hash(newPassword, 10);
            const { error } = await supabase.from('users').update({ password: hashedPassword, needs_password_change: true }).eq('email', targetEmail);
            if (error) return res.status(200).json({ success: false, message: error.message });
            await logAudit('RESET_PASSWORD', targetEmail, {});
            return res.status(200).json({ success: true });
        }

      // â–¼â–¼â–¼ ã“ã“ã‹ã‚‰è¿½åŠ : ã‚¢ã‚«ã‚¦ãƒ³ãƒˆåœæ­¢ (BAN) æ©Ÿèƒ½ â–¼â–¼â–¼
        if (type === 'admin_ban_user') {
            const { targetEmail, banType, banUntil } = params;
            if (!targetEmail || !banType) return res.status(200).json({ success: false, message: "Missing parameters" });

            let targetDate = null;
            if (banType === 'temporary' && banUntil) {
                // â˜… ä¿®æ­£: é€ã‚‰ã‚Œã¦ããŸæ—¥æ™‚(YYYY-MM-DDThh:mm)ã‚’æ—¥æœ¬æ™‚é–“(+09:00)ã¨ã—ã¦è§£é‡ˆã—ã€DBä¿å­˜ç”¨ã®UTCã«å¤‰æ›
                targetDate = new Date(banUntil + '+09:00').toISOString();
            } else if (banType === 'permanent') {
                targetDate = '2099-12-31T23:59:59.000Z'; // æ°¸ä¹…BANã¯æœªæ¥ã®æ—¥ä»˜ã‚’è¨­å®š
            } // 'none' (è§£é™¤) ã®å ´åˆã¯ null ã®ã¾ã¾

            const { error } = await supabase.from('users').update({ banned_until: targetDate }).eq('email', targetEmail);
            if (error) return res.status(200).json({ success: false, message: error.message });

            await logAudit('BAN_USER', targetEmail, { banType, targetDate });
            return res.status(200).json({ success: true, message: "ã‚¢ã‚«ã‚¦ãƒ³ãƒˆã®ã‚¢ã‚¯ã‚»ã‚¹åˆ¶é™ã‚’é©ç”¨ã—ã¾ã—ãŸ" });
        }

       // 4. ãƒ¦ãƒ¼ã‚¶ãƒ¼æƒ…å ±æ¤œç´¢
        if (type === 'admin_search') {
            const { targetEmail } = params;
            const { data: user, error } = await supabase.from('users').select('id, email, points, app_tier, banned_until').eq('email', targetEmail).maybeSingle();
            if (error || !user) return res.status(200).json({ success: false, message: "ãƒ¦ãƒ¼ã‚¶ãƒ¼ãŒè¦‹ã¤ã‹ã‚Šã¾ã›ã‚“" });

            const { data: histories } = await supabase.from('histories')
                .select('created_at, codes(*, contents(*))')
                .eq('user_id', user.id)
                .order('created_at', { ascending: false });

            const historyList = (histories || []).map(h => {
                const codeData = h.codes || {};
                const contentData = codeData.contents || {};
                
                return {
                    title: contentData['ã‚¿ã‚¤ãƒˆãƒ«(jp)'] || 'ä¸æ˜Žãªã‚³ãƒ³ãƒ†ãƒ³ãƒ„',
                    code: codeData['ã‚¢ã‚¯ãƒ†ã‚£ãƒ™ãƒ¼ã‚·ãƒ§ãƒ³ã‚³ãƒ¼ãƒ‰'] || '-',
                    // â˜… ä¿®æ­£: å±¥æ­´ã®æ—¥æ™‚ã‚’æ—¥æœ¬æ™‚é–“ã«å›ºå®š
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

        // 5. ãƒã‚¤ãƒ³ãƒˆä»˜ä¸Žãƒ»å¤‰æ›´
        if (type === 'admin_set_points') {
            const { targetEmail, amount } = params;
            const { error } = await supabase.from('users').update({ points: amount }).eq('email', targetEmail);
            if (error) return res.status(200).json({ success: false, message: error.message });
            await logAudit('SET_POINTS', targetEmail, { amount });
            return res.status(200).json({ success: true });
        }
      // â˜… è¿½åŠ : 5-2. ãƒ¦ãƒ¼ã‚¶ãƒ¼æ¨©é™(Tier)ã®å¤‰æ›´
        if (type === 'admin_set_tier') {
            const { targetEmail, targetTier } = params;
            if (!targetEmail || !targetTier) {
                return res.status(200).json({ success: false, message: "å¿…è¦ãªãƒ‘ãƒ©ãƒ¡ãƒ¼ã‚¿ãŒä¸è¶³ã—ã¦ã„ã¾ã™" });
            }
            
            // Tierã®å€¤ã‚’ standard ã‹ enterprise ã«ãƒãƒªãƒ‡ãƒ¼ã‚·ãƒ§ãƒ³
            const safeTier = targetTier === 'enterprise' ? 'enterprise' : 'standard';
            
            const { error } = await supabase.from('users').update({ app_tier: safeTier }).eq('email', targetEmail);
            
            if (error) {
                return res.status(200).json({ success: false, message: error.message });
            }
            
            // ç›£æŸ»ãƒ­ã‚°ã«æ¨©é™å¤‰æ›´ã‚’è¨˜éŒ²
            await logAudit('SET_TIER', targetEmail, { newTier: safeTier });
            
            return res.status(200).json({ success: true, message: `æ¨©é™ã‚’ ${safeTier} ã«å¤‰æ›´ã—ã¾ã—ãŸ` });
        }

        // 6. ãƒ¦ãƒ¼ã‚¶ãƒ¼å‰Šé™¤
        if (type === 'admin_delete_user') {
            const { targetEmail, adminPassword } = params;
            
            // å†èªè¨¼: é€ä¿¡ã•ã‚ŒãŸç®¡ç†è€…ã®ãƒ‘ã‚¹ãƒ¯ãƒ¼ãƒ‰ã‚’æ¤œè¨¼
            if (!adminPassword) return res.status(200).json({ success: false, message: "å†èªè¨¼ã®ãŸã‚ç®¡ç†è€…ãƒ‘ã‚¹ãƒ¯ãƒ¼ãƒ‰ãŒå¿…è¦ã§ã™" });
            const { data: adminUser } = await supabase.from('users').select('password').eq('id', authUserId).maybeSingle();
            if (!adminUser || !(await bcrypt.compare(adminPassword, adminUser.password))) {
                return res.status(200).json({ success: false, message: "ç®¡ç†è€…ãƒ‘ã‚¹ãƒ¯ãƒ¼ãƒ‰ãŒé–“é•ã£ã¦ã„ã¾ã™ã€‚æ“ä½œã¯å–ã‚Šæ¶ˆã•ã‚Œã¾ã—ãŸ" });
            }

            const { data: user } = await supabase.from('users').select('id').eq('email', targetEmail).maybeSingle();
            if (!user) return res.status(200).json({ success: false, message: "ãƒ¦ãƒ¼ã‚¶ãƒ¼ãŒè¦‹ã¤ã‹ã‚Šã¾ã›ã‚“" });
            const { error } = await supabase.from('users').delete().eq('email', targetEmail);
            if (error) return res.status(200).json({ success: false, message: error.message });
            await logAudit('DELETE_USER', targetEmail, {});
            return res.status(200).json({ success: true });
        }

        // 7. æ‰€æŒã‚³ãƒ³ãƒ†ãƒ³ãƒ„å‰¥å¥ª
        if (type === 'admin_revoke_content') {
            const { targetEmail, code } = params;
            const { data: user } = await supabase.from('users').select('id').eq('email', targetEmail).maybeSingle();
            if (!user) return res.status(200).json({ success: false, message: "ãƒ¦ãƒ¼ã‚¶ãƒ¼ãŒè¦‹ã¤ã‹ã‚Šã¾ã›ã‚“" });

            const { data: codeData } = await supabase.from('codes').select('id').eq('ã‚¢ã‚¯ãƒ†ã‚£ãƒ™ãƒ¼ã‚·ãƒ§ãƒ³ã‚³ãƒ¼ãƒ‰', code).maybeSingle();
            if (codeData) {
                const { error } = await supabase.from('histories').delete().eq('user_id', user.id).eq('code_id', codeData.id);
                if (error) return res.status(200).json({ success: false, message: error.message });
            }
            await logAudit('REVOKE_CONTENT', targetEmail, { code });
            return res.status(200).json({ success: true });
        }

        // 8. ã‚³ãƒ³ãƒ†ãƒ³ãƒ„(ãƒžã‚¹ã‚¿ãƒ¼ãƒ‡ãƒ¼ã‚¿)ç™»éŒ²ãƒ»æ›´æ–°
        if (type === 'admin_save_content') {
            const { payload } = params;
            if (!payload) return res.status(200).json({ success: false, message: "ãƒ‡ãƒ¼ã‚¿ãŒã‚ã‚Šã¾ã›ã‚“" });
            
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

        // 9. ã‚³ãƒ¼ãƒ‰ç™ºè¡Œ
        if (type === 'admin_create_code') {
            const { contentId, code, codeType, pointPpp, isActive, targetTier } = params; // â˜… targetTierã‚’è¿½åŠ 
            const { error } = await supabase.from('codes').insert([{
                content_id: contentId,
                'ã‚¢ã‚¯ãƒ†ã‚£ãƒ™ãƒ¼ã‚·ãƒ§ãƒ³ã‚³ãƒ¼ãƒ‰': code,
                Types: codeType,
                'Point PPP': pointPpp,
                'æœ‰åŠ¹/ç„¡åŠ¹': isActive,
                'USED?': false,
                target_tier: targetTier // â˜… ãƒ‡ãƒ¼ã‚¿ãƒ™ãƒ¼ã‚¹ã«Tierã‚’ä¿å­˜
            }]);
            if (error) return res.status(200).json({ success: false, message: error.message });
            await logAudit('CREATE_CODE', 'system', { code });
            return res.status(200).json({ success: true });
        }

        // 10. ã‚³ãƒ¼ãƒ‰ã‚¹ãƒ†ãƒ¼ã‚¿ã‚¹ç¢ºèª
        if (type === 'admin_check_code') {
            const { code } = params;
            // â˜…è¿½åŠ : target_tier ã‚’å–å¾—ã™ã‚‹ã‚ˆã†å¤‰æ›´
            const { data: codeData, error } = await supabase.from('codes').select('*, contents("ã‚¿ã‚¤ãƒˆãƒ«(jp)", target_tier)').eq('ã‚¢ã‚¯ãƒ†ã‚£ãƒ™ãƒ¼ã‚·ãƒ§ãƒ³ã‚³ãƒ¼ãƒ‰', code).maybeSingle();
            if (error || !codeData) return res.status(200).json({ success: false, message: "ã‚³ãƒ¼ãƒ‰ãŒè¦‹ã¤ã‹ã‚Šã¾ã›ã‚“" });

            let usedTime = null;
            let usedBy = null;

            if (codeData['USED?']) {
                const { data: hist } = await supabase.from('histories').select('created_at, users(email)').eq('code_id', codeData.id).maybeSingle();
                if (hist) {
                    usedTime = hist.created_at;
                    usedBy = hist.users?.email;
                }
            }
            
            // â˜… ã‚³ãƒ¼ãƒ‰ã®éšŽå±¤ã€ã¾ãŸã¯ã‚³ãƒ³ãƒ†ãƒ³ãƒ„ã®éšŽå±¤ã‚’åˆ¤åˆ¥
            const tTier = codeData.target_tier || codeData.contents?.target_tier || 'all';

            return res.status(200).json({
                success: true,
                code: codeData['ã‚¢ã‚¯ãƒ†ã‚£ãƒ™ãƒ¼ã‚·ãƒ§ãƒ³ã‚³ãƒ¼ãƒ‰'],
                title: codeData.contents?.['ã‚¿ã‚¤ãƒˆãƒ«(jp)'],
                isUsed: codeData['USED?'],
                usedTime,
                usedBy,
                targetTier: tTier // â˜…è¿½åŠ : ç¢ºèªçµæžœã¨ã—ã¦Tierã‚’è¿”ã™
            });
        }

        // 11. ã‚³ãƒ¼ãƒ‰ã‚¹ãƒ†ãƒ¼ã‚¿ã‚¹(ä½¿ç”¨æ¸ˆã¿)ã®è§£é™¤
        if (type === 'admin_reset_code') {
            const { code } = params;
            const { data: codeData } = await supabase.from('codes').select('id').eq('ã‚¢ã‚¯ãƒ†ã‚£ãƒ™ãƒ¼ã‚·ãƒ§ãƒ³ã‚³ãƒ¼ãƒ‰', code).maybeSingle();
            if (!codeData) return res.status(200).json({ success: false, message: "ã‚³ãƒ¼ãƒ‰ãŒè¦‹ã¤ã‹ã‚Šã¾ã›ã‚“" });

            await supabase.from('histories').delete().eq('code_id', codeData.id);
            const { error } = await supabase.from('codes').update({ 'USED?': false }).eq('id', codeData.id);
            
            if (error) return res.status(200).json({ success: false, message: error.message });
            await logAudit('RESET_CODE', 'system', { code });
            return res.status(200).json({ success: true });
        }
    }
    // ==========================================
    // â–¼ å‹•ç”»è¦–è´ç”¨ã®ä¸€æ™‚URLå–å¾—å‡¦ç† â–¼
    // ==========================================
    if (type === 'get_video_url') {
        const { code, target } = params;
        if (!authUserId) return res.status(401).json({ success: false, message: "Unauthorized" });

        const { data: userHistories } = await supabase.from('histories')
            .select('id, codes(id, content_id, ã‚¢ã‚¯ãƒ†ã‚£ãƒ™ãƒ¼ã‚·ãƒ§ãƒ³ã‚³ãƒ¼ãƒ‰, contents(Action_url, "æœ‰åŠ¹æ™‚é–“", "è§£ç¦æ™‚é–“"))')
            .eq('user_id', authUserId);

        if (!userHistories || userHistories.length === 0) return res.status(403).json({ success: false, message: "Forbidden" });

        const cleanTargetCode = String(code).replace(/[^A-Z0-9]/gi, "").toUpperCase();
        const matchedHistory = userHistories.find(h => {
            if (!h.codes) return false;
            const dbContentId = String(h.codes.content_id);
            const cleanDbCode = String(h.codes["ã‚¢ã‚¯ãƒ†ã‚£ãƒ™ãƒ¼ã‚·ãƒ§ãƒ³ã‚³ãƒ¼ãƒ‰"]).replace(/[^A-Z0-9]/gi, "").toUpperCase();
            return dbContentId === String(code) || cleanDbCode === cleanTargetCode;
        });

        if (!matchedHistory || !matchedHistory.codes || !matchedHistory.codes.contents) return res.status(403).json({ success: false, message: "Forbidden" });

        const content = matchedHistory.codes.contents;
        const checkNow = new Date();

        if (content["æœ‰åŠ¹æ™‚é–“"] && checkNow > new Date(content["æœ‰åŠ¹æ™‚é–“"])) return res.status(403).json({ success: false, message: "Expired" });
        if (content["è§£ç¦æ™‚é–“"] && checkNow < new Date(content["è§£ç¦æ™‚é–“"])) return res.status(403).json({ success: false, message: "Locked" });

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
    // ==========================================
// â˜… ç›´ãƒªãƒ³ã‚¯éš è”½ï¼ˆãƒžã‚¹ã‚­ãƒ³ã‚°ï¼‰ç”¨ãƒ˜ãƒ«ãƒ‘ãƒ¼é–¢æ•°
// ==========================================
const maskActionUrl = (rawUrl) => {
  if (!rawUrl) return null;
  let strUrl = String(rawUrl).trim();
  
  // JSONé…åˆ—ï¼ˆè¤‡æ•°ãƒªãƒ³ã‚¯ï¼‰ã®å ´åˆã€å„URLã‚’ãƒ€ãƒŸãƒ¼æ–‡å­—åˆ—ã«ç½®ãæ›ãˆã‚‹
  if (strUrl.startsWith('[')) {
      try {
          const arr = JSON.parse(strUrl);
          const maskedArr = arr.map((item, index) => {
              // YouTubeã¯å‹•ç”»å†ç”Ÿã«ç›´æŽ¥å¿…è¦ãªã®ã§éš è”½ã—ãªã„
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
  
  // å˜ä¸€ãƒªãƒ³ã‚¯ã®å ´åˆ
  const isYouTube = strUrl.includes('youtube.com') || strUrl.includes('youtu.be');
  if (isYouTube) return strUrl; 
  
  // Wixãªã©ã®ç›´ãƒªãƒ³ã‚¯ã¯å®Œå…¨ã«ãƒ€ãƒŸãƒ¼æ–‡å­—åˆ—ã«ç½®ãæ›ãˆã‚‹
  return `__MASKED_URL__:0`;
};

    // ==========================================
    // â–¼ ä¸€èˆ¬ãƒ¦ãƒ¼ã‚¶ãƒ¼ç”¨æ©Ÿèƒ½ â–¼
    // ==========================================
    // ==========================================
    // â–¼ ã‚µãƒãƒ¼ãƒˆãƒªãƒ³ã‚¯é›†æ©Ÿèƒ½ â–¼
    // ==========================================
    if (type === 'get_support_links') {
        const { data: links, error } = await supabase
            .from('support_links')
            .select('*')
            .eq('is_active', true)
            .order('sort_order', { ascending: true });

        if (error) {
            return res.status(500).json({ success: false, message: "ãƒªãƒ³ã‚¯ã®å–å¾—ã«å¤±æ•—ã—ã¾ã—ãŸã€‚" });
        }
        return res.status(200).json({ success: true, links: links || [] });
    }

    // â–¼ ãƒ–ãƒ©ãƒƒã‚¯ãƒªã‚¹ãƒˆæ–¹å¼ã«å¤‰æ›´
    if (type === 'auth_instagram') {
        const { username } = params;
        if (!username) return res.status(200).json({ success: false, message: "ãƒ¦ãƒ¼ã‚¶ãƒ¼åã‚’å…¥åŠ›ã—ã¦ãã ã•ã„" });

        // Supabaseã®ãƒ–ãƒ©ãƒƒã‚¯ãƒªã‚¹ãƒˆã‚’æ¤œç´¢ (å¤§æ–‡å­—å°æ–‡å­—ã‚’åŒºåˆ¥ã›ãšã«ä¸€è‡´ãƒã‚§ãƒƒã‚¯)
        const { data: blockedUser, error } = await supabase
            .from('blocked_instagram_users')
            .select('username')
            .ilike('username', username)
            .maybeSingle();

        // ãƒ–ãƒ©ãƒƒã‚¯ãƒªã‚¹ãƒˆã«ç™»éŒ²ã•ã‚Œã¦ã„ã‚‹å ´åˆ -> æ‹’å¦
        if (blockedUser) {
            await logAudit('INSTAGRAM_AUTH_BLOCKED', username, { status: 'blocked' });
            return res.status(403).json({ success: false, message: "ã“ã®ã‚¢ã‚«ã‚¦ãƒ³ãƒˆã‹ã‚‰ã®ã‚¢ã‚¯ã‚»ã‚¹ã¯åˆ¶é™ã•ã‚Œã¦ã„ã¾ã™ã€‚" });
        }

        // ç™»éŒ²ã•ã‚Œã¦ã„ãªã„å ´åˆ -> è¨±å¯ (é€šéŽ)
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
                const { data: ownedContents } = await supabase.from('contents').select('é‡è¤‡').in('id', contentIds);
                if(ownedContents) ownedGroupIds = new Set(ownedContents.map(c => c["é‡è¤‡"]).filter(Boolean));
            }
        }
      }

      const lMap = { ja: 'jp', en: 'en', zh: 'zh', 'zh-TW': 'zh-TW', ko: 'ko', ru: 'ru' };
      const suffix = lMap[lang] || 'jp';

      const filteredContents = (allContents || []).filter(c => {
          const isShow = String(c["show/ hide"] || "").trim().toLowerCase() === 'show';
          if (!isShow) return false;
          if (c["æœ‰åŠ¹æ™‚é–“"] && new Date(c["æœ‰åŠ¹æ™‚é–“"]).getTime() <= Date.now()) return false;
          
          // â˜… ã‚¨ãƒ³ã‚¿ãƒ¼ãƒ—ãƒ©ã‚¤ã‚ºç‰ˆAPIã®ãŸã‚åˆ¶é™ãªã—ã§è¡¨ç¤º
          return true;
      });

      const items = filteredContents.map(content => {
        const isOwned = ownedContentIds.has(content.id) || (content["é‡è¤‡"] && ownedGroupIds.has(content["é‡è¤‡"]));
        
        // â–¼ è¿½åŠ : ç¾åœ¨æ™‚åˆ»ã¨è§£ç¦æ™‚é–“ã‚’æ¯”è¼ƒ
        const now = Date.now();
        const releaseTime = content["è§£ç¦æ™‚é–“"] ? new Date(content["è§£ç¦æ™‚é–“"]).getTime() : null;
        const isLocked = releaseTime && releaseTime > now;

        // â˜… æ‰€æœ‰æ¸ˆã¿ã§ã‚ã£ã¦ã‚‚ã€è§£ç¦å‰ã®å ´åˆã¯URLã‚’éš è”½ã™ã‚‹ (æœŸé™åˆ‡ã‚Œã¯ä¸Šã®filterã§é™¤å¤–æ¸ˆã¿)
        const safeUrl = (isOwned && !isLocked) ? maskActionUrl(content.Action_url) : null;

        return {
          code: content.id,
          title: content[`ã‚¿ã‚¤ãƒˆãƒ«(${suffix})`] || content["ã‚¿ã‚¤ãƒˆãƒ«(jp)"],
          message: content[`ãƒ¡ãƒƒã‚»ãƒ¼ã‚¸(${suffix})`] || content["ãƒ¡ãƒƒã‚»ãƒ¼ã‚¸(jp)"], 
          extraInfo: content[`è©³ç´°(${suffix})`] || content["è©³ç´°(jp)"],
          imageUrl: content.Imag_Url, 
          url: safeUrl, // â˜… ä¿®æ­£
          releaseDateIso: content["è§£ç¦æ™‚é–“"], expireDateIso: content["æœ‰åŠ¹æ™‚é–“"], icon: content.ã‚¢ã‚¤ã‚³ãƒ³ || 'download',
          groupId: content["é‡è¤‡"], buttonLabel: content[`ãƒœã‚¿ãƒ³(${suffix})`] || content["ãƒœã‚¿ãƒ³(jp)"], price: content["ä¾¡æ ¼"] || 0, isOwned: isOwned
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

        // â–¼ è¿½åŠ : ç¾åœ¨æ™‚åˆ»ã¨è§£ç¦æ™‚é–“ãƒ»æœ‰åŠ¹æ™‚é–“ã‚’æ¯”è¼ƒ
        const now = Date.now();
        const releaseTime = c["è§£ç¦æ™‚é–“"] ? new Date(c["è§£ç¦æ™‚é–“"]).getTime() : null;
        const expireTime = c["æœ‰åŠ¹æ™‚é–“"] ? new Date(c["æœ‰åŠ¹æ™‚é–“"]).getTime() : null;
        
        const isLocked = releaseTime && releaseTime > now;
        const isExpired = expireTime && expireTime <= now;
        
        // â˜… æœªè§£ç¦ãƒ»ã¾ãŸã¯æœŸé™åˆ‡ã‚Œã®å ´åˆã¯URLã‚’å®Œå…¨ã«éš è”½
        const safeUrl = (isLocked || isExpired) ? null : maskActionUrl(c.Action_url);

        return {
          code: codeRec["ã‚¢ã‚¯ãƒ†ã‚£ãƒ™ãƒ¼ã‚·ãƒ§ãƒ³ã‚³ãƒ¼ãƒ‰"], date: h.created_at, title: c[`ã‚¿ã‚¤ãƒˆãƒ«(${suffix})`] || c["ã‚¿ã‚¤ãƒˆãƒ«(jp)"],
          message: c[`ãƒ¡ãƒƒã‚»ãƒ¼ã‚¸(${suffix})`] || c["ãƒ¡ãƒƒã‚»ãƒ¼ã‚¸(jp)"], 
          url: safeUrl, // â˜… ä¿®æ­£: safeUrlã‚’é©ç”¨
          imageUrl: c.Imag_Url,
          icon: c.ã‚¢ã‚¤ã‚³ãƒ³ || 'download', releaseDateIso: c["è§£ç¦æ™‚é–“"], expireDateIso: c["æœ‰åŠ¹æ™‚é–“"], extraInfo: c[`è©³ç´°(${suffix})`] || c["è©³ç´°(jp)"],
          groupId: c["é‡è¤‡"], buttonLabel: c[`ãƒœã‚¿ãƒ³(${suffix})`] || c["ãƒœã‚¿ãƒ³(jp)"], price: c["ä¾¡æ ¼"] || 0
        };
      }).filter(Boolean);
      return res.status(200).json({ success: true, points: user?.points || 0, history: historyData });
    }

    if (type === 'purchase') {
      const contentId = params.code; 
      if (!authUserId) return res.status(401).json({ success: false, message: "Unauthorized" });
      
      const { data: contentMaster } = await supabase.from('contents').select('*').eq('id', contentId).maybeSingle();
      if (!contentMaster) return res.status(200).json({ success: false, message: "Item not found" });
      
      // â˜… ã‚¨ãƒ³ã‚¿ãƒ¼ãƒ—ãƒ©ã‚¤ã‚ºç‰ˆAPIã®ãŸã‚ã€åˆ¶é™ãƒ–ãƒ­ãƒƒã‚¯ã‚’ãƒã‚¤ãƒ‘ã‚¹

      const { data: user } = await supabase.from('users').select('points').eq('id', authUserId).maybeSingle();
      const { data: existingHist } = await supabase.from('histories').select('codes(content_id)').eq('user_id', authUserId);
      
      let alreadyOwned = false;
      if (existingHist) alreadyOwned = existingHist.some(h => h.codes && String(h.codes.content_id) === String(contentId));
      if (alreadyOwned) return res.status(200).json({ success: false, message: "Already owned" });

      const price = contentMaster["ä¾¡æ ¼"] || 0;
      if (user.points < price) return res.status(200).json({ success: false, message: "Not enough points" });

      const systemCode = `STORE-BUY-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
      const { data: newCode, error: codeErr } = await supabase.from('codes').insert([{
              content_id: contentId,
              "ã‚¢ã‚¯ãƒ†ã‚£ãƒ™ãƒ¼ã‚·ãƒ§ãƒ³ã‚³ãƒ¼ãƒ‰": systemCode,
              "USED?": true,
              "æœ‰åŠ¹/ç„¡åŠ¹": true
          }]).select('id').single();

      if (codeErr || !newCode) return res.status(200).json({ success: false, message: "ã‚·ã‚¹ãƒ†ãƒ ã‚¨ãƒ©ãƒ¼ã«ã‚ˆã‚Šè³¼å…¥ã«å¤±æ•—ã—ã¾ã—ãŸ" });
      
      await supabase.from('users').update({ points: user.points - price }).eq('id', authUserId);
      await supabase.from('histories').insert([{ user_id: authUserId, code_id: newCode.id }]);
      
      return res.status(200).json({ success: true, remainingPoints: user.points - price });
    }

    if (type === 'check' || type === 'redeem') {
      const key = params.code || params.key; 
      const mode = params.mode || type;
      const targetId = authUserId; 

      const safeCode = (key || "").replace(/[^A-Z0-9\-]/gi, "").toUpperCase();
      const { data: master, error } = await supabase.from('codes').select('*, contents(*)').eq('ã‚¢ã‚¯ãƒ†ã‚£ãƒ™ãƒ¼ã‚·ãƒ§ãƒ³ã‚³ãƒ¼ãƒ‰', safeCode).maybeSingle();

      if (error || !master || !master.contents) return res.status(200).json({ success: false, message: "Invalid code" });

      const content = master.contents;
      
      // â˜… ã‚¨ãƒ³ã‚¿ãƒ¼ãƒ—ãƒ©ã‚¤ã‚ºç‰ˆAPIã®ãŸã‚ã€åˆ¶é™ãƒ–ãƒ­ãƒƒã‚¯ã‚’ãƒã‚¤ãƒ‘ã‚¹

      const isActive = master["æœ‰åŠ¹/ç„¡åŠ¹"] === true || String(master["æœ‰åŠ¹/ç„¡åŠ¹"]).trim().toUpperCase() === 'TRUE';
      if (!isActive) return res.status(200).json({ success: false, message: "Invalid code" });

      const checkNow = new Date();
      if (content["æœ‰åŠ¹æ™‚é–“"] && checkNow > new Date(content["æœ‰åŠ¹æ™‚é–“"])) return res.status(200).json({ success: false, message: "Invalid code" });

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
        btnLabel: content[`ãƒœã‚¿ãƒ³(${suffix})`] || content["ãƒœã‚¿ãƒ³(jp)"], bundle: content[`ãƒãƒ³ãƒ‰ãƒ«(${suffix})`] || content["ãƒãƒ³ãƒ‰ãƒ«(jp)"],
        message: content[`ãƒ¡ãƒƒã‚»ãƒ¼ã‚¸(${suffix})`] || content["ãƒ¡ãƒƒã‚»ãƒ¼ã‚¸(jp)"], title: content[`ã‚¿ã‚¤ãƒˆãƒ«(${suffix})`] || content["ã‚¿ã‚¤ãƒˆãƒ«(jp)"],
        desc: content[`è©³ç´°(${suffix})`] || content["è©³ç´°(jp)"]
      };

      if (mode === 'check') {
        return res.status(200).json({
          success: true, bundleLabel: txt.bundle, message: txt.message, detailedTitle: txt.title, detailedDesc: txt.desc,
          buttonLabel: txt.btnLabel, imageUrl: content.Imag_Url, icon: content.ã‚¢ã‚¤ã‚³ãƒ³ || 'download', groupId: content["é‡è¤‡"],
          isRare: content.is_rare || false // â˜… rareæ©Ÿèƒ½ã‚’å¾©æ´»
        });
      }

      if (codeType === 'POINT') {
        if (!targetId) return res.status(200).json({ success: false, message: "Login required" });
        const { data: user } = await supabase.from('users').select('points').eq('id', targetId).maybeSingle();
        if (user) {
           // URLã‚¨ãƒ©ãƒ¼ã‚’é¿ã‘ã‚‹ãŸã‚ã€ã‚·ãƒ³ãƒ—ãƒ«ãªæ›´æ–°å‡¦ç†ã«æˆ»ã—ã¾ã™
           await supabase.from('codes').update({ "USED?": true }).eq('id', master.id);
           await supabase.from('users').update({ points: user.points + (master["Point PPP"] || 0) }).eq('id', targetId);
        }
        return res.status(200).json({ success: true, isPointMode: true, addedPoints: master["Point PPP"] || 0, message: `${master["Point PPP"] || 0} pt`, title: txt.title || "ãƒã‚¤ãƒ³ãƒˆãƒãƒ£ãƒ¼ã‚¸å®Œäº†" });
      }

      if (codeType !== 'POINT') {
        let isOwned = false;
        if (targetId) {
          const { data: existingHist } = await supabase.from('histories').select('codes(content_id, contents("é‡è¤‡"))').eq('user_id', targetId);
          if (existingHist) {
            isOwned = existingHist.some(h => {
                if (!h.codes) return false;
                return h.codes.content_id === content.id || (content["é‡è¤‡"] && h.codes.contents && h.codes.contents["é‡è¤‡"] === content["é‡è¤‡"]);
            });
          }
        }
        if (isOwned) return res.status(200).json({ success: false, isAlreadyOwned: true, message: "Already owned" });

        const isRelease = !content["è§£ç¦æ™‚é–“"] || (checkNow >= new Date(content["è§£ç¦æ™‚é–“"]));
        // â˜… ä¿®æ­£: è§£ç¦æ—¥ã‚’è¿Žãˆã¦ã„ãªã„å ´åˆã¯URLã‚’éš è”½ã™ã‚‹
        const retUrl = isRelease ? maskActionUrl(content.Action_url) : null;

        // URLã‚¨ãƒ©ãƒ¼ã‚’é¿ã‘ã‚‹ãŸã‚ã€ã‚·ãƒ³ãƒ—ãƒ«ãªæ›´æ–°å‡¦ç†ã«æˆ»ã—ã¾ã™
        if (isOnce) {
           await supabase.from('codes').update({ "USED?": true }).eq('id', master.id);
        }

        if (targetId) {
           // â˜… äºŒé‡ç™»éŒ²ã‚’å°‘ã—ã§ã‚‚é˜²ããŸã‚ã€ã™ã§ã«ã“ã®ã‚³ãƒ¼ãƒ‰ãŒèª°ã‹ã®å±¥æ­´ã«å­˜åœ¨ã—ãªã„ã‹ç›´å‰ã§ç¢ºèªã—ã¾ã™
           const { count } = await supabase.from('histories').select('id', { count: 'exact', head: true }).eq('code_id', master.id);
           
           if (count === 0) {
               await supabase.from('histories').insert([{ user_id: targetId, code_id: master.id }]);
           } else if (isOnce) {
               // ã™ã§ã«èª°ã‹ã®å±¥æ­´ã«å…¥ã£ã¦ã„ã‚‹ONCEã‚³ãƒ¼ãƒ‰ãªã‚‰ã‚¨ãƒ©ãƒ¼ã‚’è¿”ã™
               return res.status(200).json({ success: false, message: "This code has already been used." });
           }
        }

        return res.status(200).json({
          success: true, actionUrl: retUrl, bundleLabel: txt.bundle, message: txt.message,         
          detailedTitle: txt.title, detailedDesc: txt.desc, buttonLabel: txt.btnLabel,
          imageUrl: content.Imag_Url, isReleaseDateReached: isRelease, releaseDateIso: content["è§£ç¦æ™‚é–“"],
          expireDateIso: content["æœ‰åŠ¹æ™‚é–“"], btnIcon: content.ã‚¢ã‚¤ã‚³ãƒ³ || 'download', groupId: content["é‡è¤‡"],
          isRare: content.is_rare || false // â˜… rareæ©Ÿèƒ½ã‚’å¾©æ´»
        });
      }
    }
    
    return res.status(200).json({ success: false, message: "Invalid request" });

  } catch (error) {
    console.error("Critical API Error:", error);
    return res.status(500).json({ success: false, message: "Internal Server Error" });
  }
}
