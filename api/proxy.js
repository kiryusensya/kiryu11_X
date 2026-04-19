import { createClient } from '@supabase/supabase-js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

// 必須の環境変数を取得
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

// 環境変数が欠損している場合はシステムを強制停止させる（安全装置）
if (!supabaseUrl || !supabaseKey || !JWT_SECRET) {
  throw new Error("FATAL ERROR: 必須の環境変数（Supabase設定またはJWT_SECRET）が設定されていません。");
}

const supabase = createClient(supabaseUrl, supabaseKey);

// 許可するフロントエンドのドメイン（本番環境のURLに書き換えてください）
const ALLOWED_ORIGINS = [
  'https://kiryu10-standard.vercel.app',
  'https://kiryu10-enterprise.vercel.app',
  'http://localhost:3000'
];

export default async function handler(req, res) {
  const origin = req.headers.origin;
  
  // リクエスト元が許可リストにある場合のみ、動的にOriginを許可
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');

  // プリフライトリクエストへの応答
  if (req.method === 'OPTIONS') return res.status(200).end();

  const params = req.method === 'POST' ? req.body : req.query;
  const type = params.type;
  const lang = params.lang || 'ja';

  // ==========================================
  // JWTトークンによる認証情報の抽出
  // ==========================================
  let authUserId = null;
  let isAdmin = false;
  const authHeader = req.headers.authorization;
  
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      authUserId = decoded.userId;
      isAdmin = decoded.isAdmin || false;
    } catch (e) {
      // 不正なトークン・期限切れトークンはここで弾かれる
    }
  }

  try {
    // 1. ユーザー登録
    if (type === 'register') {
      const { email, password } = params;
      if (!email || !password) return res.status(200).json({ success: false, message: "Missing credentials" });
      const { data: existing } = await supabase.from('users').select('id').eq('email', email).maybeSingle();
      if (existing) return res.status(200).json({ success: false, message: "Exists" });
      
      // パスワードを bcrypt でハッシュ化
      const hashedPassword = await bcrypt.hash(password, 10);
      
      const { data: newUser, error } = await supabase.from('users').insert([{ email, password: hashedPassword, points: 0 }]).select().single();
      if (error) throw error;
      return res.status(200).json({ success: true, userId: newUser.id, message: "OK" });
    }

    // 2. ユーザーログイン (DBの is_admin カラムを参照)
    if (type === 'user_login') {
      const { email, password } = params;
      
      const { data: user } = await supabase.from('users').select('*').eq('email', email).maybeSingle();
      
      if (user) {
        // bcrypt でパスワードを照合
        const isValidPassword = await bcrypt.compare(password, user.password);
        
        if (isValidPassword) {
            const isUserAdmin = user.is_admin === true;

            // 一般ユーザーで、初期パスワード変更が必要な場合
            if (user.needs_password_change && !isUserAdmin) {
                return res.status(200).json({ success: true, requirePasswordChange: true, userId: user.id });
            }

            // トークンを発行 (DBから取得した権限を付与)
            const token = jwt.sign({ userId: user.id, isAdmin: isUserAdmin }, JWT_SECRET, { expiresIn: '24h' });
            
            return res.status(200).json({ 
                success: true, 
                isAdmin: isUserAdmin, 
                token: token, 
                userId: user.id, 
                points: user.points, 
                history: [] 
            });
        }
      }
      return res.status(200).json({ success: false, message: "Invalid" });
    }

    // ==========================================
    // 管理者用機能 (厳格なトークン権限チェック)
    // ==========================================
    if (type.startsWith('admin_')) {
        if (!isAdmin) {
            return res.status(401).json({ success: false, message: "管理者権限がありません" });
        }

        // 新規ユーザー強制作成
        if (type === 'admin_create_user') {
            const { email, password } = params;
            if (!email || !password) return res.status(200).json({ success: false, message: "Missing credentials" });
            const { data: existing } = await supabase.from('users').select('id').eq('email', email).maybeSingle();
            if (existing) return res.status(200).json({ success: false, message: "そのIDは既に存在します" });
            
            const hashedPassword = await bcrypt.hash(password, 10);
            const { error } = await supabase.from('users').insert([{ 
                email, password: hashedPassword, points: 0, needs_password_change: true 
            }]);
            if (error) throw error;
            return res.status(200).json({ success: true, message: "OK" });
        }

        // パスワード強制リセット
        if (type === 'admin_reset_password') {
            const { targetEmail, newPassword } = params;
            const { data: targetUser } = await supabase.from('users').select('id').eq('email', targetEmail).maybeSingle();
            if (!targetUser) return res.status(200).json({ success: false, message: "指定されたユーザーが見つかりません" });

            const hashedNewPass = await bcrypt.hash(newPassword, 10);
            const { error: updateError } = await supabase.from('users').update({ 
                password: hashedNewPass, needs_password_change: true 
            }).eq('id', targetUser.id);

            if (updateError) return res.status(200).json({ success: false, message: "データベースの更新に失敗しました" });
            return res.status(200).json({ success: true, message: "Password reset successful" });
        }

        // ユーザー履歴検索
        if (type === 'admin_search') {
            const { targetEmail } = params;
            if (!targetEmail) return res.status(200).json({ success: false, message: "対象のメールアドレスを指定してください" });

            const { data: targetUser } = await supabase.from('users').select('id, email').eq('email', targetEmail).maybeSingle();
            if (!targetUser) return res.status(200).json({ success: false, message: "指定されたユーザーが見つかりません" });

            const { data: histories, error: searchError } = await supabase.from('histories')
              .select(`created_at, codes (*)`).eq('user_id', targetUser.id).order('created_at', { ascending: false });

            if (searchError) return res.status(200).json({ success: false, message: "履歴の取得に失敗しました" });

            const historyData = (histories || []).map(h => ({
              code: h.codes ? h.codes["アクティベーションコード"] : "不明",
              title: h.codes ? (h.codes["タイトル(jp)"] || "不明なコンテンツ") : "不明なコンテンツ",
              date: new Date(h.created_at).toLocaleString('ja-JP')
            }));
            return res.status(200).json({ success: true, userId: targetUser.email, history: historyData });
        }
      // ==========================================
        // コンテンツ所有の無効化（履歴の削除）
        // ==========================================
        if (type === 'admin_revoke_content') {
            const { targetEmail, code } = params;
            if (!targetEmail || !code) return res.status(200).json({ success: false, message: "パラメーターが不足しています" });

            // 1. 対象ユーザーのIDを取得
            const { data: targetUser } = await supabase.from('users').select('id').eq('email', targetEmail).maybeSingle();
            if (!targetUser) return res.status(200).json({ success: false, message: "対象のユーザーが見つかりません" });

            // 2. 該当コードのIDを取得
            const { data: targetCode } = await supabase.from('codes').select('id').eq('アクティベーションコード', code).maybeSingle();
            if (!targetCode) return res.status(200).json({ success: false, message: "対象のコードが見つかりません" });

            // 3. histories テーブルから該当レコードを削除する
            const { error: deleteError } = await supabase.from('histories')
                .delete()
                .match({ user_id: targetUser.id, code_id: targetCode.id });

            if (deleteError) {
                console.error("Revoke Error:", deleteError);
                return res.status(200).json({ success: false, message: "データベースの削除に失敗しました" });
            }

            return res.status(200).json({ success: true, message: "Revoked successfully" });
        }
      // ==========================================
        // コードステータス追跡 (admin_check_code)
        // ==========================================
        if (type === 'admin_check_code') {
            const { code } = params;
            if (!code) return res.status(200).json({ success: false, message: "コードを指定してください" });

            // フロントエンドのフォーマットに合わせて大文字・ハイフンのみに整形
            const safeCode = String(code).replace(/[^A-Z0-9\-]/gi, "").toUpperCase();
            
            // codeのIDも取得する
            const { data: master, error } = await supabase.from('codes').select('id, アクティベーションコード, タイトル(jp), バンドル(jp), USED?').eq('アクティベーションコード', safeCode).maybeSingle();
            
            if (error || !master) {
                return res.status(200).json({ success: false, message: "指定されたコードはデータベースに存在しません" });
            }

            const isUsed = master["USED?"] === true || String(master["USED?"]).trim().toUpperCase() === 'TRUE';
            
            let usedTime = null;
            let usedBy = null;

            // 使用済みの場合、履歴(histories)から「いつ・誰が」使ったかを取得
            if (isUsed) {
                const { data: history } = await supabase.from('histories')
                    .select('created_at, users(email)')
                    .eq('code_id', master.id)
                    .order('created_at', { ascending: false })
                    .limit(1)
                    .maybeSingle();
                
                if (history) {
                    usedTime = history.created_at;
                    usedBy = history.users ? history.users.email : '不明なユーザー';
                }
            }

            return res.status(200).json({
                success: true,
                code: master["アクティベーションコード"],
                title: master["タイトル(jp)"] || master["バンドル(jp)"] || "不明",
                isUsed: isUsed,
                usedTime: usedTime,
                usedBy: usedBy
            });
        }

        // ==========================================
        // コードステータス復旧 (admin_reset_code)
        // ==========================================
        if (type === 'admin_reset_code') {
            const { code } = params;
            if (!code) return res.status(200).json({ success: false, message: "コードを指定してください" });

            const safeCode = String(code).replace(/[^A-Z0-9\-]/gi, "").toUpperCase();
            // USED? フラグを false（未使用）に戻す
            const { error } = await supabase.from('codes').update({ "USED?": false }).eq('アクティベーションコード', safeCode);
            
            if (error) {
                console.error("Reset Code Error:", error);
                return res.status(200).json({ success: false, message: "データベースの更新に失敗しました" });
            }
            
            return res.status(200).json({ success: true, message: "OK" });
        }

        // ==========================================
        // ポイント手動調整 (admin_adjust_points)
        // ==========================================
        if (type === 'admin_adjust_points') {
            const { targetEmail, amount } = params;
            if (!targetEmail || amount === undefined) return res.status(200).json({ success: false, message: "パラメーターが不足しています" });

            const { data: targetUser } = await supabase.from('users').select('id, points').eq('email', targetEmail).maybeSingle();
            if (!targetUser) return res.status(200).json({ success: false, message: "対象のユーザーが見つかりません" });

            // 現在のポイントに加算（マイナスになる場合は0でストップさせる）
            const newPoints = Math.max(0, (targetUser.points || 0) + amount);

            const { error } = await supabase.from('users').update({ points: newPoints }).eq('id', targetUser.id);
            if (error) return res.status(200).json({ success: false, message: "ポイントの更新に失敗しました" });

            return res.status(200).json({ success: true, message: "OK" });
        }

        // ==========================================
        // アカウント完全削除 (admin_delete_user)
        // ==========================================
        if (type === 'admin_delete_user') {
            const { targetEmail } = params;
            if (!targetEmail) return res.status(200).json({ success: false, message: "パラメーターが不足しています" });

            const { data: targetUser } = await supabase.from('users').select('id').eq('email', targetEmail).maybeSingle();
            if (!targetUser) return res.status(200).json({ success: false, message: "ユーザーが見つかりません" });

            // 1. 外部キー制約エラーを防ぐため、先に紐づく履歴(histories)を全削除
            await supabase.from('histories').delete().eq('user_id', targetUser.id);
            
            // 2. users テーブルから完全に削除
            const { error } = await supabase.from('users').delete().eq('id', targetUser.id);
            
            if (error) {
                console.error("Delete User Error:", error);
                return res.status(200).json({ success: false, message: "アカウントの削除に失敗しました" });
            }

            return res.status(200).json({ success: true, message: "OK" });
        }

        // ==========================================
        // コンテンツ（コード）の新規発行・上書き保存 (admin_save_code)
        // ==========================================
        if (type === 'admin_save_code') {
            const { code, codeType, titleJp, price, pointPpp } = params;
            if (!code) return res.status(200).json({ success: false, message: "コードを指定してください" });

            const safeCode = String(code).replace(/[^A-Z0-9\-]/gi, "").toUpperCase();
            
            // 既存のコードかどうかチェック
            const { data: existing } = await supabase.from('codes').select('id').eq('アクティベーションコード', safeCode).maybeSingle();

            // DBに保存するデータのベース
            const payload = {
                "アクティベーションコード": safeCode,
                "Types": codeType, // ONCE, MULTIPLE, POINT
                "タイトル(jp)": titleJp,
                "価格": price || 0,
                "Point PPP": codeType === 'POINT' ? pointPpp : 0,
                "有効/無効": true,
                "show/ hide": "show"
            };

            let error;
            if (existing) {
                // 既に存在する場合は上書き更新 (UPDATE)
                const res = await supabase.from('codes').update(payload).eq('id', existing.id);
                error = res.error;
            } else {
                // 存在しない場合は新規作成 (INSERT)
                const res = await supabase.from('codes').insert([payload]);
                error = res.error;
            }

            if (error) {
                console.error("Save Code Error:", error);
                return res.status(200).json({ success: false, message: "データベースへの保存に失敗しました" });
            }
            return res.status(200).json({ success: true, message: "OK" });
        }
    }

    // ==========================================
    // 一般ユーザー用機能 (パスワード変更・ストア機能など)
    // ==========================================
    
    // ★追加: コンテンツ所有の無効化（自分の履歴から削除してストアに戻す）
    if (type === 'revoke_content') {
      const { code } = params;
      if (!authUserId) return res.status(401).json({ success: false, message: "Unauthorized" });

      // 消したいコードのIDを探す
      const { data: targetCode } = await supabase.from('codes').select('id').eq('アクティベーションコード', code).maybeSingle();
      if (!targetCode) return res.status(200).json({ success: false, message: "対象のコードが見つかりません" });

      // histories テーブルから「自分(authUserId)」と「対象コード」の結びつきを削除
      const { error: deleteError } = await supabase.from('histories')
          .delete()
          .match({ user_id: authUserId, code_id: targetCode.id });

      if (deleteError) {
          console.error("Revoke Error:", deleteError);
          return res.status(200).json({ success: false, message: "データベースの削除に失敗しました" });
      }

      return res.status(200).json({ success: true, message: "Revoked successfully" });
    }
    if (type === 'change_password') {
      const { userId, oldPassword, newPassword } = params;
      const targetId = authUserId || userId; 
      const { data: user } = await supabase.from('users').select('*').eq('id', targetId).maybeSingle();
      
      if (user) {
          const isValidOldPass = await bcrypt.compare(oldPassword, user.password);
          if (isValidOldPass) {
              const hashedNewPass = await bcrypt.hash(newPassword, 10);
              await supabase.from('users').update({ password: hashedNewPass, needs_password_change: false }).eq('id', targetId);
              return res.status(200).json({ success: true });
          }
      }
      return res.status(200).json({ success: false, message: "現在のパスワードが間違っています。" });
    }

    // セッション復帰
    if (type === 'get_user_info') {
      if (!authUserId) return res.status(401).json({ success: false, message: "Unauthorized" });
      const { data: user, error } = await supabase.from('users').select('points').eq('id', authUserId).single();
      if (error || !user) return res.status(200).json({ success: false, message: "User not found" });
      return res.status(200).json({ success: true, points: user.points });
    }

    // 利用可能なコンテンツ一覧 (Store)
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

    // ユーザー履歴の取得
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

    // ポイントでの購入
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

    // コードの確認(check) と 引き換え(redeem)
    if (type === 'check' || type === 'redeem') {
      // ★修正：フロントエンドのデータ名（code）を受け取れるようにし、modeもtypeから判別する
      const key = params.code || params.key; 
      const mode = params.mode || type;
      const targetId = authUserId; // 未ログインならnull

      // ハイフンは除去せずにフォーマットを維持
      const safeCode = (key || "").replace(/[^A-Z0-9\-]/gi, "").toUpperCase();
      const { data: master, error } = await supabase.from('codes').select('*').eq('アクティベーションコード', safeCode).maybeSingle();

      // ========================================================
      // ★ここから修正：エラー理由ごとに明確なメッセージを返す
      // ========================================================
      
      // 1. コードがDBに存在しない場合
      if (error || !master) {
          return res.status(200).json({ success: false, message: "Invalid code" });
      }

      // 2. コードが無効化されている場合
      const isActive = master["有効/無効"] === true || String(master["有効/無効"]).trim().toUpperCase() === 'TRUE';
      if (!isActive) {
          return res.status(200).json({ success: false, message: "Invalid code" });
      }

      // 3. 有効期限切れの場合
      const now = new Date();
      if (master["有効時間"] && now > new Date(master["有効時間"])) {
        return res.status(200).json({ success: false, message: "Invalid code" });
      }

      // 4. 使用済みかどうかチェック
      const codeType = (master.Types || "").trim().toUpperCase();
      const isOnce = (codeType === 'ONCE' || codeType === '');
      const rawUsed = master["USED?"];
      const isCodeUsed = rawUsed === true || String(rawUsed).trim().toUpperCase() === 'TRUE';

      // 1回使い切り または ポイントコードで、既に使用済みの場合は「使用済み」と返す
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
    return res.status(200).json({ success: false, message: "Invalid request" });
  } catch (error) {
    console.error("API Error:", error);
    return res.status(500).json({ success: false, message: "Internal Server Error" });
  }
}
