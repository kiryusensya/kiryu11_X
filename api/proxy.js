import { createClient } from '@supabase/supabase-js';

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ message: "Method Not Allowed" });

  const params = req.body;
  const type = params.type;
  const lang = params.lang || 'ja';

  try {
    // 1. ユーザー登録
    if (type === 'register') {
      const { email, password } = params;
      if (!email || !password) return res.status(200).json({ success: false, message: "Missing credentials" });
      const { data: existing } = await supabase.from('users').select('id').eq('email', email).single();
      if (existing) return res.status(200).json({ success: false, message: "Exists" });
      const { data: newUser, error } = await supabase.from('users').insert([{ email, password, points: 0 }]).select().single();
      if (error) throw error;
      return res.status(200).json({ success: true, userId: newUser.id, message: "OK" });
    }

    // 2. ユーザーログイン
    if (type === 'user_login') {
      const { email, password } = params;
      const { data: user } = await supabase.from('users').select('*').eq('email', email).single();
      if (user && user.password === password) {
        return res.status(200).json({ success: true, userId: user.id, points: user.points, history: [] });
      }
      return res.status(200).json({ success: false, message: "Invalid" });
    }

    // 3. 利用可能なコンテンツ一覧 (Store)
    if (type === 'get_available') {
      const { userId } = params;
      const { data: availableCodes } = await supabase.from('codes').select('*').eq('有効/無効', true).neq('Types', 'POINT');
      
      let ownedCodeIds = new Set();
      let ownedGroupIds = new Set();

      if (userId) {
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

      const items = (availableCodes || []).map(code => {
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
      const { userId } = params;
      if (!userId) return res.status(200).json({ success: false, message: "No User ID" });

      const { data: user } = await supabase.from('users').select('points').eq('id', userId).single();
      if (!user) return res.status(200).json({ success: false, message: "User not found" });

      const { data: histories } = await supabase
        .from('histories')
        .select(`created_at, codes (*)`)
        .eq('user_id', userId)
        .order('created_at', { ascending: false });

      const lMap = { ja: 'jp', en: 'en', zh: 'SC', 'zh-TW': 'TC', ko: 'ko', ru: 'ru' };
      const suffix = lMap[lang] || 'jp';

      const historyData = (histories || []).map(h => {
        const c = h.codes;
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
      });

      return res.status(200).json({ success: true, points: user.points, history: historyData });
    }

    // 5. ポイントでの購入
    if (type === 'purchase') {
      const { userId, code } = params;
      if (!userId || userId === "GUEST") return res.status(200).json({ success: false, message: "Login required" });

      const { data: master } = await supabase.from('codes').select('*').eq('アクティベーションコード', code).single();
      if (!master) return res.status(200).json({ success: false, message: "Item not found" });

      const { data: user } = await supabase.from('users').select('points').eq('id', userId).single();
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

    // 6. コードの確認(check) と 引き換え(redeem)
    if (type === 'check' || type === 'redeem') {
      const { key, userId, mode } = params;
      const safeCode = (key || "").replace(/[^A-Z0-9\-]/gi, "").toUpperCase();

      const { data: master, error } = await supabase.from('codes').select('*').eq('アクティベーションコード', safeCode).single();

      if (error || !master) return res.status(200).json({ success: false, message: "This code is invalid." });

      const now = new Date();
      if (master["有効時間"] && now > new Date(master["有効時間"])) {
        return res.status(200).json({ success: false, message: "This code is invalid." });
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

      if (master.Types === 'POINT' && mode === 'redeem') {
        if (userId === "GUEST") return res.status(200).json({ success: false, message: "Login required" });
        if (master["USED?"]) return res.status(200).json({ success: false, message: "This code has already been used." });

        const { data: user } = await supabase.from('users').select('points').eq('id', userId).single();
        if (user) {
           await supabase.from('users').update({ points: user.points + (master["Point PPP"] || 0) }).eq('id', userId);
           await supabase.from('codes').update({ "USED?": true }).eq('id', master.id);
        }

        return res.status(200).json({
          success: true, isPointMode: true, addedPoints: master["Point PPP"] || 0,
          message: `${master["Point PPP"] || 0} pt`, title: txt.title || "ポイントチャージ完了"
        });
      }

      if (master.Types !== 'POINT') {
        let isOwned = false;
        if (userId !== "GUEST") {
          const { data: existingHist } = await supabase.from('histories').select('codes(アクティベーションコード, 重複)').eq('user_id', userId);
          if (existingHist) {
            isOwned = existingHist.some(h => h.codes && (h.codes["アクティベーションコード"] === safeCode || (master["重複"] && h.codes["重複"] === master["重複"])));
          }
        }

        if (mode === 'redeem' && isOwned) return res.status(200).json({ success: false, isAlreadyOwned: true, message: "Already owned" });
        if (master.Types === 'ONCE' && master["USED?"] && mode !== 'poll') return res.status(200).json({ success: false, message: "This code has already been used." });

        const isRelease = !master["解禁時間"] || (now >= new Date(master["解禁時間"]));
        const retUrl = ((mode === 'redeem' || mode === 'poll') && isRelease) ? master.Action_url : "";

        if (mode === 'redeem') {
          if (userId !== "GUEST") await supabase.from('histories').insert([{ user_id: userId, code_id: master.id }]);
          if (master.Types === 'ONCE') await supabase.from('codes').update({ "USED?": true }).eq('id', master.id);
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
}import { PrismaClient } from '@prisma/client';

// グローバルスコープでPrismaクライアントを初期化（Serverless環境での接続過多を防ぐため）
const globalForPrisma = global;
const prisma = globalForPrisma.prisma || new PrismaClient();
if (process.env.NODE_ENV !== 'production') globalForPrisma.prisma = prisma;

// ランダムなエラーコード生成関数
function generateErrorCode() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+';
  let code = '';
  for(let i=0; i<20; i++) code += chars.charAt(Math.floor(Math.random() * chars.length));
  return code + '.' + Math.floor(Math.random()*10) + '.' + Math.floor(Math.random()*10);
}

export default async function handler(req, res) {
  // CORS対応 (必要であれば)
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // GETリクエスト（get_available, get_historyなど）とPOSTリクエスト両方に対応
  const params = req.method === 'POST' ? req.body : req.query;
  const type = params.type;
  const lang = params.lang || 'ja';

  try {
    // ==========================================
    // 1. サービスの稼働状況確認
    // ==========================================
    if (type === 'service_status') {
      return res.status(200).json({ success: true });
    }

    // ==========================================
    // 2. ユーザー登録
    // ==========================================
    if (type === 'register') {
      const { email, password } = params;
      if (!email || !password) return res.status(200).json({ success: false, message: "Missing credentials" });

      // TODO: 必要であれば管理者判定のロジックを追加
      // if (checkIsAdmin(email, password)) return res.status(200).json({ success: true, isAdmin: true });

      const existingUser = await prisma.user.findUnique({ where: { email } });
      if (existingUser) {
        return res.status(200).json({ success: false, message: "Exists" });
      }

      const newUser = await prisma.user.create({
        data: { email, password, points: 0 }
      });

      return res.status(200).json({ success: true, userId: newUser.id, message: "OK" });
    }

    // ==========================================
    // 3. ユーザーログイン
    // ==========================================
    if (type === 'user_login') {
      const { email, password } = params;

      // TODO: 必要であれば管理者判定のロジックを追加
      // if (checkIsAdmin(email, password)) return res.status(200).json({ success: true, isAdmin: true });

      const user = await prisma.user.findUnique({ where: { email } });
      
      if (user && user.password === password) {
        return res.status(200).json({ 
          success: true, 
          userId: user.id, 
          points: user.points, 
          history: [] // 履歴は別APIで取得するため空で返す
        });
      }
      return res.status(200).json({ success: false, message: "Invalid" });
    }

    // ==========================================
    // 4. 利用可能なコンテンツ一覧 (Store)
    // ==========================================
    if (type === 'get_available') {
      const { userId } = params;
      
      // アクティブなコード一覧を取得 (POINT系は除く)
      const availableCodes = await prisma.code.findMany({
        where: { 
          isActive: true,
          type: { not: 'POINT' } 
        }
      });

      // ユーザーの所有済み履歴を取得
      let userHistory = [];
      if (userId) {
        userHistory = await prisma.history.findMany({
          where: { userId },
          include: { code: true }
        });
      }

      const ownedCodeIds = new Set(userHistory.map(h => h.codeId));
      const ownedGroupIds = new Set(userHistory.map(h => h.code.groupId).filter(Boolean));

      const items = availableCodes.map(code => {
        const txt = code.textData[lang] || code.textData['en'] || code.textData['ja'];
        const isOwned = ownedCodeIds.has(code.id) || (code.groupId && ownedGroupIds.has(code.groupId));

        return {
          code: code.codeString,
          title: txt.title,
          message: txt.message,
          extraInfo: txt.extra,
          imageUrl: code.imageUrl,
          url: code.actionUrl,
          releaseDateIso: code.releaseDate,
          icon: code.icon,
          groupId: code.groupId,
          buttonLabel: txt.btnLabel,
          price: code.price,
          isOwned: isOwned
        };
      });

      return res.status(200).json({ success: true, items });
    }

    // ==========================================
    // 5. ユーザー履歴の取得
    // ==========================================
    if (type === 'get_history') {
      const { userId } = params;
      if (!userId) return res.status(200).json({ success: false, message: "No User ID" });

      const user = await prisma.user.findUnique({
        where: { id: userId },
        include: {
          histories: {
            include: { code: true },
            orderBy: { createdAt: 'desc' } // 最新順
          }
        }
      });

      if (!user) return res.status(200).json({ success: false, message: "User not found" });

      const historyData = user.histories.map(h => {
        const txt = h.code.textData[lang] || h.code.textData['en'] || h.code.textData['ja'];
        return {
          code: h.code.codeString,
          date: h.createdAt,
          title: txt.title,
          message: txt.message,
          url: h.code.actionUrl,
          imageUrl: h.code.imageUrl,
          icon: h.code.icon,
          releaseDateIso: h.code.releaseDate,
          extraInfo: txt.extra,
          groupId: h.code.groupId,
          buttonLabel: txt.btnLabel
        };
      });

      return res.status(200).json({ 
        success: true, 
        points: user.points, 
        history: historyData 
      });
    }

    // ==========================================
    // 6. ポイントでの購入
    // ==========================================
    if (type === 'purchase') {
      const { userId, code } = params;
      if (!userId || userId === "GUEST") return res.status(200).json({ success: false, message: "Login required" });

      const master = await prisma.code.findUnique({ where: { codeString: code } });
      if (!master) return res.status(200).json({ success: false, message: "Item not found" });

      const user = await prisma.user.findUnique({
        where: { id: userId },
        include: { histories: { include: { code: true } } }
      });
      if (!user) return res.status(200).json({ success: false, message: "User not found" });

      // 既に所有しているかチェック
      const alreadyOwned = user.histories.some(h => 
        h.code.codeString === code || 
        (master.groupId && h.code.groupId === master.groupId)
      );

      if (alreadyOwned) return res.status(200).json({ success: false, message: "Already owned" });

      if (user.points < master.price) {
        return res.status(200).json({ success: false, message: "Not enough points" });
      }

      // 購入処理（トランザクション）
      await prisma.$transaction(async (tx) => {
        await tx.user.update({
          where: { id: userId },
          data: { points: { decrement: master.price } }
        });
        await tx.history.create({
          data: { userId: userId, codeId: master.id }
        });
      });

      return res.status(200).json({ success: true, remainingPoints: user.points - master.price });
    }

    // ==========================================
    // 7. 管理者検索
    // ==========================================
    if (type === 'admin_search') {
      const { adminUser, adminPass, targetEmail } = params;
      // TODO: 管理者認証ロジックを追加
      // if (!checkIsAdmin(adminUser, adminPass)) return res.status(200).json({ success: false });

      const targetUser = await prisma.user.findUnique({
        where: { email: targetEmail },
        include: { histories: { include: { code: true }, orderBy: { createdAt: 'desc' } } }
      });

      if (!targetUser) return res.status(200).json({ success: false, message: "User not found" });

      const historyData = targetUser.histories.map(h => {
        const txt = h.code.textData['ja'] || h.code.textData['en'];
        return {
          code: h.code.codeString,
          date: h.createdAt,
          title: txt ? txt.title : "Unknown"
        };
      });

      return res.status(200).json({ success: true, userId: targetUser.id, history: historyData });
    }

    // ==========================================
    // 8. コードの確認(check) と 引き換え(redeem)  ※デフォルト動作
    // ==========================================
    const key = params.key;
    const mode = params.mode || 'check';
    const userId = params.userId || "GUEST";

    if (key) {
      // 入力されたコードのハイフンを保持し、大文字化
      const safeCode = key.replace(/[^A-Z0-9\-]/gi, "").toUpperCase();

      const master = await prisma.code.findUnique({
        where: { codeString: safeCode }
      });

      // エラー時の統一メッセージ
      const genericErrorMessage = "This code is invalid.";

      if (!master) {
        return res.status(200).json({ success: false, message: genericErrorMessage });
      }

      const now = new Date();
      if (master.expirationDate && now > master.expirationDate) {
        return res.status(200).json({ success: false, message: genericErrorMessage });
      }

      // POINTコードの引き換え
      if (master.type === 'POINT' && mode === 'redeem') {
        if (userId === "GUEST") {
          return res.status(200).json({ success: false, message: "Login required" });
        }
        if (master.isUsed) {
          return res.status(200).json({ success: false, message: "This code has already been used." });
        }

        await prisma.$transaction(async (tx) => {
          await tx.user.update({
            where: { id: userId },
            data: { points: { increment: master.pointValue } }
          });
          await tx.code.update({
            where: { id: master.id },
            data: { isUsed: true }
          });
        });

        const txt = master.textData[lang] || master.textData['ja'];
        return res.status(200).json({
          success: true,
          isPointMode: true,
          addedPoints: master.pointValue,
          message: `${master.pointValue} pt`,
          title: txt.title || "ポイントチャージ完了"
        });
      }

      // コンテンツコード (ONCE等)
      if (master.type !== 'POINT') {
        let isOwned = false;
        if (userId !== "GUEST") {
          const userHistory = await prisma.history.findMany({
            where: { userId },
            include: { code: true }
          });
          
          isOwned = userHistory.some(h => 
            h.code.codeString === safeCode || 
            (master.groupId && h.code.groupId === master.groupId)
          );
        }

        if (mode === 'redeem' && isOwned) {
          return res.status(200).json({ success: false, isAlreadyOwned: true, message: "Already owned" });
        }

        if (master.type === 'ONCE' && master.isUsed && mode !== 'poll') {
          return res.status(200).json({ success: false, message: "This code has already been used." });
        }

        const txt = master.textData[lang] || master.textData['en'] || master.textData['ja'];
        const isRelease = !master.releaseDate || (now >= master.releaseDate);
        const retUrl = ((mode === 'redeem' || mode === 'poll') && isRelease) ? master.actionUrl : "";

        if (mode === 'redeem') {
          await prisma.$transaction(async (tx) => {
            if (userId !== "GUEST") {
              await tx.history.create({ data: { userId, codeId: master.id } });
            }
            if (master.type === 'ONCE') {
              await tx.code.update({ where: { id: master.id }, data: { isUsed: true } });
            }
          });
        }

        return res.status(200).json({
          success: true,
          actionUrl: retUrl,
          bundleLabel: txt.bundle,      
          message: txt.message,         
          detailedTitle: txt.title,     
          detailedDesc: txt.desc,       
          buttonLabel: txt.btnLabel,
          imageUrl: master.imageUrl,
          isReleaseDateReached: isRelease,
          releaseDateIso: master.releaseDate,
          btnIcon: master.icon,
          groupId: master.groupId 
        });
      }
    }

    return res.status(200).json({ success: false, message: "Invalid request" });

  } catch (error) {
    console.error("API Error:", error);
    return res.status(500).json({ success: false, message: "Internal Server Error" });
  }
}
