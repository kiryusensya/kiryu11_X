import { PrismaClient } from '@prisma/client';

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
