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

      const codeType = (master.Types || "").trim().toUpperCase();
      const isOnce = (codeType === 'ONCE' || codeType === '');

      // ★ 超・厳格な使用済みチェック（"FALSE"や空白スペースを無視する）
      const rawUsed = master["USED?"];
      const isCodeUsed = rawUsed === true || String(rawUsed).trim().toUpperCase() === 'TRUE';

      // ONCEコードが使用済みの場合
      if (isOnce && isCodeUsed) {
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

      // ポイントコードの処理
      if (codeType === 'POINT' && mode === 'redeem') {
        if (userId === "GUEST") return res.status(200).json({ success: false, message: "Login required" });
        if (isCodeUsed) return res.status(200).json({ success: false, message: "This code has already been used." });

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

      // 通常コンテンツコードの処理
      if (codeType !== 'POINT') {
        let isOwned = false;
        if (userId !== "GUEST") {
          const { data: existingHist } = await supabase.from('histories').select('codes(アクティベーションコード, 重複)').eq('user_id', userId);
          if (existingHist) {
            isOwned = existingHist.some(h => h.codes && (h.codes["アクティベーションコード"] === safeCode || (master["重複"] && h.codes["重複"] === master["重複"])));
          }
        }

        if (mode === 'redeem' && isOwned) return res.status(200).json({ success: false, isAlreadyOwned: true, message: "Already owned" });

        const isRelease = !master["解禁時間"] || (now >= new Date(master["解禁時間"]));
        const retUrl = ((mode === 'redeem' || mode === 'poll') && isRelease) ? master.Action_url : "";

        if (mode === 'redeem') {
          if (userId !== "GUEST") await supabase.from('histories').insert([{ user_id: userId, code_id: master.id }]);
          
          if (isOnce) {
            await supabase.from('codes').update({ "USED?": true }).eq('id', master.id);
          }
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
