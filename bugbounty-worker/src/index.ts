import { Hono } from "hono";
import { cors } from "hono/cors";
import { createClient } from "@libsql/client/web";

type Bindings = {
  TURSO_URL: string;
  TURSO_AUTH_TOKEN: string;
  ADMIN_KEY: string;
  // メインAPIのセッション検証用
  MAIN_API_URL: string;
};

const app = new Hono<{ Bindings: Bindings }>();

app.use("*", async (c, next) => {
  c.res.headers.set("Access-Control-Allow-Origin", "*");
  c.res.headers.set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS");
  c.res.headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Admin-Key");
  c.res.headers.set("Access-Control-Max-Age", "86400");
  if (c.req.method === "OPTIONS") return c.text("", 204);
  await next();
});

// Tursoクライアントを取得
function db(env: Bindings) {
  return createClient({
    url: env.TURSO_URL,
    authToken: env.TURSO_AUTH_TOKEN,
  });
}

// 管理者認証
function requireAdmin(c: any): boolean {
  return c.req.header("X-Admin-Key") === c.env.ADMIN_KEY;
}

// メインAPIのセッションを検証してhunter_idを取得
async function getHunterId(c: any): Promise<string | null> {
  const token = c.req.header("Authorization")?.replace("Bearer ", "");
  if (!token) return null;
  try {
    const res = await fetch(`${c.env.MAIN_API_URL}/auth/me`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) return null;
    const data: any = await res.json();
    if (data.userType !== "hunter") return null;
    return data.id;
  } catch {
    return null;
  }
}

// =====================================================
// DBセットアップ（初回のみ実行）
// =====================================================

app.post("/setup", async (c) => {
  if (!requireAdmin(c)) return c.json({ error: "unauthorized" }, 401);
  const client = db(c.env);

  await client.executeMultiple(`
    CREATE TABLE IF NOT EXISTS challenges (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      difficulty TEXT NOT NULL DEFAULT 'easy',
      category TEXT NOT NULL DEFAULT 'linux',
      flag TEXT NOT NULL,
      order_index INTEGER NOT NULL DEFAULT 0,
      is_published INTEGER NOT NULL DEFAULT 0,
      points INTEGER NOT NULL DEFAULT 10,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS challenge_commands (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      challenge_id INTEGER NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
      command TEXT NOT NULL,
      response TEXT NOT NULL,
      is_exact INTEGER NOT NULL DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS challenge_completions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      challenge_id INTEGER NOT NULL,
      hunter_id TEXT NOT NULL,
      completed_at INTEGER NOT NULL,
      UNIQUE(challenge_id, hunter_id)
    );
  `);

  return c.json({ ok: true });
});

// =====================================================
// 問題一覧（公開）
// =====================================================

app.get("/challenges", async (c) => {
  const client = db(c.env);
  const { rows } = await client.execute(
    `SELECT id, title, description, difficulty, category, order_index, points, is_published
     FROM challenges WHERE is_published = 1 ORDER BY order_index ASC`
  );
  return c.json({ challenges: rows });
});

// =====================================================
// 問題詳細（コマンド一覧は含まない・フラグも含まない）
// =====================================================

app.get("/challenges/:id", async (c) => {
  const id = c.req.param("id");
  const client = db(c.env);
  const row = await client.execute(
    `SELECT id, title, description, difficulty, category, points FROM challenges WHERE id = ? AND is_published = 1`,
    [id]
  );
  if (!row.rows[0]) return c.json({ error: "not found" }, 404);
  return c.json(row.rows[0]);
});

// =====================================================
// コマンド実行（疑似ターミナル）
// =====================================================

app.post("/challenges/:id/exec", async (c) => {
  const id = c.req.param("id");
  const body = await c.req.json().catch(() => null);
  if (!body?.command) return c.json({ error: "command is required" }, 400);

  const command = String(body.command).trim();
  const client = db(c.env);

  // コマンドの返答を検索（完全一致優先、次に前方一致）
  const exact = await client.execute(
    `SELECT response FROM challenge_commands WHERE challenge_id = ? AND command = ? AND is_exact = 1`,
    [id, command]
  );

  if (exact.rows[0]) {
    return c.json({ output: exact.rows[0].response });
  }

  // 前方一致（コマンド名だけ一致）
  const partial = await client.execute(
    `SELECT response FROM challenge_commands WHERE challenge_id = ? AND ? LIKE command || '%' AND is_exact = 0 LIMIT 1`,
    [id, command]
  );

  if (partial.rows[0]) {
    return c.json({ output: partial.rows[0].response });
  }

  // デフォルト返答
  return c.json({ output: `bash: ${command.split(" ")[0]}: command not found` });
});

// =====================================================
// フラグ送信
// =====================================================

app.post("/challenges/:id/submit", async (c) => {
  const id = c.req.param("id");
  const hunterId = await getHunterId(c);
  if (!hunterId) return c.json({ error: "ログインが必要です" }, 401);

  const body = await c.req.json().catch(() => null);
  if (!body?.flag) return c.json({ error: "flag is required" }, 400);

  const client = db(c.env);
  const challenge = await client.execute(
    `SELECT id, flag, points FROM challenges WHERE id = ? AND is_published = 1`,
    [id]
  );
  if (!challenge.rows[0]) return c.json({ error: "not found" }, 404);

  const row = challenge.rows[0] as any;
  if (body.flag.trim() !== row.flag) {
    return c.json({ correct: false, message: "フラグが違います" });
  }

  // すでにクリア済みか確認
  const already = await client.execute(
    `SELECT id FROM challenge_completions WHERE challenge_id = ? AND hunter_id = ?`,
    [id, hunterId]
  );
  if (already.rows[0]) {
    return c.json({ correct: true, message: "すでにクリア済みです", alreadyCompleted: true });
  }

  // クリア記録
  await client.execute(
    `INSERT INTO challenge_completions (challenge_id, hunter_id, completed_at) VALUES (?, ?, ?)`,
    [id, hunterId, Date.now()]
  );

  return c.json({ correct: true, message: "正解！クリアしました🎉", points: row.points });
});

// クリア済み一覧（ログイン中ハンター）
app.get("/my/completions", async (c) => {
  const hunterId = await getHunterId(c);
  if (!hunterId) return c.json({ error: "ログインが必要です" }, 401);
  const client = db(c.env);
  const { rows } = await client.execute(
    `SELECT challenge_id, completed_at FROM challenge_completions WHERE hunter_id = ?`,
    [hunterId]
  );
  return c.json({ completions: rows });
});

// =====================================================
// 管理者API
// =====================================================

// 問題一覧（管理者・非公開含む）
app.get("/admin/challenges", async (c) => {
  if (!requireAdmin(c)) return c.json({ error: "unauthorized" }, 401);
  const client = db(c.env);
  const { rows } = await client.execute(
    `SELECT * FROM challenges ORDER BY order_index ASC`
  );
  return c.json({ challenges: rows });
});

// 問題作成
app.post("/admin/challenges", async (c) => {
  if (!requireAdmin(c)) return c.json({ error: "unauthorized" }, 401);
  const body = await c.req.json().catch(() => null);
  if (!body?.title || !body?.flag) return c.json({ error: "title と flag は必須です" }, 400);

  const client = db(c.env);
  const result = await client.execute(
    `INSERT INTO challenges (title, description, difficulty, category, flag, order_index, is_published, points, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      body.title,
      body.description || "",
      body.difficulty || "easy",
      body.category || "linux",
      body.flag,
      body.orderIndex || 0,
      body.isPublished ? 1 : 0,
      body.points || 10,
      Date.now(),
    ]
  );
  return c.json({ id: Number(result.lastInsertRowid) });
});

// 問題編集
app.patch("/admin/challenges/:id", async (c) => {
  if (!requireAdmin(c)) return c.json({ error: "unauthorized" }, 401);
  const id = c.req.param("id");
  const body = await c.req.json().catch(() => null);
  const client = db(c.env);

  await client.execute(
    `UPDATE challenges SET
       title = COALESCE(?, title),
       description = COALESCE(?, description),
       difficulty = COALESCE(?, difficulty),
       category = COALESCE(?, category),
       flag = COALESCE(?, flag),
       order_index = COALESCE(?, order_index),
       is_published = COALESCE(?, is_published),
       points = COALESCE(?, points)
     WHERE id = ?`,
    [
      body.title ?? null,
      body.description ?? null,
      body.difficulty ?? null,
      body.category ?? null,
      body.flag ?? null,
      body.orderIndex ?? null,
      body.isPublished !== undefined ? (body.isPublished ? 1 : 0) : null,
      body.points ?? null,
      id,
    ]
  );
  return c.json({ updated: true });
});

// 問題削除
app.delete("/admin/challenges/:id", async (c) => {
  if (!requireAdmin(c)) return c.json({ error: "unauthorized" }, 401);
  const id = c.req.param("id");
  const client = db(c.env);
  await client.execute(`DELETE FROM challenges WHERE id = ?`, [id]);
  return c.json({ deleted: true });
});

// コマンド一覧取得
app.get("/admin/challenges/:id/commands", async (c) => {
  if (!requireAdmin(c)) return c.json({ error: "unauthorized" }, 401);
  const id = c.req.param("id");
  const client = db(c.env);
  const { rows } = await client.execute(
    `SELECT * FROM challenge_commands WHERE challenge_id = ? ORDER BY id ASC`,
    [id]
  );
  return c.json({ commands: rows });
});

// コマンド追加
app.post("/admin/challenges/:id/commands", async (c) => {
  if (!requireAdmin(c)) return c.json({ error: "unauthorized" }, 401);
  const id = c.req.param("id");
  const body = await c.req.json().catch(() => null);
  if (!body?.command || body?.response === undefined) {
    return c.json({ error: "command と response は必須です" }, 400);
  }
  const client = db(c.env);
  const result = await client.execute(
    `INSERT INTO challenge_commands (challenge_id, command, response, is_exact) VALUES (?, ?, ?, ?)`,
    [id, body.command, body.response, body.isExact !== false ? 1 : 0]
  );
  return c.json({ id: Number(result.lastInsertRowid) });
});

// コマンド削除
app.delete("/admin/commands/:id", async (c) => {
  if (!requireAdmin(c)) return c.json({ error: "unauthorized" }, 401);
  const id = c.req.param("id");
  const client = db(c.env);
  await client.execute(`DELETE FROM challenge_commands WHERE id = ?`, [id]);
  return c.json({ deleted: true });
});

export default app;
