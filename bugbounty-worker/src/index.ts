import { Hono } from "hono";
import { cors } from "hono/cors";

type Bindings = {
  DB: D1Database;
  AVATARS: R2Bucket;
};

type SessionUser = { userType: "hunter" | "program"; userId: string };

const app = new Hono<{ Bindings: Bindings }>();

app.use("*", cors());

// ---------- パスワードのハッシュ化 / 検証 (Web Crypto / PBKDF2) ----------
async function hashPassword(password: string): Promise<string> {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const derivedBits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    256
  );
  const saltHex = Array.from(salt).map((b) => b.toString(16).padStart(2, "0")).join("");
  const hashHex = Array.from(new Uint8Array(derivedBits)).map((b) => b.toString(16).padStart(2, "0")).join("");
  return `${saltHex}:${hashHex}`;
}

async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [saltHex, hashHex] = (stored || "").split(":");
  if (!saltHex || !hashHex) return false;
  const salt = new Uint8Array(saltHex.match(/.{1,2}/g)!.map((b) => parseInt(b, 16)));
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const derivedBits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    256
  );
  const computedHex = Array.from(new Uint8Array(derivedBits)).map((b) => b.toString(16).padStart(2, "0")).join("");
  return computedHex === hashHex;
}

function isValidPassword(password: unknown): password is string {
  return typeof password === "string" && password.length >= 8;
}

// ---------- セッション ----------
const SESSION_DURATION_MS = 7 * 24 * 60 * 60 * 1000; // 7日間

async function createSession(db: D1Database, userType: "hunter" | "program", userId: string): Promise<string> {
  const token = crypto.randomUUID() + crypto.randomUUID().replace(/-/g, "");
  const createdAt = Date.now();
  const expiresAt = createdAt + SESSION_DURATION_MS;
  await db
    .prepare(`INSERT INTO sessions (token, user_type, user_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`)
    .bind(token, userType, userId, createdAt, expiresAt)
    .run();
  return token;
}

async function getSessionUser(c: any): Promise<SessionUser | null> {
  const auth = c.req.header("Authorization");
  if (!auth || !auth.startsWith("Bearer ")) return null;
  const token = auth.slice(7);
  const row = await c.env.DB.prepare(`SELECT * FROM sessions WHERE token = ?`).bind(token).first();
  if (!row) return null;
  if ((row as any).expires_at < Date.now()) return null;
  return { userType: (row as any).user_type, userId: (row as any).user_id };
}

const MAX_AVATAR_BYTES = 2 * 1024 * 1024; // 2MB
const ALLOWED_TYPES = ["image/png", "image/jpeg", "image/webp", "image/gif"];

// ---------- ヘルスチェック ----------
app.get("/", (c) => c.json({ status: "ok", message: "BBP API is running" }));

// =====================================================
// 認証
// =====================================================

app.post("/auth/login", async (c) => {
  const body = await c.req.json().catch(() => null);
  if (!body || !body.userType || !body.email || !body.password) {
    return c.json({ error: "必須項目が不足しています" }, 400);
  }
  if (body.userType !== "hunter" && body.userType !== "program") {
    return c.json({ error: "userTypeが不正です" }, 400);
  }

  const table = body.userType === "hunter" ? "hunters" : "programs";
  const emailCol = body.userType === "hunter" ? "email" : "contact_email";

  const row: any = await c.env.DB.prepare(`SELECT * FROM ${table} WHERE ${emailCol} = ?`).bind(body.email).first();
  if (!row || !row.password_hash || !(await verifyPassword(body.password, row.password_hash))) {
    return c.json({ error: "メールアドレスまたはパスワードが違います" }, 401);
  }

  const token = await createSession(c.env.DB, body.userType, row.id);
  return c.json({
    token,
    userType: body.userType,
    id: row.id,
    name: body.userType === "hunter" ? row.handle : row.company_name,
  });
});

app.get("/auth/me", async (c) => {
  const user = await getSessionUser(c);
  if (!user) return c.json({ error: "unauthorized" }, 401);

  const table = user.userType === "hunter" ? "hunters" : "programs";
  const cols =
    user.userType === "hunter"
      ? "id, handle, email, skills, portfolio, avatar_key, created_at"
      : "id, company_name, contact_email, scope, description, reward_min, reward_max, avatar_key, created_at";

  const row = await c.env.DB.prepare(`SELECT ${cols} FROM ${table} WHERE id = ?`).bind(user.userId).first();
  if (!row) return c.json({ error: "not found" }, 404);
  return c.json({ userType: user.userType, ...row });
});

app.post("/auth/logout", async (c) => {
  const auth = c.req.header("Authorization");
  if (auth && auth.startsWith("Bearer ")) {
    await c.env.DB.prepare(`DELETE FROM sessions WHERE token = ?`).bind(auth.slice(7)).run();
  }
  return c.json({ ok: true });
});

// =====================================================
// プログラム（企業）
// =====================================================

app.post("/programs", async (c) => {
  const body = await c.req.json().catch(() => null);

  if (!body || !body.companyName || !body.contactEmail || !body.scope || !body.description) {
    return c.json({ error: "必須項目が不足しています" }, 400);
  }
  if (!isValidPassword(body.password)) {
    return c.json({ error: "パスワードは8文字以上で入力してください" }, 400);
  }

  const existing = await c.env.DB.prepare(`SELECT id FROM programs WHERE contact_email = ?`)
    .bind(body.contactEmail)
    .first();
  if (existing) {
    return c.json({ error: "このメールアドレスは既に登録されています" }, 409);
  }

  const id = crypto.randomUUID();
  const createdAt = Date.now();
  const passwordHash = await hashPassword(body.password);

  try {
    await c.env.DB.prepare(
      `INSERT INTO programs (id, company_name, contact_email, scope, description, reward_min, reward_max, password_hash, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        id,
        body.companyName,
        body.contactEmail,
        body.scope,
        body.description,
        Number(body.rewardMin) || 0,
        Number(body.rewardMax) || 0,
        passwordHash,
        createdAt
      )
      .run();

    const token = await createSession(c.env.DB, "program", id);
    return c.json({ received: true, id, createdAt, token });
  } catch (err: any) {
    if (String(err?.message || "").includes("UNIQUE")) {
      return c.json({ error: "このメールアドレスは既に登録されています" }, 409);
    }
    console.error("D1 insert error:", err);
    return c.json({ error: "保存に失敗しました" }, 500);
  }
});

app.get("/programs", async (c) => {
  try {
    const { results } = await c.env.DB.prepare(
      `SELECT id, company_name, contact_email, scope, description, reward_min, reward_max, avatar_key, created_at
       FROM programs ORDER BY created_at DESC`
    ).all();
    return c.json({ programs: results });
  } catch (err) {
    console.error("D1 select error:", err);
    return c.json({ error: "取得に失敗しました" }, 500);
  }
});

app.post("/programs/:id/avatar", async (c) => {
  const id = c.req.param("id");
  const user = await getSessionUser(c);
  if (!user || user.userType !== "program" || user.userId !== id) {
    return c.json({ error: "権限がありません。ログインし直してください" }, 403);
  }

  const body = await c.req.parseBody().catch(() => null);
  const file = body?.avatar;
  if (!file || !(file instanceof File)) return c.json({ error: "画像ファイルが見つかりません" }, 400);
  if (!ALLOWED_TYPES.includes(file.type)) return c.json({ error: "png / jpeg / webp / gif のみ対応しています" }, 400);
  if (file.size > MAX_AVATAR_BYTES) return c.json({ error: "ファイルサイズは2MB以下にしてください" }, 400);

  const key = `programs/${id}`;
  try {
    await c.env.AVATARS.put(key, await file.arrayBuffer(), { httpMetadata: { contentType: file.type } });
    await c.env.DB.prepare(`UPDATE programs SET avatar_key = ? WHERE id = ?`).bind(key, id).run();
    return c.json({ received: true, avatarUrl: `/avatars/${key}` });
  } catch (err) {
    console.error("R2 upload error:", err);
    return c.json({ error: "アップロードに失敗しました" }, 500);
  }
});

// =====================================================
// ハンター
// =====================================================

app.post("/hunters", async (c) => {
  const body = await c.req.json().catch(() => null);

  if (!body || !body.handle || !body.email) {
    return c.json({ error: "ハンドルネームとメールアドレスは必須です" }, 400);
  }
  if (!isValidPassword(body.password)) {
    return c.json({ error: "パスワードは8文字以上で入力してください" }, 400);
  }

  const existing = await c.env.DB.prepare(`SELECT id FROM hunters WHERE email = ?`).bind(body.email).first();
  if (existing) {
    return c.json({ error: "このメールアドレスは既に登録されています" }, 409);
  }

  const id = crypto.randomUUID();
  const createdAt = Date.now();
  const passwordHash = await hashPassword(body.password);

  try {
    await c.env.DB.prepare(
      `INSERT INTO hunters (id, handle, email, skills, portfolio, password_hash, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(id, body.handle, body.email, body.skills || null, body.portfolio || null, passwordHash, createdAt)
      .run();

    const token = await createSession(c.env.DB, "hunter", id);
    return c.json({ received: true, id, createdAt, token });
  } catch (err: any) {
    if (String(err?.message || "").includes("UNIQUE")) {
      return c.json({ error: "このメールアドレスは既に登録されています" }, 409);
    }
    console.error("D1 insert error:", err);
    return c.json({ error: "保存に失敗しました" }, 500);
  }
});

app.get("/hunters", async (c) => {
  try {
    const { results } = await c.env.DB.prepare(
      `SELECT id, handle, email, skills, portfolio, avatar_key, created_at
       FROM hunters ORDER BY created_at DESC`
    ).all();
    return c.json({ hunters: results });
  } catch (err) {
    console.error("D1 select error:", err);
    return c.json({ error: "取得に失敗しました" }, 500);
  }
});

app.post("/hunters/:id/avatar", async (c) => {
  const id = c.req.param("id");
  const user = await getSessionUser(c);
  if (!user || user.userType !== "hunter" || user.userId !== id) {
    return c.json({ error: "権限がありません。ログインし直してください" }, 403);
  }

  const body = await c.req.parseBody().catch(() => null);
  const file = body?.avatar;
  if (!file || !(file instanceof File)) return c.json({ error: "画像ファイルが見つかりません" }, 400);
  if (!ALLOWED_TYPES.includes(file.type)) return c.json({ error: "png / jpeg / webp / gif のみ対応しています" }, 400);
  if (file.size > MAX_AVATAR_BYTES) return c.json({ error: "ファイルサイズは2MB以下にしてください" }, 400);

  const key = `hunters/${id}`;
  try {
    await c.env.AVATARS.put(key, await file.arrayBuffer(), { httpMetadata: { contentType: file.type } });
    await c.env.DB.prepare(`UPDATE hunters SET avatar_key = ? WHERE id = ?`).bind(key, id).run();
    return c.json({ received: true, avatarUrl: `/avatars/${key}` });
  } catch (err) {
    console.error("R2 upload error:", err);
    return c.json({ error: "アップロードに失敗しました" }, 500);
  }
});

// =====================================================
// 画像配信
// =====================================================

app.get("/avatars/:type/:id", async (c) => {
  const { type, id } = c.req.param();
  if (type !== "hunters" && type !== "programs") return c.json({ error: "not found" }, 404);

  const key = `${type}/${id}`;
  const object = await c.env.AVATARS.get(key);
  if (!object) return c.json({ error: "not found" }, 404);

  return new Response(object.body, {
    headers: {
      "Content-Type": object.httpMetadata?.contentType || "application/octet-stream",
      "Cache-Control": "public, max-age=3600",
    },
  });
});

// =====================================================
// レポート
// =====================================================

app.post("/reports", async (c) => {
  const body = await c.req.json().catch(() => null);

  if (!body || !body.programId || !body.title || !body.severity || !body.description || !body.contactEmail) {
    return c.json({ error: "必須項目が不足しています" }, 400);
  }
  const validSeverities = ["critical", "high", "medium", "low"];
  if (!validSeverities.includes(body.severity)) {
    return c.json({ error: "severityの値が不正です" }, 400);
  }

  const id = crypto.randomUUID();
  const createdAt = Date.now();

  try {
    await c.env.DB.prepare(
      `INSERT INTO reports (id, program_id, title, severity, description, poc, contact_email, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(id, body.programId, body.title, body.severity, body.description, body.poc || null, body.contactEmail, "triage待ち", createdAt)
      .run();

    return c.json({ received: true, id, createdAt });
  } catch (err) {
    console.error("D1 insert error:", err);
    return c.json({ error: "保存に失敗しました" }, 500);
  }
});

app.get("/programs/:id/reports", async (c) => {
  const programId = c.req.param("id");
  try {
    const { results } = await c.env.DB.prepare(`SELECT * FROM reports WHERE program_id = ? ORDER BY created_at DESC`)
      .bind(programId)
      .all();
    return c.json({ reports: results });
  } catch (err) {
    console.error("D1 select error:", err);
    return c.json({ error: "取得に失敗しました" }, 500);
  }
});

export default app;
