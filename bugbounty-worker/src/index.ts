import { Hono } from "hono";
import { cors } from "hono/cors";

type Bindings = {
  DB: D1Database;
};

const app = new Hono<{ Bindings: Bindings }>();

app.use("*", cors());

// ---------- パスワードのハッシュ化 (Web Crypto / PBKDF2) ----------
// 生のパスワードは絶対に保存しない。salt:hash の形式で password_hash に保存する。
async function hashPassword(password: string): Promise<string> {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const derivedBits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    256
  );
  const saltHex = Array.from(salt).map((b) => b.toString(16).padStart(2, "0")).join("");
  const hashHex = Array.from(new Uint8Array(derivedBits))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `${saltHex}:${hashHex}`;
}

function isValidPassword(password: unknown): password is string {
  return typeof password === "string" && password.length >= 8;
}

// ---------- ヘルスチェック ----------
app.get("/", (c) => {
  return c.json({ status: "ok", message: "BBP API is running" });
});

// ---------- プログラム登録 ----------
app.post("/programs", async (c) => {
  const body = await c.req.json().catch(() => null);

  if (
    !body ||
    !body.companyName ||
    !body.contactEmail ||
    !body.scope ||
    !body.description
  ) {
    return c.json({ error: "必須項目が不足しています" }, 400);
  }
  if (!isValidPassword(body.password)) {
    return c.json({ error: "パスワードは8文字以上で入力してください" }, 400);
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

    return c.json({ received: true, id, createdAt });
  } catch (err) {
    console.error("D1 insert error:", err);
    return c.json({ error: "保存に失敗しました" }, 500);
  }
});

// ---------- プログラム一覧取得 ----------
// password_hash は絶対に返さないよう、列を明示的に指定する
app.get("/programs", async (c) => {
  try {
    const { results } = await c.env.DB.prepare(
      `SELECT id, company_name, contact_email, scope, description, reward_min, reward_max, created_at
       FROM programs ORDER BY created_at DESC`
    ).all();

    return c.json({ programs: results });
  } catch (err) {
    console.error("D1 select error:", err);
    return c.json({ error: "取得に失敗しました" }, 500);
  }
});

// ---------- ハンター登録 ----------
app.post("/hunters", async (c) => {
  const body = await c.req.json().catch(() => null);

  if (!body || !body.handle || !body.email) {
    return c.json({ error: "ハンドルネームとメールアドレスは必須です" }, 400);
  }
  if (!isValidPassword(body.password)) {
    return c.json({ error: "パスワードは8文字以上で入力してください" }, 400);
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

    return c.json({ received: true, id, createdAt });
  } catch (err) {
    console.error("D1 insert error:", err);
    return c.json({ error: "保存に失敗しました" }, 500);
  }
});

// ---------- ハンター一覧取得 ----------
app.get("/hunters", async (c) => {
  try {
    const { results } = await c.env.DB.prepare(
      `SELECT id, handle, email, skills, portfolio, created_at
       FROM hunters ORDER BY created_at DESC`
    ).all();
    return c.json({ hunters: results });
  } catch (err) {
    console.error("D1 select error:", err);
    return c.json({ error: "取得に失敗しました" }, 500);
  }
});

// ---------- レポート提出 ----------
app.post("/reports", async (c) => {
  const body = await c.req.json().catch(() => null);

  if (
    !body ||
    !body.programId ||
    !body.title ||
    !body.severity ||
    !body.description ||
    !body.contactEmail
  ) {
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
      .bind(
        id,
        body.programId,
        body.title,
        body.severity,
        body.description,
        body.poc || null,
        body.contactEmail,
        "triage待ち",
        createdAt
      )
      .run();

    return c.json({ received: true, id, createdAt });
  } catch (err) {
    console.error("D1 insert error:", err);
    return c.json({ error: "保存に失敗しました" }, 500);
  }
});

// ---------- 特定プログラムのレポート一覧取得 ----------
app.get("/programs/:id/reports", async (c) => {
  const programId = c.req.param("id");
  try {
    const { results } = await c.env.DB.prepare(
      `SELECT * FROM reports WHERE program_id = ? ORDER BY created_at DESC`
    )
      .bind(programId)
      .all();
    return c.json({ reports: results });
  } catch (err) {
    console.error("D1 select error:", err);
    return c.json({ error: "取得に失敗しました" }, 500);
  }
});

export default app;
