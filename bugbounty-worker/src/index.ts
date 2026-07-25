import { Hono } from "hono";
import { cors } from "hono/cors";

type Bindings = {
  DB: D1Database;
  AVATARS: R2Bucket;
};

type SessionUser = { userType: "hunter" | "program"; userId: string };

const app = new Hono<{ Bindings: Bindings }>();

app.use("*", cors());

// =====================================================
// TOTP (RFC 6238) - Web Crypto のみで実装、外部ライブラリ不要
// =====================================================

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = "";
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

function base32Decode(str: string): Uint8Array {
  const clean = str.toUpperCase().replace(/[^A-Z2-7]/g, "");
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const char of clean) {
    const idx = BASE32_ALPHABET.indexOf(char);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(bytes);
}

function generateTotpSecret(): string {
  return base32Encode(crypto.getRandomValues(new Uint8Array(20)));
}

async function totpCodeAt(secretBase32: string, counterOffset: number): Promise<string> {
  const key = base32Decode(secretBase32);
  const counter = Math.floor(Date.now() / 1000 / 30) + counterOffset;
  const counterBuffer = new ArrayBuffer(8);
  new DataView(counterBuffer).setUint32(4, counter, false);

  const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, counterBuffer));

  const offset = signature[signature.length - 1] & 0xf;
  const binCode =
    ((signature[offset] & 0x7f) << 24) |
    ((signature[offset + 1] & 0xff) << 16) |
    ((signature[offset + 2] & 0xff) << 8) |
    (signature[offset + 3] & 0xff);

  return (binCode % 1000000).toString().padStart(6, "0");
}

// クロックのズレを吸収するため、前後30秒（計90秒の幅）まで許容する
async function verifyTotp(secretBase32: string, inputCode: string): Promise<boolean> {
  const clean = (inputCode || "").replace(/\s/g, "");
  for (const offset of [0, -1, 1]) {
    if ((await totpCodeAt(secretBase32, offset)) === clean) return true;
  }
  return false;
}

// =====================================================
// バックアップコード
// =====================================================

function generateBackupCodes(count = 8): string[] {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    const bytes = crypto.getRandomValues(new Uint8Array(5));
    const hex = Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 10);
    codes.push(`${hex.slice(0, 5)}-${hex.slice(5, 10)}`);
  }
  return codes;
}

async function hashCode(code: string): Promise<string> {
  const enc = new TextEncoder();
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(code.trim().toLowerCase()));
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// バックアップコードを検証し、使われたら配列から取り除く。戻り値は更新後の配列(使えなければnull)
async function consumeBackupCode(hashedCodes: string[], inputCode: string): Promise<string[] | null> {
  const inputHash = await hashCode(inputCode);
  const idx = hashedCodes.indexOf(inputHash);
  if (idx === -1) return null;
  const next = [...hashedCodes];
  next.splice(idx, 1);
  return next;
}

// =====================================================
// セッション
// =====================================================

const SESSION_DURATION_MS = 7 * 24 * 60 * 60 * 1000;

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

const MAX_AVATAR_BYTES = 2 * 1024 * 1024;
const ALLOWED_TYPES = ["image/png", "image/jpeg", "image/webp", "image/gif"];

app.get("/", (c) => c.json({ status: "ok", message: "BBP API is running" }));

// =====================================================
// 認証
// =====================================================

// メール + 6桁コード（または未使用のバックアップコード）でログイン
app.post("/auth/login", async (c) => {
  const body = await c.req.json().catch(() => null);
  if (!body || !body.userType || !body.email || !body.code) {
    return c.json({ error: "必須項目が不足しています" }, 400);
  }
  if (body.userType !== "hunter" && body.userType !== "program") {
    return c.json({ error: "userTypeが不正です" }, 400);
  }

  const table = body.userType === "hunter" ? "hunters" : "programs";
  const emailCol = body.userType === "hunter" ? "email" : "contact_email";

  const row: any = await c.env.DB.prepare(`SELECT * FROM ${table} WHERE ${emailCol} = ?`).bind(body.email).first();
  if (!row || !row.totp_confirmed) {
    return c.json({ error: "メールアドレスが未登録か、認証アプリの設定が完了していません" }, 401);
  }

  const isTotpValid = await verifyTotp(row.totp_secret, body.code);
  if (isTotpValid) {
    const token = await createSession(c.env.DB, body.userType, row.id);
    return c.json({ token, userType: body.userType, id: row.id, name: body.userType === "hunter" ? row.handle : row.company_name });
  }

  // 6桁コードで失敗したら、バックアップコードとしても試す
  const hashedCodes: string[] = row.backup_codes ? JSON.parse(row.backup_codes) : [];
  const remaining = await consumeBackupCode(hashedCodes, body.code);
  if (remaining) {
    await c.env.DB.prepare(`UPDATE ${table} SET backup_codes = ? WHERE id = ?`).bind(JSON.stringify(remaining), row.id).run();
    const token = await createSession(c.env.DB, body.userType, row.id);
    return c.json({
      token,
      userType: body.userType,
      id: row.id,
      name: body.userType === "hunter" ? row.handle : row.company_name,
      usedBackupCode: true,
      backupCodesRemaining: remaining.length,
    });
  }

  return c.json({ error: "コードが正しくありません" }, 401);
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

// 登録: パスワードは受け取らない。TOTPシークレットとバックアップコードを発行して返す
app.post("/programs", async (c) => {
  const body = await c.req.json().catch(() => null);

  if (!body || !body.companyName || !body.contactEmail || !body.scope || !body.description) {
    return c.json({ error: "必須項目が不足しています" }, 400);
  }

  const existing = await c.env.DB.prepare(`SELECT id FROM programs WHERE contact_email = ?`).bind(body.contactEmail).first();
  if (existing) {
    return c.json({ error: "このメールアドレスは既に登録されています" }, 409);
  }

  const id = crypto.randomUUID();
  const createdAt = Date.now();
  const secret = generateTotpSecret();
  const backupCodes = generateBackupCodes();
  const hashedBackupCodes = await Promise.all(backupCodes.map(hashCode));

  try {
    await c.env.DB.prepare(
      `INSERT INTO programs (id, company_name, contact_email, scope, description, reward_min, reward_max, totp_secret, totp_confirmed, backup_codes, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`
    )
      .bind(
        id,
        body.companyName,
        body.contactEmail,
        body.scope,
        body.description,
        Number(body.rewardMin) || 0,
        Number(body.rewardMax) || 0,
        secret,
        JSON.stringify(hashedBackupCodes),
        createdAt
      )
      .run();

    const otpauthUrl = `otpauth://totp/BBP:${encodeURIComponent(body.contactEmail)}?secret=${secret}&issuer=BBP&algorithm=SHA1&digits=6&period=30`;
    return c.json({ received: true, id, createdAt, secret, otpauthUrl, backupCodes });
  } catch (err: any) {
    if (String(err?.message || "").includes("UNIQUE")) {
      return c.json({ error: "このメールアドレスは既に登録されています" }, 409);
    }
    console.error("D1 insert error:", err);
    return c.json({ error: "保存に失敗しました" }, 500);
  }
});

// 登録直後、認証アプリに表示された6桁コードを入力して紐付けを確定させる
app.post("/programs/:id/confirm-totp", async (c) => {
  const id = c.req.param("id");
  const body = await c.req.json().catch(() => null);
  if (!body || !body.code) return c.json({ error: "コードを入力してください" }, 400);

  const row: any = await c.env.DB.prepare(`SELECT * FROM programs WHERE id = ?`).bind(id).first();
  if (!row) return c.json({ error: "not found" }, 404);
  if (row.totp_confirmed) return c.json({ error: "すでに確認済みです" }, 400);

  const ok = await verifyTotp(row.totp_secret, body.code);
  if (!ok) return c.json({ error: "コードが正しくありません" }, 401);

  await c.env.DB.prepare(`UPDATE programs SET totp_confirmed = 1 WHERE id = ?`).bind(id).run();
  const token = await createSession(c.env.DB, "program", id);
  return c.json({ confirmed: true, token });
});

app.get("/programs", async (c) => {
  try {
    const { results } = await c.env.DB.prepare(
      `SELECT id, company_name, contact_email, scope, description, reward_min, reward_max, avatar_key, created_at
       FROM programs WHERE totp_confirmed = 1 ORDER BY created_at DESC`
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

  const existing = await c.env.DB.prepare(`SELECT id FROM hunters WHERE email = ?`).bind(body.email).first();
  if (existing) {
    return c.json({ error: "このメールアドレスは既に登録されています" }, 409);
  }

  const id = crypto.randomUUID();
  const createdAt = Date.now();
  const secret = generateTotpSecret();
  const backupCodes = generateBackupCodes();
  const hashedBackupCodes = await Promise.all(backupCodes.map(hashCode));

  try {
    await c.env.DB.prepare(
      `INSERT INTO hunters (id, handle, email, skills, portfolio, totp_secret, totp_confirmed, backup_codes, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)`
    )
      .bind(id, body.handle, body.email, body.skills || null, body.portfolio || null, secret, JSON.stringify(hashedBackupCodes), createdAt)
      .run();

    const otpauthUrl = `otpauth://totp/BBP:${encodeURIComponent(body.email)}?secret=${secret}&issuer=BBP&algorithm=SHA1&digits=6&period=30`;
    return c.json({ received: true, id, createdAt, secret, otpauthUrl, backupCodes });
  } catch (err: any) {
    if (String(err?.message || "").includes("UNIQUE")) {
      return c.json({ error: "このメールアドレスは既に登録されています" }, 409);
    }
    console.error("D1 insert error:", err);
    return c.json({ error: "保存に失敗しました" }, 500);
  }
});

app.post("/hunters/:id/confirm-totp", async (c) => {
  const id = c.req.param("id");
  const body = await c.req.json().catch(() => null);
  if (!body || !body.code) return c.json({ error: "コードを入力してください" }, 400);

  const row: any = await c.env.DB.prepare(`SELECT * FROM hunters WHERE id = ?`).bind(id).first();
  if (!row) return c.json({ error: "not found" }, 404);
  if (row.totp_confirmed) return c.json({ error: "すでに確認済みです" }, 400);

  const ok = await verifyTotp(row.totp_secret, body.code);
  if (!ok) return c.json({ error: "コードが正しくありません" }, 401);

  await c.env.DB.prepare(`UPDATE hunters SET totp_confirmed = 1 WHERE id = ?`).bind(id).run();
  const token = await createSession(c.env.DB, "hunter", id);
  return c.json({ confirmed: true, token });
});

app.get("/hunters", async (c) => {
  try {
    const { results } = await c.env.DB.prepare(
      `SELECT id, handle, email, skills, portfolio, avatar_key, created_at
       FROM hunters WHERE totp_confirmed = 1 ORDER BY created_at DESC`
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
