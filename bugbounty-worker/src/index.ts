import { Hono } from "hono";
import { cors } from "hono/cors";

type Bindings = {
  DB: D1Database;
  AVATARS: R2Bucket;
  ADMIN_KEY: string;
  PLATFORM_PAYPAL_LINK: string;
  RESEND_API_KEY: string;
  BREVO_API_KEY: string;
  DIDIT_API_KEY: string;
  DIDIT_WEBHOOK_SECRET: string;
  DIDIT_WORKFLOW_ID_HUNTER: string;
};

type SessionUser = { userType: "hunter" | "program"; userId: string; actorType: "owner" | "member"; actorId: string | null };

const app = new Hono<{ Bindings: Bindings }>();

// 自分のサイトからのアクセスだけ許可する。新しいサイトを追加した時はここにも追記すること
const ALLOWED_ORIGINS = [
  "https://bughunter.uk",
  "https://www.bughunter.uk",
  "https://zizenntouroku.bughunter.uk", // 事前登録サイト
  "https://support.bughunter.uk", // サポートサイト
  "https://admin.bughunter.uk", // 管理画面（独自ドメインを設定していない場合は *.pages.dev のURLに変更）
];

app.use(
  "*",
  cors({
    origin: "*",
    allowHeaders: ["Content-Type", "Authorization", "X-Admin-Key"],
  })
);

// =====================================================
// レート制限（総当たり攻撃・スパム対策）
// =====================================================

// key: 制限をかける単位（例: "login:user@example.com"、"totp:programId"）
// 戻り値 true = 制限内（処理続行OK）、false = 制限超過（拒否すべき）
async function checkRateLimit(db: D1Database, key: string, maxAttempts: number, windowMs: number): Promise<boolean> {
  const now = Date.now();
  try {
    const row: any = await db.prepare(`SELECT count, window_start FROM rate_limits WHERE key = ?`).bind(key).first();

    if (!row || now - row.window_start > windowMs) {
      // ウィンドウが無い、または期限切れなら新しく数え直す
      await db
        .prepare(
          `INSERT INTO rate_limits (key, count, window_start) VALUES (?, 1, ?)
           ON CONFLICT(key) DO UPDATE SET count = 1, window_start = excluded.window_start`
        )
        .bind(key, now)
        .run();
      return true;
    }

    if (row.count >= maxAttempts) return false;

    await db.prepare(`UPDATE rate_limits SET count = count + 1 WHERE key = ?`).bind(key).run();
    return true;
  } catch (err) {
    // rate_limitsテーブルが無い等の場合は、機能を止めないためフェイルオープンにする
    console.error("rate limit check error:", err);
    return true;
  }
}

function clientIp(c: any): string {
  return c.req.header("cf-connecting-ip") || c.req.header("x-forwarded-for") || "unknown";
}

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
// メールアドレス確認（数字コード送信）
// =====================================================

const EMAIL_CODE_DURATION_MS = 15 * 60 * 1000; // 15分

function generateEmailCode(): string {
  const n = crypto.getRandomValues(new Uint32Array(1))[0] % 1000000;
  return String(n).padStart(6, "0");
}

// メールアドレスの形式チェック（ローカル部@ドメイン.TLD の最低限の形式のみ許可）
function isValidEmail(email: unknown): email is string {
  if (typeof email !== "string") return false;
  const trimmed = email.trim();
  if (trimmed.length === 0 || trimmed.length > 254) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed);
}

async function sendViaResend(apiKey: string, to: string, subject: string, text: string): Promise<boolean> {
  if (!apiKey) return false;
  try {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: "bughunter.uk <no-reply@bughunter.uk>",
        to: [to],
        subject,
        text,
      }),
    });
    if (!res.ok) console.error("Resend send failed:", res.status, await res.text().catch(() => ""));
    return res.ok;
  } catch (err) {
    console.error("Resend send error:", err);
    return false;
  }
}

async function sendViaBrevo(apiKey: string, to: string, subject: string, text: string): Promise<boolean> {
  if (!apiKey) return false;
  try {
    const res = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: {
        "api-key": apiKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        sender: { name: "bughunter.uk", email: "no-reply@bughunter.uk" },
        to: [{ email: to }],
        subject,
        textContent: text,
      }),
    });
    if (!res.ok) console.error("Brevo send failed:", res.status, await res.text().catch(() => ""));
    return res.ok;
  } catch (err) {
    console.error("Brevo send error:", err);
    return false;
  }
}

// Brevoでの送信を優先し、失敗した場合（上限到達・エラー等）は自動でResendにフォールバックする
async function sendEmail(env: { RESEND_API_KEY: string; BREVO_API_KEY: string }, to: string, subject: string, text: string): Promise<boolean> {
  if (!to) {
    console.error("recipient missing; skipping email send");
    return false;
  }

  const viaBrevo = await sendViaBrevo(env.BREVO_API_KEY, to, subject, text);
  if (viaBrevo) return true;

  console.error("Falling back to Resend for:", to);
  const viaResend = await sendViaResend(env.RESEND_API_KEY, to, subject, text);
  return viaResend;
}

async function sendVerificationEmail(env: { RESEND_API_KEY: string; BREVO_API_KEY: string }, to: string, code: string): Promise<boolean> {
  return sendEmail(
    env,
    to,
    `【bughunter.uk】確認コード: ${code}`,
    `以下の確認コードをサイトに入力してください。\n\n確認コード: ${code}\n\nこのコードの有効期限は15分です。心当たりがない場合はこのメールを無視してください。`
  );
}

// =====================================================
// Didit（本人確認 / 企業確認）
// =====================================================

// Diditのホスト型セッションを作成し、ユーザーを飛ばす先のURLを返す
async function createDiditSession(
  apiKey: string,
  workflowId: string,
  vendorData: string,
  callbackUrl: string
): Promise<{ sessionId: string; url: string } | null> {
  if (!apiKey || !workflowId) {
    console.error("Didit API key or workflow_id is not set");
    return null;
  }
  try {
    const res = await fetch("https://verification.didit.me/v3/session/", {
      method: "POST",
      headers: {
        "x-api-key": apiKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        workflow_id: workflowId,
        vendor_data: vendorData,
        callback: callbackUrl,
      }),
    });
    if (!res.ok) {
      console.error("Didit session create failed:", res.status, await res.text().catch(() => ""));
      return null;
    }
    const data: any = await res.json();
    const url = data.url || data.verification_url;
    const sessionId = data.session_id || data.id;
    if (!url || !sessionId) {
      console.error("Didit session response missing url/session_id:", JSON.stringify(data));
      return null;
    }
    return { sessionId, url };
  } catch (err) {
    console.error("Didit session create error:", err);
    return null;
  }
}

// HMAC-SHA256でX-Signature-V2を検証する（生のリクエストボディに対して計算）
async function verifyDiditSignature(secret: string, rawBody: string, signatureHeader: string | null): Promise<boolean> {
  if (!secret || !signatureHeader) return false;
  try {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const sigBuffer = await crypto.subtle.sign("HMAC", key, enc.encode(rawBody));
    const computedHex = Array.from(new Uint8Array(sigBuffer))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    // タイミング攻撃対策のため定数時間で比較
    const a = enc.encode(computedHex);
    const b = enc.encode(signatureHeader.trim().toLowerCase());
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  } catch (err) {
    console.error("Didit signature verify error:", err);
    return false;
  }
}

// Diditのステータス文字列を、このサービス内部の verification_status にマッピングする
function mapDiditStatus(status: string): "verified" | "rejected" | "pending" | "none" {
  const s = (status || "").toLowerCase();
  if (s === "approved") return "verified";
  if (s === "declined") return "rejected";
  if (s === "in review" || s === "in_review" || s === "not started" || s === "not_started" || s === "in progress" || s === "in_progress") return "pending";
  return "none"; // abandoned など
}

// =====================================================
// Didit Webhook（ステータス更新の受信）
// =====================================================

app.post("/webhooks/didit", async (c) => {
  const rawBody = await c.req.text();
  const signature = c.req.header("X-Signature") || c.req.header("x-signature");

  const valid = await verifyDiditSignature(c.env.DIDIT_WEBHOOK_SECRET, rawBody, signature);
  if (!valid) {
    console.error("Didit webhook signature verification failed");
    return c.json({ error: "invalid signature" }, 401);
  }

  let payload: any;
  try {
    payload = JSON.parse(rawBody);
  } catch (err) {
    return c.json({ error: "invalid payload" }, 400);
  }

  const sessionId: string | undefined = payload.session_id;
  const status: string | undefined = payload.status;
  if (!sessionId || !status) {
    return c.json({ error: "missing session_id or status" }, 400);
  }

  const mapped = mapDiditStatus(status);

  const session: any = await c.env.DB.prepare(`SELECT * FROM didit_sessions WHERE session_id = ?`).bind(sessionId).first();
  if (!session) {
    console.error("Didit webhook: unknown session_id", sessionId);
    return c.json({ received: true }); // 200で応答しないとDidit側がリトライし続けるため
  }

  const table = session.entity_type === "hunter" ? "hunters" : "programs";
  await c.env.DB.prepare(`UPDATE ${table} SET verification_status = ? WHERE id = ?`).bind(mapped, session.entity_id).run();

  // 結果をメールで通知
  try {
    if (session.entity_type === "hunter") {
      const hunter: any = await c.env.DB.prepare(`SELECT email, handle FROM hunters WHERE id = ?`).bind(session.entity_id).first();
      if (hunter && (mapped === "verified" || mapped === "rejected")) {
        await sendEmail(
          c.env,
          hunter.email,
          `【bughunter.uk】本人確認の結果: ${mapped === "verified" ? "承認されました" : "却下されました"}`,
          mapped === "verified"
            ? "本人確認が承認されました。非公開プログラムの閲覧・応募が可能になりました。"
            : "本人確認が却下されました。お手数ですが、マイページから再度お申し込みください。"
        );
      }
    } else {
      const program: any = await c.env.DB.prepare(`SELECT contact_email, company_name FROM programs WHERE id = ?`).bind(session.entity_id).first();
      if (program && (mapped === "verified" || mapped === "rejected")) {
        await sendEmail(
          c.env,
          program.contact_email,
          `【bughunter.uk】企業確認の結果: ${mapped === "verified" ? "承認されました" : "却下されました"}`,
          mapped === "verified"
            ? "企業確認が承認されました。非公開プログラムを作成できるようになりました。"
            : "企業確認が却下されました。お手数ですが、マイページから再度お申し込みください。"
        );
      }
    }
  } catch (err) {
    console.error("Didit webhook notification email error:", err);
  }

  return c.json({ received: true });
});

const SESSION_DURATION_MS = 7 * 24 * 60 * 60 * 1000;

async function createSession(
  db: D1Database,
  userType: "hunter" | "program",
  userId: string,
  actorType: "owner" | "member" = "owner",
  actorId: string | null = null
): Promise<string> {
  const token = crypto.randomUUID() + crypto.randomUUID().replace(/-/g, "");
  const createdAt = Date.now();
  const expiresAt = createdAt + SESSION_DURATION_MS;
  await db
    .prepare(
      `INSERT INTO sessions (token, user_type, user_id, actor_type, actor_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(token, userType, userId, actorType, actorId, createdAt, expiresAt)
    .run();
  return token;
}

async function getSessionUser(c: any): Promise<SessionUser | null> {
  const auth = c.req.header("Authorization");
  if (!auth || !auth.startsWith("Bearer ")) return null;
  const token = auth.slice(7);
  const row: any = await c.env.DB.prepare(`SELECT * FROM sessions WHERE token = ?`).bind(token).first();
  if (!row) return null;
  if (row.expires_at < Date.now()) return null;
  return {
    userType: row.user_type,
    userId: row.user_id,
    actorType: row.actor_type || "owner",
    actorId: row.actor_id || null,
  };
}

const MAX_AVATAR_BYTES = 2 * 1024 * 1024;
const ALLOWED_TYPES = ["image/png", "image/jpeg", "image/webp", "image/gif"];

app.get("/", (c) => c.json({ status: "ok", message: "BBP API is running" }));

// Diditからのwebhook受信（本人確認・企業確認の結果を受け取る）
app.post("/webhooks/didit", async (c) => {
  const rawBody = await c.req.text();
  const signature = c.req.header("X-Signature-V2") || c.req.header("x-signature-v2");

  const ok = await verifyDiditSignature(c.env.DIDIT_WEBHOOK_SECRET, rawBody, signature || null);
  if (!ok) {
    console.error("Didit webhook signature verification failed");
    return c.json({ error: "invalid signature" }, 401);
  }

  let payload: any;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    return c.json({ error: "invalid json" }, 400);
  }

  const sessionId: string | undefined = payload.session_id;
  const status: string | undefined = payload.status || payload.decision?.status;
  if (!sessionId || !status) {
    return c.json({ error: "missing session_id or status" }, 400);
  }

  const sessionRow: any = await c.env.DB.prepare(`SELECT * FROM didit_sessions WHERE session_id = ?`).bind(sessionId).first();
  if (!sessionRow) {
    console.error("Didit webhook: unknown session_id", sessionId);
    return c.json({ received: true }); // 200を返し、Diditの不要なリトライを防ぐ
  }

  const mappedStatus = mapDiditStatus(status);
  const table = sessionRow.entity_type === "hunter" ? "hunters" : "programs";

  await c.env.DB.prepare(`UPDATE ${table} SET verification_status = ? WHERE id = ?`)
    .bind(mappedStatus, sessionRow.entity_id)
    .run();

  // 承認・却下時は本人にメール通知
  if (mappedStatus === "verified" || mappedStatus === "rejected") {
    const emailCol = sessionRow.entity_type === "hunter" ? "email" : "contact_email";
    const row: any = await c.env.DB.prepare(`SELECT ${emailCol} as email FROM ${table} WHERE id = ?`)
      .bind(sessionRow.entity_id)
      .first();
    if (row?.email) {
      const label = sessionRow.entity_type === "hunter" ? "本人確認" : "企業確認";
      await sendEmail(
        c.env,
        row.email,
        `【bughunter.uk】${label}の結果: ${mappedStatus === "verified" ? "承認されました" : "承認されませんでした"}`,
        mappedStatus === "verified"
          ? `${label}が完了しました。サイトにログインしてご確認ください。`
          : `${label}が承認されませんでした。詳細はサイトにログインの上、サポートチケットからお問い合わせください。`
      );
    }
  }

  return c.json({ received: true });
});

// プラットフォーム設定（PayPal送金先・手数料率）をD1から読む。未設定・テーブル未作成ならフォールバック
async function getPlatformSettings(db: D1Database, envFallbackLink?: string) {
  try {
    const rows = await db.prepare(`SELECT key, value FROM platform_settings WHERE key IN ('paypal_link', 'fee_percent', 'admin_email')`).all();
    const map: Record<string, string> = {};
    for (const row of rows.results as any[]) map[row.key] = row.value;

    const paypalLink = map.paypal_link ?? envFallbackLink ?? null;
    const feePercent = map.fee_percent != null ? Number(map.fee_percent) : 10;
    const adminEmail = map.admin_email ?? null;
    return { paypalLink, feePercent, adminEmail };
  } catch (err) {
    console.error("platform_settings read error (table may not exist yet):", err);
    return { paypalLink: envFallbackLink ?? null, feePercent: 10, adminEmail: null };
  }
}

// 企業側に見せる、プラットフォームの送金先と手数料率（公開情報）
app.get("/platform-info", async (c) => {
  const settings = await getPlatformSettings(c.env.DB, c.env.PLATFORM_PAYPAL_LINK);
  return c.json(settings);
});

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

  // TOTPコードの総当たりを防ぐため、メールアドレス単位・IP単位の両方で制限する
  const emailOk = await checkRateLimit(c.env.DB, `login:email:${body.email.toLowerCase()}`, 10, 15 * 60 * 1000);
  const ipOk = await checkRateLimit(c.env.DB, `login:ip:${clientIp(c)}`, 30, 15 * 60 * 1000);
  if (!emailOk || !ipOk) {
    return c.json({ error: "試行回数が多すぎます。しばらく待ってから再度お試しください" }, 429);
  }

  // 企業ログインの場合、まずオーナー（programs）を探し、無ければチームメンバーを探す
  if (body.userType === "program") {
    const owner: any = await c.env.DB.prepare(`SELECT * FROM programs WHERE contact_email = ?`).bind(body.email).first();
    if (owner) {
      if (!owner.totp_confirmed || !owner.email_verified) {
        return c.json({ error: "メールアドレスが未登録か、認証アプリ・メール確認の設定が完了していません" }, 401);
      }
      return await tryLoginAndRespond(c, owner, body.code, "program", owner.id, "owner", null, owner.company_name);
    }

    const member: any = await c.env.DB.prepare(`SELECT * FROM program_members WHERE email = ? AND active = 1`).bind(body.email).first();
    if (member) {
      const program: any = await c.env.DB.prepare(`SELECT company_name FROM programs WHERE id = ?`).bind(member.program_id).first();
      return await tryLoginAndRespond(
        c,
        member,
        body.code,
        "program",
        member.program_id,
        "member",
        member.id,
        `${member.name}（${program?.company_name || "企業"}）`
      );
    }

    return c.json({ error: "メールアドレスが未登録か、認証アプリ・メール確認の設定が完了していません" }, 401);
  }

  // ハンターログイン
  const row: any = await c.env.DB.prepare(`SELECT * FROM hunters WHERE email = ?`).bind(body.email).first();
  if (!row || !row.totp_confirmed || !row.email_verified) {
    return c.json({ error: "メールアドレスが未登録か、認証アプリ・メール確認の設定が完了していません" }, 401);
  }
  return await tryLoginAndRespond(c, row, body.code, "hunter", row.id, "owner", null, row.handle);
});

// TOTP／バックアップコードを検証し、成功したらセッションを発行して返す共通処理
async function tryLoginAndRespond(
  c: any,
  row: any,
  code: string,
  userType: "hunter" | "program",
  userId: string,
  actorType: "owner" | "member",
  actorId: string | null,
  name: string
) {
  const isTotpValid = await verifyTotp(row.totp_secret, code);
  if (isTotpValid) {
    const token = await createSession(c.env.DB, userType, userId, actorType, actorId);
    return c.json({ token, userType, id: userId, name, isOwner: actorType === "owner" });
  }

  const hashedCodes: string[] = row.backup_codes ? JSON.parse(row.backup_codes) : [];
  const remaining = await consumeBackupCode(hashedCodes, code);
  if (remaining) {
    const table = actorType === "member" ? "program_members" : userType === "hunter" ? "hunters" : "programs";
    await c.env.DB.prepare(`UPDATE ${table} SET backup_codes = ? WHERE id = ?`).bind(JSON.stringify(remaining), row.id).run();
    const token = await createSession(c.env.DB, userType, userId, actorType, actorId);
    return c.json({
      token,
      userType,
      id: userId,
      name,
      isOwner: actorType === "owner",
      usedBackupCode: true,
      backupCodesRemaining: remaining.length,
    });
  }

  return c.json({ error: "コードが正しくありません" }, 401);
}

app.get("/auth/me", async (c) => {
  const user = await getSessionUser(c);
  if (!user) return c.json({ error: "unauthorized" }, 401);

  const table = user.userType === "hunter" ? "hunters" : "programs";
  const cols =
    user.userType === "hunter"
      ? "id, handle, email, skills, portfolio, paypal_link, points, verification_status, avatar_key, created_at"
      : "id, company_name, contact_email, scope, description, reward_min, reward_max, program_type, verification_status, is_private, avatar_key, created_at";

  const row: any = await c.env.DB.prepare(`SELECT ${cols} FROM ${table} WHERE id = ?`).bind(user.userId).first();
  if (!row) return c.json({ error: "not found" }, 404);

  let actingMemberName = null;
  if (user.userType === "program" && user.actorType === "member" && user.actorId) {
    const member: any = await c.env.DB.prepare(`SELECT name FROM program_members WHERE id = ?`).bind(user.actorId).first();
    actingMemberName = member?.name || null;
  }

  let canStartVerification = false;
  if (user.userType === "hunter" && row.verification_status !== "verified" && row.verification_status !== "pending") {
    const hasValidReport = await c.env.DB.prepare(`SELECT 1 FROM reports WHERE hunter_id = ? AND status = 'トリアージ' LIMIT 1`)
      .bind(user.userId)
      .first();
    canStartVerification = !!hasValidReport;
  }

  let level = null;
  if (user.userType === "hunter") {
    level = await calcHunterLevel(c.env.DB, user.userId);
  }

  return c.json({
    userType: user.userType,
    isOwner: user.actorType === "owner",
    actingMemberName,
    canStartVerification,
    level,
    ...row,
  });
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
  const regOk = await checkRateLimit(c.env.DB, `register:program:${clientIp(c)}`, 5, 60 * 60 * 1000);
  if (!regOk) return c.json({ error: "登録の試行回数が多すぎます。しばらく待ってから再度お試しください" }, 429);

  const body = await c.req.json().catch(() => null);

  if (!body || !body.companyName || !body.contactEmail || !body.scope || !body.description) {
    return c.json({ error: "必須項目が不足しています" }, 400);
  }
  if (!isValidEmail(body.contactEmail)) {
    return c.json({ error: "メールアドレスの形式が正しくありません" }, 400);
  }
  if (!body.agreedToTerms) {
    return c.json({ error: "利用規約とプライバシーポリシーへの同意が必要です" }, 400);
  }

  const existing = await c.env.DB.prepare(`SELECT id FROM programs WHERE contact_email = ?`).bind(body.contactEmail).first();
  if (existing) {
    return c.json({ error: "このメールアドレスは既に登録されています" }, 409);
  }

  const id = crypto.randomUUID();
  const createdAt = Date.now();
  const programType = body.programType === "vdp" ? "vdp" : "bbp";
  const secret = generateTotpSecret();
  const backupCodes = generateBackupCodes();
  const hashedBackupCodes = await Promise.all(backupCodes.map(hashCode));
  const emailCode = generateEmailCode();
  const emailCodeHash = await hashCode(emailCode);
  const emailCodeExpires = Date.now() + EMAIL_CODE_DURATION_MS;

  try {
    await c.env.DB.prepare(
      `INSERT INTO programs (id, company_name, contact_email, scope, description, reward_min, reward_max, program_type, terms_agreed_at, totp_secret, totp_confirmed, backup_codes, email_verified, email_code, email_code_expires, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, 0, ?, ?, ?)`
    )
      .bind(
        id,
        body.companyName,
        body.contactEmail,
        body.scope,
        body.description,
        Number(body.rewardMin) || 0,
        Number(body.rewardMax) || 0,
        programType,
        createdAt,
        secret,
        JSON.stringify(hashedBackupCodes),
        emailCodeHash,
        emailCodeExpires,
        createdAt
      )
      .run();

    const emailSent = await sendVerificationEmail(c.env, body.contactEmail, emailCode);
    const otpauthUrl = `otpauth://totp/BBP:${encodeURIComponent(body.contactEmail)}?secret=${secret}&issuer=BBP&algorithm=SHA1&digits=6&period=30`;
    return c.json({ received: true, id, createdAt, secret, otpauthUrl, backupCodes, emailSent });
  } catch (err: any) {
    if (String(err?.message || "").includes("UNIQUE")) {
      return c.json({ error: "このメールアドレスは既に登録されています" }, 409);
    }
    console.error("D1 insert error:", err);
    return c.json({ error: "保存に失敗しました" }, 500);
  }
});

// メール認証コードの確認
app.post("/programs/:id/confirm-email", async (c) => {
  const id = c.req.param("id");
  const body = await c.req.json().catch(() => null);
  if (!body || !body.code) return c.json({ error: "コードを入力してください" }, 400);

  const row: any = await c.env.DB.prepare(`SELECT * FROM programs WHERE id = ?`).bind(id).first();
  if (!row) return c.json({ error: "not found" }, 404);
  if (row.email_verified) return c.json({ error: "すでに確認済みです" }, 400);
  if (!row.email_code_expires || row.email_code_expires < Date.now()) {
    return c.json({ error: "コードの有効期限が切れています。再送信してください" }, 401);
  }

  const inputHash = await hashCode(body.code);
  if (inputHash !== row.email_code) {
    return c.json({ error: "コードが正しくありません" }, 401);
  }

  await c.env.DB.prepare(`UPDATE programs SET email_verified = 1, email_code = NULL, email_code_expires = NULL WHERE id = ?`)
    .bind(id)
    .run();
  return c.json({ confirmed: true });
});

// メール認証コードの再送信
app.post("/programs/:id/resend-email-code", async (c) => {
  const id = c.req.param("id");
  const row: any = await c.env.DB.prepare(`SELECT * FROM programs WHERE id = ?`).bind(id).first();
  if (!row) return c.json({ error: "not found" }, 404);
  if (row.email_verified) return c.json({ error: "すでに確認済みです" }, 400);

  const emailCode = generateEmailCode();
  const emailCodeHash = await hashCode(emailCode);
  const emailCodeExpires = Date.now() + EMAIL_CODE_DURATION_MS;

  await c.env.DB.prepare(`UPDATE programs SET email_code = ?, email_code_expires = ? WHERE id = ?`)
    .bind(emailCodeHash, emailCodeExpires, id)
    .run();

  const emailSent = await sendVerificationEmail(c.env, row.contact_email, emailCode);
  return c.json({ sent: emailSent });
});

// 登録直後、認証アプリに表示された6桁コードを入力して紐付けを確定させる
app.post("/programs/:id/confirm-totp", async (c) => {
  const id = c.req.param("id");
  const body = await c.req.json().catch(() => null);
  if (!body || !body.code) return c.json({ error: "コードを入力してください" }, 400);

  const ok1 = await checkRateLimit(c.env.DB, `totp-confirm:${id}`, 10, 15 * 60 * 1000);
  if (!ok1) return c.json({ error: "試行回数が多すぎます。しばらく待ってから再度お試しください" }, 429);

  const row: any = await c.env.DB.prepare(`SELECT * FROM programs WHERE id = ?`).bind(id).first();
  if (!row) return c.json({ error: "not found" }, 404);
  if (!row.email_verified) return c.json({ error: "先にメールアドレスの確認を完了してください" }, 400);
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
      `SELECT id, company_name, scope, description, reward_min, reward_max, program_type, verification_status, is_private, avatar_key, created_at
       FROM programs WHERE totp_confirmed = 1 AND email_verified = 1 ORDER BY created_at DESC`
    ).all();

    const rows = results as any[];
    const hasPrivate = rows.some((p) => p.is_private);
    let hunterVerified = false;
    if (hasPrivate) {
      const user = await getSessionUser(c);
      if (user && user.userType === "hunter") {
        const hunter: any = await c.env.DB.prepare(`SELECT verification_status FROM hunters WHERE id = ?`).bind(user.userId).first();
        hunterVerified = hunter?.verification_status === "verified";
      }
    }

    const visible = hunterVerified ? rows : rows.filter((p) => !p.is_private);
    return c.json({ programs: visible });
  } catch (err) {
    console.error("D1 select error:", err);
    return c.json({ error: "取得に失敗しました" }, 500);
  }
});

// プロフィール編集（本人のみ）
app.patch("/programs/:id", async (c) => {
  const id = c.req.param("id");
  const user = await getSessionUser(c);
  if (!user || user.userType !== "program" || user.userId !== id) {
    return c.json({ error: "権限がありません。ログインし直してください" }, 403);
  }

  const body = await c.req.json().catch(() => null);
  if (!body) return c.json({ error: "リクエストが不正です" }, 400);

  const companyName = body.companyName ?? null;
  const scope = body.scope ?? null;
  const description = body.description ?? null;
  const rewardMin = body.rewardMin != null ? Number(body.rewardMin) : null;
  const rewardMax = body.rewardMax != null ? Number(body.rewardMax) : null;

  if (companyName === "" || scope === "" || description === "") {
    return c.json({ error: "会社名・スコープ・説明は空にできません" }, 400);
  }
  if (rewardMin != null && rewardMax != null && rewardMin > rewardMax) {
    return c.json({ error: "報奨金の下限は上限以下にしてください" }, 400);
  }

  const isPrivate: number | null = body.isPrivate !== undefined ? (body.isPrivate ? 1 : 0) : null;

  try {
    await c.env.DB.prepare(
      `UPDATE programs SET
         company_name = COALESCE(?, company_name),
         scope = COALESCE(?, scope),
         description = COALESCE(?, description),
         reward_min = COALESCE(?, reward_min),
         reward_max = COALESCE(?, reward_max),
         is_private = COALESCE(?, is_private)
       WHERE id = ?`
    )
      .bind(companyName, scope, description, rewardMin, rewardMax, isPrivate, id)
      .run();

    return c.json({ updated: true });
  } catch (err) {
    console.error("D1 update error:", err);
    return c.json({ error: "更新に失敗しました" }, 500);
  }
});

// =====================================================
// チームメンバー（企業アカウントの子アカウント）
// =====================================================

// メンバー一覧（オーナーのみ）
app.get("/programs/:id/members", async (c) => {
  const id = c.req.param("id");
  const user = await getSessionUser(c);
  if (!user || user.userType !== "program" || user.userId !== id || user.actorType !== "owner") {
    return c.json({ error: "権限がありません" }, 403);
  }

  const { results } = await c.env.DB.prepare(
    `SELECT id, name, email, created_at FROM program_members WHERE program_id = ? AND active = 1 ORDER BY created_at DESC`
  )
    .bind(id)
    .all();
  return c.json({ members: results });
});

// メンバー追加（オーナーのみ）。TOTPシークレット・バックアップコードはこのレスポンスで一度だけ返す
app.post("/programs/:id/members", async (c) => {
  const id = c.req.param("id");
  const user = await getSessionUser(c);
  if (!user || user.userType !== "program" || user.userId !== id || user.actorType !== "owner") {
    return c.json({ error: "権限がありません" }, 403);
  }

  const body = await c.req.json().catch(() => null);
  if (!body || !body.name || !body.email) {
    return c.json({ error: "名前とメールアドレスは必須です" }, 400);
  }
  if (!isValidEmail(body.email)) {
    return c.json({ error: "メールアドレスの形式が正しくありません" }, 400);
  }

  const existingProgram = await c.env.DB.prepare(`SELECT id FROM programs WHERE contact_email = ?`).bind(body.email).first();
  const existingMember = await c.env.DB.prepare(`SELECT id FROM program_members WHERE email = ?`).bind(body.email).first();
  if (existingProgram || existingMember) {
    return c.json({ error: "このメールアドレスは既に使われています" }, 409);
  }

  const memberId = crypto.randomUUID();
  const createdAt = Date.now();
  const secret = generateTotpSecret();
  const backupCodes = generateBackupCodes();
  const hashedBackupCodes = await Promise.all(backupCodes.map(hashCode));

  try {
    await c.env.DB.prepare(
      `INSERT INTO program_members (id, program_id, name, email, totp_secret, backup_codes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(memberId, id, body.name, body.email, secret, JSON.stringify(hashedBackupCodes), createdAt)
      .run();

    await sendEmail(
      c.env,
      body.email,
      `【bughunter.uk】チームメンバーとして追加されました`,
      `bughunter.uk のチームメンバーとして追加されました。\n\nログイン用の認証アプリ設定（QRコード・バックアップコード）は、追加した担当者から直接お受け取りください。\n\nログイン画面で「企業」を選び、このメールアドレスとログイン先から共有される認証コードでログインできます。`
    );

    const otpauthUrl = `otpauth://totp/BBP:${encodeURIComponent(body.email)}?secret=${secret}&issuer=BBP&algorithm=SHA1&digits=6&period=30`;
    return c.json({ id: memberId, name: body.name, email: body.email, secret, otpauthUrl, backupCodes });
  } catch (err: any) {
    if (String(err?.message || "").includes("UNIQUE")) {
      return c.json({ error: "このメールアドレスは既に使われています" }, 409);
    }
    console.error("D1 insert error:", err);
    return c.json({ error: "追加に失敗しました" }, 500);
  }
});

// メンバーを非表示化（オーナーのみ）。データは残したまま、企業側の一覧・ログインだけを止める
app.delete("/programs/:id/members/:memberId", async (c) => {
  const id = c.req.param("id");
  const memberId = c.req.param("memberId");
  const user = await getSessionUser(c);
  if (!user || user.userType !== "program" || user.userId !== id || user.actorType !== "owner") {
    return c.json({ error: "権限がありません" }, 403);
  }

  try {
    await c.env.DB.prepare(`DELETE FROM sessions WHERE user_type = 'program' AND user_id = ? AND actor_type = 'member' AND actor_id = ?`)
      .bind(id, memberId)
      .run();
    await c.env.DB.prepare(`UPDATE program_members SET active = 0 WHERE id = ? AND program_id = ?`).bind(memberId, id).run();
    return c.json({ deleted: true });
  } catch (err) {
    console.error("D1 update error:", err);
    return c.json({ error: "処理に失敗しました" }, 500);
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
  if (!isValidEmail(body.email)) {
    return c.json({ error: "メールアドレスの形式が正しくありません" }, 400);
  }
  if (!body.agreedToTerms) {
    return c.json({ error: "利用規約とプライバシーポリシーへの同意が必要です" }, 400);
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
  const emailCode = generateEmailCode();
  const emailCodeHash = await hashCode(emailCode);
  const emailCodeExpires = Date.now() + EMAIL_CODE_DURATION_MS;

  try {
    await c.env.DB.prepare(
      `INSERT INTO hunters (id, handle, email, skills, portfolio, terms_agreed_at, totp_secret, totp_confirmed, backup_codes, email_verified, email_code, email_code_expires, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, 0, ?, ?, ?)`
    )
      .bind(
        id,
        body.handle,
        body.email,
        body.skills || null,
        body.portfolio || null,
        createdAt,
        secret,
        JSON.stringify(hashedBackupCodes),
        emailCodeHash,
        emailCodeExpires,
        createdAt
      )
      .run();

    const emailSent = await sendVerificationEmail(c.env, body.email, emailCode);
    const otpauthUrl = `otpauth://totp/BBP:${encodeURIComponent(body.email)}?secret=${secret}&issuer=BBP&algorithm=SHA1&digits=6&period=30`;
    return c.json({ received: true, id, createdAt, secret, otpauthUrl, backupCodes, emailSent });
  } catch (err: any) {
    if (String(err?.message || "").includes("UNIQUE")) {
      return c.json({ error: "このメールアドレスは既に登録されています" }, 409);
    }
    console.error("D1 insert error:", err);
    return c.json({ error: "保存に失敗しました" }, 500);
  }
});

// メール認証コードの確認
app.post("/hunters/:id/confirm-email", async (c) => {
  const id = c.req.param("id");
  const body = await c.req.json().catch(() => null);
  if (!body || !body.code) return c.json({ error: "コードを入力してください" }, 400);

  const row: any = await c.env.DB.prepare(`SELECT * FROM hunters WHERE id = ?`).bind(id).first();
  if (!row) return c.json({ error: "not found" }, 404);
  if (row.email_verified) return c.json({ error: "すでに確認済みです" }, 400);
  if (!row.email_code_expires || row.email_code_expires < Date.now()) {
    return c.json({ error: "コードの有効期限が切れています。再送信してください" }, 401);
  }

  const inputHash = await hashCode(body.code);
  if (inputHash !== row.email_code) {
    return c.json({ error: "コードが正しくありません" }, 401);
  }

  await c.env.DB.prepare(`UPDATE hunters SET email_verified = 1, email_code = NULL, email_code_expires = NULL WHERE id = ?`)
    .bind(id)
    .run();
  return c.json({ confirmed: true });
});

// メール認証コードの再送信
app.post("/hunters/:id/resend-email-code", async (c) => {
  const id = c.req.param("id");
  const row: any = await c.env.DB.prepare(`SELECT * FROM hunters WHERE id = ?`).bind(id).first();
  if (!row) return c.json({ error: "not found" }, 404);
  if (row.email_verified) return c.json({ error: "すでに確認済みです" }, 400);

  const emailCode = generateEmailCode();
  const emailCodeHash = await hashCode(emailCode);
  const emailCodeExpires = Date.now() + EMAIL_CODE_DURATION_MS;

  await c.env.DB.prepare(`UPDATE hunters SET email_code = ?, email_code_expires = ? WHERE id = ?`)
    .bind(emailCodeHash, emailCodeExpires, id)
    .run();

  const emailSent = await sendVerificationEmail(c.env, row.email, emailCode);
  return c.json({ sent: emailSent });
});

app.post("/hunters/:id/confirm-totp", async (c) => {
  const id = c.req.param("id");
  const body = await c.req.json().catch(() => null);
  if (!body || !body.code) return c.json({ error: "コードを入力してください" }, 400);

  const rateOk = await checkRateLimit(c.env.DB, `totp-confirm:${id}`, 10, 15 * 60 * 1000);
  if (!rateOk) return c.json({ error: "試行回数が多すぎます。しばらく待ってから再度お試しください" }, 429);

  const row: any = await c.env.DB.prepare(`SELECT * FROM hunters WHERE id = ?`).bind(id).first();
  if (!row) return c.json({ error: "not found" }, 404);
  if (!row.email_verified) return c.json({ error: "先にメールアドレスの確認を完了してください" }, 400);
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
      `SELECT id, handle, skills, portfolio, points, avatar_key, created_at
       FROM hunters WHERE totp_confirmed = 1 AND email_verified = 1 ORDER BY created_at DESC`
    ).all();

    const hunters = await Promise.all(
      (results as any[]).map(async (h) => {
        const level = await calcHunterLevel(c.env.DB, h.id);
        return { ...h, level };
      })
    );

    return c.json({ hunters });
  } catch (err) {
    console.error("D1 select error:", err);
    return c.json({ error: "取得に失敗しました" }, 500);
  }
});

// プロフィール編集（本人のみ）
app.patch("/hunters/:id", async (c) => {
  const id = c.req.param("id");
  const user = await getSessionUser(c);
  if (!user || user.userType !== "hunter" || user.userId !== id) {
    return c.json({ error: "権限がありません。ログインし直してください" }, 403);
  }

  const body = await c.req.json().catch(() => null);
  if (!body) return c.json({ error: "リクエストが不正です" }, 400);

  const handle = body.handle ?? null;
  const skills = body.skills ?? null;
  const portfolio = body.portfolio ?? null;
  const paypalLink = body.paypalLink ?? null;

  if (handle === "") {
    return c.json({ error: "ハンドルネームは空にできません" }, 400);
  }

  try {
    await c.env.DB.prepare(
      `UPDATE hunters SET
         handle = COALESCE(?, handle),
         skills = COALESCE(?, skills),
         portfolio = COALESCE(?, portfolio),
         paypal_link = COALESCE(?, paypal_link)
       WHERE id = ?`
    )
      .bind(handle, skills, portfolio, paypalLink, id)
      .run();

    return c.json({ updated: true });
  } catch (err) {
    console.error("D1 update error:", err);
    return c.json({ error: "更新に失敗しました" }, 500);
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

// レポート提出（ハンターとしてログイン必須。誰が送ったかをhunter_idに記録する）
app.post("/reports", async (c) => {
  const user = await getSessionUser(c);
  if (!user || user.userType !== "hunter") {
    return c.json({ error: "レポートの提出にはハンターとしてログインが必要です" }, 401);
  }

  const reportsOk = await checkRateLimit(c.env.DB, `reports:${user.userId}`, 20, 60 * 60 * 1000);
  if (!reportsOk) return c.json({ error: "レポートの提出回数が上限に達しました。しばらくしてから再度お試しください" }, 429);

  const body = await c.req.json().catch(() => null);

  if (!body || !body.programId || !body.title || !body.severity || !body.description || !body.contactEmail) {
    return c.json({ error: "必須項目が不足しています" }, 400);
  }
  const validSeverities = ["critical", "high", "medium", "low"];
  if (!validSeverities.includes(body.severity)) {
    return c.json({ error: "severityの値が不正です" }, 400);
  }

  const targetProgram: any = await c.env.DB.prepare(`SELECT company_name, contact_email, is_private FROM programs WHERE id = ?`)
    .bind(body.programId)
    .first();
  if (!targetProgram) return c.json({ error: "プログラムが見つかりません" }, 404);

  if (targetProgram.is_private) {
    const hunter: any = await c.env.DB.prepare(`SELECT verification_status FROM hunters WHERE id = ?`).bind(user.userId).first();
    if (hunter?.verification_status !== "verified") {
      return c.json({ error: "このプログラムは非公開です。本人確認（KYC）を完了したハンターのみレポートを提出できます" }, 403);
    }
  }

  const id = crypto.randomUUID();
  const createdAt = Date.now();

  try {
    await c.env.DB.prepare(
      `INSERT INTO reports (id, program_id, hunter_id, title, severity, description, poc, contact_email, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(id, body.programId, user.userId, body.title, body.severity, body.description, body.poc || null, body.contactEmail, "triage待ち", createdAt)
      .run();

    if (targetProgram) {
      await sendEmail(
        c.env,
        targetProgram.contact_email,
        `【bughunter.uk】新しいレポートが届きました: ${body.title}`,
        `${targetProgram.company_name} 宛に新しい脆弱性レポートが提出されました。\n\nタイトル: ${body.title}\n重大度: ${body.severity}\n\nサイトにログインして内容を確認してください。`
      );
    }

    return c.json({ received: true, id, createdAt });
  } catch (err) {
    console.error("D1 insert error:", err);
    return c.json({ error: "保存に失敗しました" }, 500);
  }
});

// プログラム宛のレポート一覧（そのプログラムの企業本人のみ閲覧可）
app.get("/programs/:id/reports", async (c) => {
  const programId = c.req.param("id");
  const user = await getSessionUser(c);
  if (!user || user.userType !== "program" || user.userId !== programId) {
    return c.json({ error: "権限がありません。ログインし直してください" }, 403);
  }
  const includeHidden = c.req.query("includeHidden") === "1";
  try {
    const { results } = await c.env.DB.prepare(
      includeHidden
        ? `SELECT * FROM reports WHERE program_id = ? ORDER BY created_at DESC`
        : `SELECT * FROM reports WHERE program_id = ? AND hidden_by_company = 0 ORDER BY created_at DESC`
    )
      .bind(programId)
      .all();
    return c.json({ reports: results });
  } catch (err) {
    console.error("D1 select error:", err);
    return c.json({ error: "取得に失敗しました" }, 500);
  }
});

// 自分（ハンター本人）が提出したレポート一覧
app.get("/hunters/:id/reports", async (c) => {
  const id = c.req.param("id");
  const user = await getSessionUser(c);
  if (!user || user.userType !== "hunter" || user.userId !== id) {
    return c.json({ error: "権限がありません" }, 403);
  }

  try {
    const { results } = await c.env.DB.prepare(
      `SELECT r.*, p.company_name AS program_company_name
       FROM reports r
       JOIN programs p ON p.id = r.program_id
       WHERE r.hunter_id = ?
       ORDER BY r.created_at DESC`
    )
      .bind(id)
      .all();
    return c.json({ reports: results });
  } catch (err) {
    console.error("D1 select error:", err);
    return c.json({ error: "取得に失敗しました" }, 500);
  }
});

// 本人確認（Didit）を開始する。解決済みレポートが1件以上ないと申請できない
app.post("/hunters/:id/start-verification", async (c) => {
  const id = c.req.param("id");
  const user = await getSessionUser(c);
  if (!user || user.userType !== "hunter" || user.userId !== id) {
    return c.json({ error: "権限がありません" }, 403);
  }

  const hasValidReport = await c.env.DB.prepare(
    `SELECT 1 FROM reports WHERE hunter_id = ? AND status = 'トリアージ' LIMIT 1`
  )
    .bind(id)
    .first();
  if (!hasValidReport) {
    return c.json({ error: "本人確認には「トリアージ」ステータスのレポートが1件以上必要です" }, 403);
  }

  const hunter: any = await c.env.DB.prepare(`SELECT verification_status FROM hunters WHERE id = ?`).bind(id).first();
  if (hunter?.verification_status === "verified") {
    return c.json({ error: "すでに本人確認済みです" }, 400);
  }
  if (hunter?.verification_status === "pending") {
    return c.json({ error: "本人確認を審査中です。しばらくお待ちください" }, 400);
  }

  const session = await createDiditSession(
    c.env.DIDIT_API_KEY,
    c.env.DIDIT_WORKFLOW_ID_HUNTER,
    `hunter:${id}`,
    "https://bughunter.uk/?tab=myprofile"
  );
  if (!session) {
    return c.json({ error: "本人確認セッションの作成に失敗しました。時間をおいて再度お試しください" }, 500);
  }

  await c.env.DB.prepare(
    `INSERT INTO didit_sessions (session_id, entity_type, entity_id, created_at) VALUES (?, 'hunter', ?, ?)`
  )
    .bind(session.sessionId, id, Date.now())
    .run();
  await c.env.DB.prepare(`UPDATE hunters SET verification_status = 'pending' WHERE id = ?`).bind(id).run();

  return c.json({ url: session.url });
});



const PAYOUT_REQUEST_THRESHOLD = 5000;

async function getHunterPendingTotal(db: D1Database, hunterId: string, feePercent: number) {
  const { results } = await db
    .prepare(`SELECT reward_amount FROM reports WHERE hunter_id = ? AND reward_amount IS NOT NULL AND reward_paid = 0`)
    .bind(hunterId)
    .all();
  const feeRate = feePercent / 100;
  const totalGross = (results as any[]).reduce((sum, r) => sum + (Number(r.reward_amount) || 0), 0);
  const totalNet = Math.round(totalGross * (1 - feeRate));
  return { totalGross, totalNet, count: results.length };
}

// 未払い合計金額の確認（本人のみ）
app.get("/hunters/:id/pending-total", async (c) => {
  const id = c.req.param("id");
  const user = await getSessionUser(c);
  if (!user || user.userType !== "hunter" || user.userId !== id) {
    return c.json({ error: "権限がありません" }, 403);
  }

  const settings = await getPlatformSettings(c.env.DB, c.env.PLATFORM_PAYPAL_LINK);
  const { totalGross, totalNet, count } = await getHunterPendingTotal(c.env.DB, id, settings.feePercent);

  const hunter: any = await c.env.DB.prepare(`SELECT payout_requested_at FROM hunters WHERE id = ?`).bind(id).first();
  const alreadyRequested = !!hunter?.payout_requested_at;

  return c.json({
    totalGross,
    totalNet,
    count,
    canRequest: totalNet >= PAYOUT_REQUEST_THRESHOLD && !alreadyRequested,
    threshold: PAYOUT_REQUEST_THRESHOLD,
    alreadyRequested,
    requestedAt: hunter?.payout_requested_at || null,
  });
});

// 支払いの申請（本人のみ、合計が閾値以上・未申請の場合のみ。運営者へメール通知）
app.post("/hunters/:id/request-payout", async (c) => {
  const id = c.req.param("id");
  const user = await getSessionUser(c);
  if (!user || user.userType !== "hunter" || user.userId !== id) {
    return c.json({ error: "権限がありません" }, 403);
  }

  const hunterRow: any = await c.env.DB.prepare(`SELECT handle, paypal_link, payout_requested_at FROM hunters WHERE id = ?`)
    .bind(id)
    .first();
  if (hunterRow?.payout_requested_at) {
    return c.json({ error: "すでに支払いを申請済みです" }, 400);
  }

  const settings = await getPlatformSettings(c.env.DB, c.env.PLATFORM_PAYPAL_LINK);
  const { totalNet } = await getHunterPendingTotal(c.env.DB, id, settings.feePercent);

  if (totalNet < PAYOUT_REQUEST_THRESHOLD) {
    return c.json({ error: `未払い合計が¥${PAYOUT_REQUEST_THRESHOLD.toLocaleString()}未満のため申請できません` }, 400);
  }

  await c.env.DB.prepare(`UPDATE hunters SET payout_requested_at = ? WHERE id = ?`).bind(Date.now(), id).run();

  if (settings.adminEmail) {
    await sendEmail(
      c.env,
      settings.adminEmail,
      `【bughunter.uk】支払い申請: ${hunterRow?.handle || id}`,
      `ハンター「${hunterRow?.handle || id}」から支払い申請がありました。\n\n未払い合計（手数料差引後）: ¥${totalNet.toLocaleString()}\nPayPal受け取り先: ${hunterRow?.paypal_link || "未登録"}\n\n管理画面の「支払い待ち」から詳細を確認し、送金後は「支払い済みにする」を押してください。`
    );
  } else {
    console.error("adminEmail not set; payout request email not sent");
  }

  return c.json({ requested: true, totalNet });
});


// 権限チェック：そのレポートの当事者（提出したハンター or 宛先の企業）だけがアクセスできる
async function getAuthorizedReport(c: any, reportId: string) {
  const report: any = await c.env.DB.prepare(`SELECT * FROM reports WHERE id = ?`).bind(reportId).first();
  if (!report) return { report: null, user: null };
  const user = await getSessionUser(c);
  const ok =
    !!user &&
    ((user.userType === "hunter" && report.hunter_id === user.userId) ||
      (user.userType === "program" && report.program_id === user.userId));
  return { report, user: ok ? user : null };
}

// レポート詳細
app.get("/reports/:id", async (c) => {
  const id = c.req.param("id");
  const { report, user } = await getAuthorizedReport(c, id);
  if (!report) return c.json({ error: "not found" }, 404);
  if (!user) return c.json({ error: "権限がありません" }, 403);

  const program = await c.env.DB.prepare(`SELECT id, company_name, program_type FROM programs WHERE id = ?`).bind(report.program_id).first();
  // 支払いはプラットフォーム経由になったため、企業にハンターのPayPal先は返さない
  const hunter = report.hunter_id
    ? await c.env.DB.prepare(`SELECT id, handle FROM hunters WHERE id = ?`).bind(report.hunter_id).first()
    : null;

  return c.json({ report, program, hunter });
});

// やり取り（コメント）一覧
app.get("/reports/:id/comments", async (c) => {
  const id = c.req.param("id");
  const { report, user } = await getAuthorizedReport(c, id);
  if (!report) return c.json({ error: "not found" }, 404);
  if (!user) return c.json({ error: "権限がありません" }, 403);

  try {
    const { results } = await c.env.DB.prepare(
      `SELECT * FROM report_comments WHERE report_id = ? ORDER BY created_at ASC`
    )
      .bind(id)
      .all();
    return c.json({ comments: results });
  } catch (err) {
    console.error("D1 select error:", err);
    return c.json({ error: "取得に失敗しました" }, 500);
  }
});

// やり取り（コメント）を書き込む
app.post("/reports/:id/comments", async (c) => {
  const id = c.req.param("id");
  const { report, user } = await getAuthorizedReport(c, id);
  if (!report) return c.json({ error: "not found" }, 404);
  if (!user) return c.json({ error: "権限がありません" }, 403);

  const commentsOk = await checkRateLimit(c.env.DB, `comments:${user.userType}:${user.userId}`, 60, 60 * 60 * 1000);
  if (!commentsOk) return c.json({ error: "投稿回数が上限に達しました。しばらくしてから再度お試しください" }, 429);

  const body = await c.req.json().catch(() => null);
  if (!body || !body.message || !String(body.message).trim()) {
    return c.json({ error: "メッセージを入力してください" }, 400);
  }

  const commentId = crypto.randomUUID();
  const createdAt = Date.now();

  try {
    await c.env.DB.prepare(
      `INSERT INTO report_comments (id, report_id, author_type, author_id, message, created_at) VALUES (?, ?, ?, ?, ?, ?)`
    )
      .bind(commentId, id, user.userType, user.userId, String(body.message).trim(), createdAt)
      .run();

    // 返信を書いた側と反対側の相手にメール通知
    if (user.userType === "hunter") {
      const program: any = await c.env.DB.prepare(`SELECT company_name, contact_email FROM programs WHERE id = ?`)
        .bind(report.program_id)
        .first();
      if (program) {
        await sendEmail(
          c.env,
          program.contact_email,
          `【bughunter.uk】レポートに返信がありました: ${report.title}`,
          `ハンターから返信がありました。\n\nレポート: ${report.title}\n\nサイトにログインして内容を確認してください。`
        );
      }
    } else if (report.hunter_id) {
      const hunter: any = await c.env.DB.prepare(`SELECT handle, email FROM hunters WHERE id = ?`)
        .bind(report.hunter_id)
        .first();
      if (hunter) {
        await sendEmail(
          c.env,
          hunter.email,
          `【bughunter.uk】レポートに返信がありました: ${report.title}`,
          `企業から返信がありました。\n\nレポート: ${report.title}\n\nサイトにログインして内容を確認してください。`
        );
      }
    }

    return c.json({ received: true, id: commentId, createdAt });
  } catch (err) {
    console.error("D1 insert error:", err);
    return c.json({ error: "送信に失敗しました" }, 500);
  }
});

const VALID_STATUSES = ["トリアージ", "返信待ち", "info", "解決済み", "スパム", "N/A", "重複", "閉鎖"];

// =====================================================
// ハンターレベル
// =====================================================

// -5〜+5 の11段階。0が初期値
const LEVEL_NAMES: Record<number, string> = {
  "-5": "Reckless",
  "-4": "Shady",
  "-3": "Suspect",
  "-2": "Rookie",
  "-1": "Novice",
   "0": "Unranked",
   "1": "Scout",
   "2": "Hunter",
   "3": "Veteran",
   "4": "Expert",
   "5": "Elite",
};

// 有効レポート（トリアージ or 解決済み）2件ごとに+1、N/A 2件ごとに-1、-5〜+5でクランプ
async function calcHunterLevel(db: D1Database, hunterId: string): Promise<{ score: number; name: string; validCount: number; naCount: number }> {
  const valid: any = await db
    .prepare(`SELECT COUNT(*) AS c FROM reports WHERE hunter_id = ? AND status IN ('トリアージ', '解決済み')`)
    .bind(hunterId)
    .first();
  const na: any = await db
    .prepare(`SELECT COUNT(*) AS c FROM reports WHERE hunter_id = ? AND status = 'N/A'`)
    .bind(hunterId)
    .first();

  const validCount = Number(valid?.c || 0);
  const naCount = Number(na?.c || 0);
  const raw = Math.floor(validCount / 2) - Math.floor(naCount / 2);
  const score = Math.max(-5, Math.min(5, raw));

  return { score, name: LEVEL_NAMES[String(score)], validCount, naCount };
}

// ステータスごとのポイント（該当しないステータスは0）
function statusPoints(status: string, programType: string): number {
  if (status === "解決済み") return programType === "vdp" ? 20 : 10;
  if (status === "N/A") return -10;
  return 0;
}

// ステータス変更・報奨金の付与・支払い状況の更新（宛先企業のみ）
app.patch("/reports/:id", async (c) => {
  const id = c.req.param("id");
  const { report, user } = await getAuthorizedReport(c, id);
  if (!report) return c.json({ error: "not found" }, 404);
  if (!user || user.userType !== "program") {
    return c.json({ error: "権限がありません。企業アカウントでログインしてください" }, 403);
  }

  const body = await c.req.json().catch(() => null);
  if (!body) return c.json({ error: "リクエストが不正です" }, 400);

  if (body.status !== undefined && !VALID_STATUSES.includes(body.status)) {
    return c.json({ error: "ステータスの値が不正です" }, 400);
  }
  if (body.rewardAmount !== undefined && body.rewardAmount !== null && Number(body.rewardAmount) < 0) {
    return c.json({ error: "報奨金額は0以上にしてください" }, 400);
  }

  const programRow: any = await c.env.DB.prepare(`SELECT program_type FROM programs WHERE id = ?`)
    .bind(report.program_id)
    .first();

  if (body.rewardAmount !== undefined && body.rewardAmount !== null) {
    if (programRow?.program_type === "vdp") {
      return c.json({ error: "VDPプログラムでは報奨金を設定できません" }, 400);
    }
  }

  const fields: string[] = [];
  const values: any[] = [];

  if (body.status !== undefined) {
    fields.push("status = ?");
    values.push(body.status);
  }
  if (body.rewardAmount !== undefined) {
    fields.push("reward_amount = ?");
    values.push(body.rewardAmount === null ? null : Number(body.rewardAmount));
  }
  if (body.hiddenByCompany !== undefined) {
    fields.push("hidden_by_company = ?");
    values.push(body.hiddenByCompany ? 1 : 0);
  }
  // reward_paid / payment_note は運営者(管理画面)側だけが更新できる。企業側からは変更不可。

  if (fields.length === 0) {
    return c.json({ error: "更新項目がありません" }, 400);
  }

  try {
    await c.env.DB.prepare(`UPDATE reports SET ${fields.join(", ")} WHERE id = ?`)
      .bind(...values, id)
      .run();

    if (body.status !== undefined && body.status !== report.status && report.hunter_id) {
      const programType = programRow?.program_type || "bbp";
      const delta = statusPoints(body.status, programType) - statusPoints(report.status, programType);

      if (delta !== 0) {
        await c.env.DB.prepare(`UPDATE hunters SET points = points + ? WHERE id = ?`)
          .bind(delta, report.hunter_id)
          .run();
      }

      const hunter: any = await c.env.DB.prepare(`SELECT email FROM hunters WHERE id = ?`).bind(report.hunter_id).first();
      if (hunter) {
        await sendEmail(
          c.env,
          hunter.email,
          `【bughunter.uk】レポートのステータスが更新されました: ${report.title}`,
          `レポート「${report.title}」のステータスが「${body.status}」に更新されました。\n\nサイトにログインして詳細を確認してください。`
        );
      }
    }

    return c.json({ updated: true });
  } catch (err) {
    console.error("D1 update error:", err);
    return c.json({ error: "更新に失敗しました" }, 500);
  }
});

// レポート削除（宛先企業のみ）
app.delete("/reports/:id", async (c) => {
  const id = c.req.param("id");
  const { report, user } = await getAuthorizedReport(c, id);
  if (!report) return c.json({ error: "not found" }, 404);
  if (!user || user.userType !== "program") {
    return c.json({ error: "権限がありません。企業アカウントでログインしてください" }, 403);
  }

  try {
    await c.env.DB.prepare(`DELETE FROM report_comments WHERE report_id = ?`).bind(id).run();
    await c.env.DB.prepare(`DELETE FROM reports WHERE id = ?`).bind(id).run();
    return c.json({ deleted: true });
  } catch (err) {
    console.error("D1 delete error:", err);
    return c.json({ error: "削除に失敗しました" }, 500);
  }
});

// =====================================================
// 管理者用（別デプロイの管理画面から X-Admin-Key ヘッダーで呼ばれる）
// =====================================================

function requireAdmin(c: any): boolean {
  const key = c.req.header("X-Admin-Key");
  return !!key && !!c.env.ADMIN_KEY && key === c.env.ADMIN_KEY;
}

app.get("/admin/hunters", async (c) => {
  if (!requireAdmin(c)) return c.json({ error: "unauthorized" }, 401);
  const { results } = await c.env.DB.prepare(
    `SELECT id, handle, email, paypal_link, points, avatar_key, totp_confirmed, created_at FROM hunters ORDER BY created_at DESC`
  ).all();
  return c.json({ hunters: results });
});

app.get("/admin/programs", async (c) => {
  if (!requireAdmin(c)) return c.json({ error: "unauthorized" }, 401);
  const { results } = await c.env.DB.prepare(
    `SELECT id, company_name, contact_email, program_type, avatar_key, totp_confirmed, created_at FROM programs ORDER BY created_at DESC`
  ).all();
  return c.json({ programs: results });
});

app.delete("/admin/hunters/:id", async (c) => {
  if (!requireAdmin(c)) return c.json({ error: "unauthorized" }, 401);
  const id = c.req.param("id");
  try {
    await c.env.DB.prepare(`DELETE FROM report_comments WHERE author_type = 'hunter' AND author_id = ?`).bind(id).run();
    await c.env.DB.prepare(`DELETE FROM reports WHERE hunter_id = ?`).bind(id).run();
    await c.env.DB.prepare(`DELETE FROM sessions WHERE user_type = 'hunter' AND user_id = ?`).bind(id).run();
    await c.env.DB.prepare(`DELETE FROM hunters WHERE id = ?`).bind(id).run();
    return c.json({ deleted: true });
  } catch (err) {
    console.error("D1 admin delete error:", err);
    return c.json({ error: "削除に失敗しました" }, 500);
  }
});

app.delete("/admin/programs/:id", async (c) => {
  if (!requireAdmin(c)) return c.json({ error: "unauthorized" }, 401);
  const id = c.req.param("id");
  try {
    await c.env.DB.prepare(
      `DELETE FROM report_comments WHERE report_id IN (SELECT id FROM reports WHERE program_id = ?)`
    ).bind(id).run();
    await c.env.DB.prepare(`DELETE FROM reports WHERE program_id = ?`).bind(id).run();
    await c.env.DB.prepare(`DELETE FROM sessions WHERE user_type = 'program' AND user_id = ?`).bind(id).run();
    await c.env.DB.prepare(`DELETE FROM programs WHERE id = ?`).bind(id).run();
    return c.json({ deleted: true });
  } catch (err) {
    console.error("D1 admin delete error:", err);
    return c.json({ error: "削除に失敗しました" }, 500);
  }
});

// 報奨金が設定されているレポート一覧（送金先のPayPalリンク付き）
app.get("/admin/reports", async (c) => {
  if (!requireAdmin(c)) return c.json({ error: "unauthorized" }, 401);
  const { results } = await c.env.DB.prepare(
    `SELECT r.id, r.title, r.status, r.reward_amount, r.reward_paid, r.payment_note, r.created_at,
            p.company_name AS program_company_name,
            h.handle AS hunter_handle, h.paypal_link AS hunter_paypal_link
     FROM reports r
     JOIN programs p ON p.id = r.program_id
     LEFT JOIN hunters h ON h.id = r.hunter_id
     WHERE r.reward_amount IS NOT NULL
     ORDER BY r.reward_paid ASC, r.created_at DESC`
  ).all();
  return c.json({ reports: results });
});

// 支払い済みフラグ・メモの更新（運営者のみ）
app.patch("/admin/reports/:id", async (c) => {
  if (!requireAdmin(c)) return c.json({ error: "unauthorized" }, 401);
  const id = c.req.param("id");
  const body = await c.req.json().catch(() => null);
  if (!body) return c.json({ error: "リクエストが不正です" }, 400);

  const fields: string[] = [];
  const values: any[] = [];
  if (body.rewardPaid !== undefined) {
    fields.push("reward_paid = ?");
    values.push(body.rewardPaid ? 1 : 0);
  }
  if (body.paymentNote !== undefined) {
    fields.push("payment_note = ?");
    values.push(body.paymentNote);
  }
  if (fields.length === 0) return c.json({ error: "更新項目がありません" }, 400);

  try {
    await c.env.DB.prepare(`UPDATE reports SET ${fields.join(", ")} WHERE id = ?`)
      .bind(...values, id)
      .run();
    return c.json({ updated: true });
  } catch (err) {
    console.error("D1 admin update error:", err);
    return c.json({ error: "更新に失敗しました" }, 500);
  }
});

// 支払い待ちのレポート一覧（報奨金が設定済み・未払いのもの全件、企業横断）
app.get("/admin/reports/unpaid", async (c) => {
  if (!requireAdmin(c)) return c.json({ error: "unauthorized" }, 401);
  try {
    const settings = await getPlatformSettings(c.env.DB, c.env.PLATFORM_PAYPAL_LINK);
    const feeRate = settings.feePercent / 100;

    const { results } = await c.env.DB.prepare(
      `SELECT r.id, r.title, r.reward_amount, r.status, r.created_at,
              p.company_name AS program_company_name,
              h.id AS hunter_id, h.handle AS hunter_handle, h.paypal_link AS hunter_paypal_link, h.payout_requested_at AS hunter_payout_requested_at
       FROM reports r
       JOIN programs p ON p.id = r.program_id
       LEFT JOIN hunters h ON h.id = r.hunter_id
       WHERE r.reward_amount IS NOT NULL AND r.reward_paid = 0
       ORDER BY (h.payout_requested_at IS NULL) ASC, r.created_at ASC`
    ).all();

    const withFees = (results as any[]).map((r) => {
      const gross = Number(r.reward_amount) || 0;
      const fee = Math.round(gross * feeRate);
      return { ...r, gross_amount: gross, platform_fee: fee, net_amount: gross - fee };
    });

    return c.json({ reports: withFees, feeRate });
  } catch (err) {
    console.error("D1 select error:", err);
    return c.json({ error: "取得に失敗しました" }, 500);
  }
});

// 運営者がハンターへの送金を終えたら、支払い済みにする
app.patch("/admin/reports/:id/paid", async (c) => {
  if (!requireAdmin(c)) return c.json({ error: "unauthorized" }, 401);
  const id = c.req.param("id");
  const body = await c.req.json().catch(() => ({}));

  try {
    await c.env.DB.prepare(`UPDATE reports SET reward_paid = 1, payment_note = COALESCE(?, payment_note) WHERE id = ?`)
      .bind(body?.paymentNote ?? null, id)
      .run();

    const report: any = await c.env.DB.prepare(`SELECT title, hunter_id, reward_amount FROM reports WHERE id = ?`).bind(id).first();
    if (report?.hunter_id) {
      const remaining = await c.env.DB.prepare(
        `SELECT COUNT(*) AS c FROM reports WHERE hunter_id = ? AND reward_amount IS NOT NULL AND reward_paid = 0`
      )
        .bind(report.hunter_id)
        .first();
      if ((remaining as any)?.c === 0) {
        await c.env.DB.prepare(`UPDATE hunters SET payout_requested_at = NULL WHERE id = ?`).bind(report.hunter_id).run();
      }

      const hunter: any = await c.env.DB.prepare(`SELECT email FROM hunters WHERE id = ?`).bind(report.hunter_id).first();
      if (hunter) {
        await sendEmail(
          c.env,
          hunter.email,
          `【bughunter.uk】報奨金の支払いが完了しました: ${report.title}`,
          `レポート「${report.title}」の報奨金（¥${Number(report.reward_amount || 0).toLocaleString()}）の送金が完了しました。\n\nPayPalをご確認ください。`
        );
      }
    }

    return c.json({ updated: true });
  } catch (err) {
    console.error("D1 update error:", err);
    return c.json({ error: "更新に失敗しました" }, 500);
  }
});

// プラットフォーム設定の確認・変更（PayPal送金先・手数料率）
app.get("/admin/settings", async (c) => {
  if (!requireAdmin(c)) return c.json({ error: "unauthorized" }, 401);
  const settings = await getPlatformSettings(c.env.DB, c.env.PLATFORM_PAYPAL_LINK);
  return c.json(settings);
});

app.patch("/admin/settings", async (c) => {
  if (!requireAdmin(c)) return c.json({ error: "unauthorized" }, 401);
  const body = await c.req.json().catch(() => null);
  if (!body) return c.json({ error: "リクエストが不正です" }, 400);

  if (body.feePercent !== undefined) {
    const fp = Number(body.feePercent);
    if (isNaN(fp) || fp < 0 || fp > 100) return c.json({ error: "手数料率は0〜100の数値にしてください" }, 400);
  }

  try {
    if (body.paypalLink !== undefined) {
      await c.env.DB.prepare(
        `INSERT INTO platform_settings (key, value) VALUES ('paypal_link', ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value`
      ).bind(body.paypalLink).run();
    }
    if (body.feePercent !== undefined) {
      await c.env.DB.prepare(
        `INSERT INTO platform_settings (key, value) VALUES ('fee_percent', ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value`
      ).bind(String(body.feePercent)).run();
    }
    if (body.adminEmail !== undefined) {
      await c.env.DB.prepare(
        `INSERT INTO platform_settings (key, value) VALUES ('admin_email', ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value`
      ).bind(body.adminEmail).run();
    }
    return c.json({ updated: true });
  } catch (err) {
    console.error("D1 update error:", err);
    return c.json({ error: "更新に失敗しました" }, 500);
  }
});

// =====================================================
// 事前登録（公開前のランディングページ用）
// =====================================================

app.post("/pre-register", async (c) => {
  const body = await c.req.json().catch(() => null);
  const email = (body?.email || "").trim();
  const role = body?.role === "program" ? "program" : "hunter";

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return c.json({ error: "有効なメールアドレスを入力してください" }, 400);
  }

  try {
    await c.env.DB.prepare(`INSERT INTO pre_registrations (id, email, role, created_at) VALUES (?, ?, ?, ?)`)
      .bind(crypto.randomUUID(), email, role, Date.now())
      .run();
    return c.json({ received: true });
  } catch (err: any) {
    if (String(err?.message || "").includes("UNIQUE")) {
      return c.json({ received: true, alreadyRegistered: true });
    }
    console.error("D1 insert error:", err);
    return c.json({ error: "登録に失敗しました" }, 500);
  }
});

app.get("/admin/pre-registrations", async (c) => {
  if (!requireAdmin(c)) return c.json({ error: "unauthorized" }, 401);
  const { results } = await c.env.DB.prepare(
    `SELECT id, email, role, created_at FROM pre_registrations ORDER BY created_at DESC`
  ).all();
  return c.json({ registrations: results });
});

// お問い合わせフォーム（認証不要、運営者にメール通知）
app.post("/contact", async (c) => {
  const contactOk = await checkRateLimit(c.env.DB, `contact:${clientIp(c)}`, 5, 60 * 60 * 1000);
  if (!contactOk) return c.json({ error: "送信回数が上限に達しました。しばらくしてから再度お試しください" }, 429);

  const body = await c.req.json().catch(() => null);
  if (!body || !body.name || !body.email || !body.message) {
    return c.json({ error: "必須項目が不足しています" }, 400);
  }
  if (!isValidEmail(body.email)) {
    return c.json({ error: "メールアドレスの形式が正しくありません" }, 400);
  }
  if (String(body.message).length > 5000) {
    return c.json({ error: "本文が長すぎます" }, 400);
  }

  const settings = await getPlatformSettings(c.env.DB, c.env.PLATFORM_PAYPAL_LINK);
  if (!settings.adminEmail) {
    return c.json({ error: "現在お問い合わせを受け付けられません。時間をおいて再度お試しください" }, 500);
  }

  const sent = await sendEmail(
    c.env,
    settings.adminEmail,
    `【bughunter.uk】お問い合わせ: ${body.name}`,
    `名前: ${body.name}\nメールアドレス: ${body.email}\n\n${body.message}`
  );

  return c.json({ sent });
});

// =====================================================
// サポートチケット
// =====================================================

const TICKET_STATUSES = ["未対応", "対応中", "解決済み"];

// アカウントの表示名・メールアドレスを取得するヘルパー
async function getAccountIdentity(db: D1Database, user: SessionUser): Promise<{ name: string; email: string } | null> {
  if (user.userType === "hunter") {
    const row: any = await db.prepare(`SELECT handle, email FROM hunters WHERE id = ?`).bind(user.userId).first();
    return row ? { name: row.handle, email: row.email } : null;
  }
  const row: any = await db.prepare(`SELECT company_name, contact_email FROM programs WHERE id = ?`).bind(user.userId).first();
  return row ? { name: row.company_name, email: row.contact_email } : null;
}

// チケット作成（ログイン必須。名前・メールはアカウント情報から自動で使う）
app.post("/support/tickets", async (c) => {
  const user = await getSessionUser(c);
  if (!user) return c.json({ error: "ログインが必要です" }, 401);

  const ticketsOk = await checkRateLimit(c.env.DB, `tickets:${user.userType}:${user.userId}`, 10, 60 * 60 * 1000);
  if (!ticketsOk) return c.json({ error: "チケットの作成回数が上限に達しました。しばらくしてから再度お試しください" }, 429);

  const body = await c.req.json().catch(() => null);
  if (!body || !body.subject || !body.message) {
    return c.json({ error: "必須項目が不足しています" }, 400);
  }
  if (String(body.message).length > 5000) {
    return c.json({ error: "本文が長すぎます" }, 400);
  }

  const identity = await getAccountIdentity(c.env.DB, user);
  if (!identity) return c.json({ error: "アカウント情報が見つかりません" }, 404);

  const id = crypto.randomUUID();
  const createdAt = Date.now();

  try {
    await c.env.DB.prepare(
      `INSERT INTO support_tickets (id, name, email, user_type, user_id, subject, message, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(id, identity.name, identity.email, user.userType, user.userId, body.subject, body.message, "未対応", createdAt)
      .run();

    const settings = await getPlatformSettings(c.env.DB, c.env.PLATFORM_PAYPAL_LINK);
    if (settings.adminEmail) {
      await sendEmail(
        c.env,
        settings.adminEmail,
        `【bughunter.uk】新しいサポートチケット: ${body.subject}`,
        `${identity.name}（${identity.email} / ${user.userType === "hunter" ? "ハンター" : "企業"}）からチケットが届きました。\n\n件名: ${body.subject}\n\n${body.message}\n\n管理画面から返信してください。チケットID: ${id}`
      );
    }
    await sendEmail(
      c.env,
      identity.email,
      `【bughunter.uk】お問い合わせを受け付けました: ${body.subject}`,
      `お問い合わせありがとうございます。以下の内容で受け付けました。\n\n件名: ${body.subject}\n\n${body.message}\n\nサイトにログインし、マイチケットから対応状況を確認できます。`
    );

    return c.json({ received: true, id });
  } catch (err) {
    console.error("D1 insert error:", err);
    return c.json({ error: "送信に失敗しました" }, 500);
  }
});

// 自分のチケット一覧（ログイン必須、本人分のみ）
app.get("/support/my-tickets", async (c) => {
  const user = await getSessionUser(c);
  if (!user) return c.json({ error: "ログインが必要です" }, 401);

  const { results } = await c.env.DB.prepare(
    `SELECT * FROM support_tickets WHERE user_type = ? AND user_id = ? ORDER BY created_at DESC`
  )
    .bind(user.userType, user.userId)
    .all();

  return c.json({ tickets: results });
});

async function getAuthorizedTicket(c: any, ticketId: string) {
  const ticket: any = await c.env.DB.prepare(`SELECT * FROM support_tickets WHERE id = ?`).bind(ticketId).first();
  if (!ticket) return { ticket: null, user: null };
  const user = await getSessionUser(c);
  const ok = !!user && ticket.user_type === user.userType && ticket.user_id === user.userId;
  return { ticket, user: ok ? user : null };
}

// チケット詳細確認（本人のみ）
app.get("/support/tickets/:id", async (c) => {
  const id = c.req.param("id");
  const { ticket, user } = await getAuthorizedTicket(c, id);
  if (!ticket) return c.json({ error: "not found" }, 404);
  if (!user) return c.json({ error: "権限がありません" }, 403);

  const { results } = await c.env.DB.prepare(`SELECT * FROM support_replies WHERE ticket_id = ? ORDER BY created_at ASC`)
    .bind(id)
    .all();

  return c.json({ ticket, replies: results });
});

// 本人からの追記返信
app.post("/support/tickets/:id/replies", async (c) => {
  const id = c.req.param("id");
  const { ticket, user } = await getAuthorizedTicket(c, id);
  if (!ticket) return c.json({ error: "not found" }, 404);
  if (!user) return c.json({ error: "権限がありません" }, 403);

  const replyOk = await checkRateLimit(c.env.DB, `ticket-replies:${user.userType}:${user.userId}`, 30, 60 * 60 * 1000);
  if (!replyOk) return c.json({ error: "投稿回数が上限に達しました。しばらくしてから再度お試しください" }, 429);

  const body = await c.req.json().catch(() => null);
  if (!body || !body.message) {
    return c.json({ error: "メッセージを入力してください" }, 400);
  }

  const replyId = crypto.randomUUID();
  const createdAt = Date.now();
  await c.env.DB.prepare(
    `INSERT INTO support_replies (id, ticket_id, author_type, message, created_at) VALUES (?, ?, 'user', ?, ?)`
  )
    .bind(replyId, id, String(body.message).trim(), createdAt)
    .run();

  const settings = await getPlatformSettings(c.env.DB, c.env.PLATFORM_PAYPAL_LINK);
  if (settings.adminEmail) {
    await sendEmail(
      c.env,
      settings.adminEmail,
      `【bughunter.uk】チケットに追記がありました: ${ticket.subject}`,
      `${ticket.name} からチケットに追記がありました。\n\nチケットID: ${id}\n\n${body.message}`
    );
  }

  return c.json({ received: true, id: replyId, createdAt });
});

// ---------- 管理者用 ----------

app.get("/admin/support/tickets", async (c) => {
  if (!requireAdmin(c)) return c.json({ error: "unauthorized" }, 401);
  const { results } = await c.env.DB.prepare(`SELECT * FROM support_tickets ORDER BY created_at DESC`).all();
  return c.json({ tickets: results });
});

app.get("/admin/support/tickets/:id", async (c) => {
  if (!requireAdmin(c)) return c.json({ error: "unauthorized" }, 401);
  const id = c.req.param("id");
  const ticket = await c.env.DB.prepare(`SELECT * FROM support_tickets WHERE id = ?`).bind(id).first();
  if (!ticket) return c.json({ error: "not found" }, 404);
  const { results } = await c.env.DB.prepare(`SELECT * FROM support_replies WHERE ticket_id = ? ORDER BY created_at ASC`)
    .bind(id)
    .all();
  return c.json({ ticket, replies: results });
});

app.patch("/admin/support/tickets/:id", async (c) => {
  if (!requireAdmin(c)) return c.json({ error: "unauthorized" }, 401);
  const id = c.req.param("id");
  const body = await c.req.json().catch(() => null);
  if (!body || !body.status || !TICKET_STATUSES.includes(body.status)) {
    return c.json({ error: "ステータスの値が不正です" }, 400);
  }
  await c.env.DB.prepare(`UPDATE support_tickets SET status = ? WHERE id = ?`).bind(body.status, id).run();
  return c.json({ updated: true });
});

app.post("/admin/support/tickets/:id/replies", async (c) => {
  if (!requireAdmin(c)) return c.json({ error: "unauthorized" }, 401);
  const id = c.req.param("id");
  const body = await c.req.json().catch(() => null);
  if (!body || !body.message) return c.json({ error: "メッセージを入力してください" }, 400);

  const ticket: any = await c.env.DB.prepare(`SELECT * FROM support_tickets WHERE id = ?`).bind(id).first();
  if (!ticket) return c.json({ error: "not found" }, 404);

  const replyId = crypto.randomUUID();
  const createdAt = Date.now();
  await c.env.DB.prepare(
    `INSERT INTO support_replies (id, ticket_id, author_type, message, created_at) VALUES (?, ?, 'admin', ?, ?)`
  )
    .bind(replyId, id, String(body.message).trim(), createdAt)
    .run();

  // 返信したら自動的に「対応中」にする（すでに解決済みならそのまま）
  if (ticket.status === "未対応") {
    await c.env.DB.prepare(`UPDATE support_tickets SET status = '対応中' WHERE id = ?`).bind(id).run();
  }

  await sendEmail(
    c.env,
    ticket.email,
    `【bughunter.uk】お問い合わせに返信がありました: ${ticket.subject}`,
    `お問い合わせ「${ticket.subject}」に返信がありました。\n\n${body.message}\n\nチケットID: ${id}\nサイトのチケット確認ページから続きをご覧いただけます。`
  );

  return c.json({ received: true, id: replyId, createdAt });
});

export default app;
