import { Hono } from "hono";
import { cors } from "hono/cors";

type Bindings = {
  DB: D1Database;
};

const app = new Hono<{ Bindings: Bindings }>();

app.use("*", cors());

// 動作確認用のヘルスチェック
app.get("/", (c) => {
  return c.json({ status: "ok", message: "BBP API is running" });
});

// プログラムをD1に保存
app.post("/programs", async (c) => {
  const body = await c.req.json().catch(() => null);

  if (!body || !body.companyName || !body.contactEmail || !body.scope || !body.description) {
    return c.json({ error: "必須項目が不足しています" }, 400);
  }

  const id = crypto.randomUUID();
  const createdAt = Date.now();

  try {
    await c.env.DB.prepare(
      `INSERT INTO programs (id, company_name, contact_email, scope, description, reward_min, reward_max, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        id,
        body.companyName,
        body.contactEmail,
        body.scope,
        body.description,
        Number(body.rewardMin) || 0,
        Number(body.rewardMax) || 0,
        createdAt
      )
      .run();

    return c.json({ received: true, id, createdAt });
  } catch (err) {
    console.error("D1 insert error:", err);
    return c.json({ error: "保存に失敗しました" }, 500);
  }
});
// プログラム一覧を取得
app.get("/programs", async (c) => {
  try {
    const { results } = await c.env.DB.prepare(
      `SELECT * FROM programs ORDER BY created_at DESC`
    ).all();

    return c.json({ programs: results });
  } catch (err) {
    console.error("D1 select error:", err);
    return c.json({ error: "取得に失敗しました" }, 500);
  }
});
export default app;
