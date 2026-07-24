import { Hono } from "hono";
import { cors } from "hono/cors";

const app = new Hono();

// フロントエンド（別オリジンで動くHTML）からのリクエストを許可
app.use("*", cors());

// 動作確認用のヘルスチェック
app.get("/", (c) => {
  return c.json({ status: "ok", message: "BBP API is running" });
});

// ステップ①: フロントから届いたデータをログに出すだけ
app.post("/programs", async (c) => {
  const body = await c.req.json().catch(() => null);

  if (!body || !body.companyName) {
    return c.json({ error: "companyName is required" }, 400);
  }

  console.log("New program submission:", body);

  // 次のステップでここをD1への保存に置き換える
  return c.json({ received: true, program: body });
});

export default app;
