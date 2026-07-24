# BBP API — ステップ① フロント↔API疎通

このステップの目的は、DBも認証もナシで「フォームを送ったらWorkers側に届く」ことだけを確認することです。

## 手順

1. 依存パッケージをインストール
   ```
   cd bugbounty-worker
   npm install
   ```

2. Workers をローカルで起動
   ```
   npm run dev
   ```
   `http://localhost:8787` で起動します。ターミナルはこのまま開いておいてください。

3. `public/index.html` をブラウザで直接開く（ダブルクリックでOK）

4. フォームに会社名を入力して送信

5. 確認ポイント
   - ブラウザ側：`result` の枠に `{"received": true, ...}` が表示される
   - ターミナル側：`New program submission: {...}` というログが出る

両方確認できればステップ①は完了です。

## 次のステップ（②）

`src/index.ts` の `POST /programs` の中で `console.log` しているだけの部分を、
Cloudflare D1（データベース）への保存に置き換えていきます。
そのタイミングで `wrangler d1 create` の話をします。

## つまずきやすいポイント

- **`npm install` でエラーが出る**: Node.js のバージョンが古い可能性があります（18以上推奨）
- **フォーム送信時に「APIに接続できませんでした」と出る**: `npm run dev` が起動しているか、ポート番号（8787）が一致しているか確認してください
- **CORSエラーが出る**: `src/index.ts` に `app.use("*", cors())` が入っているか確認してください（すでに入っています）
