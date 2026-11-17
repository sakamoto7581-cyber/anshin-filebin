# ファイル暗号化メーカー

ブラウザ完結型のセキュアなファイル共有ツール（脱PPAP）。ホームページ工房「Webツール工房」のプレミアム道具。

公開URL: https://file.homepage-kobo.com （Cloudflare Pages のカスタムドメイン）

## 仕組み（ゼロ知識）
- ファイルは送信者のブラウザ内で、パスワードから PBKDF2（SHA-256 / 600,000回）で導出した鍵を使い AES-GCM（256bit）で暗号化される
- サーバー（Cloudflare）には暗号化データのみが保存され、パスワード・ファイル名・平文は一切送られない
- 保存期間は最大3日間、ダウンロード回数は1〜10回で設定可能（上限到達で自動削除）

## 構成
- `public/` … フロントエンド（index.html = 送信画面 / download.html = 受信画面 / js/）
- `src/api.ts` … Hono 製 API（POST /api/upload、GET /api/download/:token、GET /api/info/:token）
  - `GET /api/info/:token` は残り回数・有効期限などのメタ情報（`size, maxDownloads, currentDownloads, remainingDownloads, expiresAt`）だけを返し、ダウンロード回数は消費しない（期限切れ・不明は 404、上限到達は 410）
- `worker-entry.ts` … Pages の _worker.js 用エントリ（/api/* は API、それ以外は静的配信）
- ビルド: `npm run build`（esbuild で public/_worker.js を生成）

## Cloudflare Pages 設定
- Build command: `npm run build`
- Build output directory: `public`
- Bindings（Settings > Bindings）: KV namespace を `KV` として紐付け（KV のみ使用）
- 保存方式: 暗号化データを 20MiB ごとに分割して `data:{token}:{index}` に、メタ情報を `meta:{token}` に保存（すべて TTL 3日）

## ローカル開発
```
npm install
npm run build
npm run dev   # wrangler pages dev（KV はローカルエミュレーション）
```
