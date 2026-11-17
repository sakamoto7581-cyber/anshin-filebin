import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { bodyLimit } from 'hono/body-limit';

type Bindings = {
  KV: KVNamespace;
};

/**
 * KV の meta:{token} に保存するメタデータ（平文のファイル名・MIME などは持たない）。
 * expiresAt はアップロード時刻＋3日の epoch ミリ秒、chunks は分割数、size は暗号化データ全体のバイト数。
 */
type FileMeta = {
  salt: string;
  iv: string;
  maxDownloads: number;
  currentDownloads: number;
  expiresAt: number;
  chunks: number;
  size: number;
};

const MAX_FILE_BYTES = 50 * 1024 * 1024; // 元ファイル 50MB
// 暗号文 = 4バイト長 + ヘッダーJSON + ファイル本体 + GCM タグ(16バイト)。
// ヘッダー（ファイル名・MIME）分の余裕として 64KB を足した値を上限とする。
const MAX_BODY_BYTES = MAX_FILE_BYTES + 64 * 1024;
const TTL_SECONDS = 259200; // 3日
// KV の値上限は 25MB。余裕をもって 20MiB ごとに分割して保存する
const CHUNK_SIZE = 20 * 1024 * 1024;
// KV の expirationTtl は 60 秒未満を受け付けない
const KV_MIN_TTL_SECONDS = 60;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const TOKEN_LENGTH = 16;
const TOKEN_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const TOKEN_RE = /^[A-Za-z0-9]{16}$/;

const app = new Hono<{ Bindings: Bindings }>();

// Pages と Worker を別ドメインで動かす場合に備えて CORS を付与する。
// 本番で特定オリジンに絞りたい場合は origin を変更する。
app.use(
  '/api/*',
  cors({
    origin: '*',
    allowMethods: ['GET', 'POST', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'X-Salt', 'X-Iv', 'X-Max-Downloads'],
    exposeHeaders: ['X-Salt', 'X-Iv', 'Content-Length'],
    maxAge: 86400,
  }),
);

const jsonError = (status: number, error: string) =>
  new Response(JSON.stringify({ error }), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });

/** crypto.getRandomValues 由来の 16 桁英数字（剰余バイアスを避けるため棄却サンプリング） */
function generateToken(): string {
  const limit = 256 - (256 % TOKEN_CHARS.length); // 248
  let token = '';
  while (token.length < TOKEN_LENGTH) {
    const buf = crypto.getRandomValues(new Uint8Array(32));
    for (const b of buf) {
      if (b < limit) token += TOKEN_CHARS[b % TOKEN_CHARS.length];
      if (token.length === TOKEN_LENGTH) break;
    }
  }
  return token;
}

/** base64url 文字列が指定バイト長にデコードできるか検証する */
function isBase64UrlOfLength(value: string | undefined, bytes: number): value is string {
  if (!value || !/^[A-Za-z0-9_-]+$/.test(value)) return false;
  try {
    const b64 = value.replace(/-/g, '+').replace(/_/g, '/');
    return atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4)).length === bytes;
  } catch {
    return false;
  }
}

const metaKey = (token: string) => `meta:${token}`;
const dataKey = (token: string, index: number) => `data:${token}:${index}`;

/** メタと全チャンクを削除する（期限切れ・上限到達の両方から使う） */
async function deleteFile(kv: KVNamespace, token: string, chunks: number): Promise<void> {
  const keys = [metaKey(token)];
  for (let i = 0; i < chunks; i++) keys.push(dataKey(token, i));
  await Promise.all(keys.map((k) => kv.delete(k)));
}

// ---------------------------------------------------------------------------
// POST /api/upload
// ---------------------------------------------------------------------------
app.post(
  '/api/upload',
  // Content-Length（およびストリームの実バイト数）が上限を超えたら 413
  bodyLimit({
    maxSize: MAX_BODY_BYTES,
    onError: () => jsonError(413, 'ファイルサイズが上限（50MB）を超えています'),
  }),
  async (c) => {
    const salt = c.req.header('X-Salt');
    const iv = c.req.header('X-Iv');
    const maxRaw = c.req.header('X-Max-Downloads');

    if (!isBase64UrlOfLength(salt, SALT_BYTES)) return jsonError(400, 'X-Salt が不正です');
    if (!isBase64UrlOfLength(iv, IV_BYTES)) return jsonError(400, 'X-Iv が不正です');

    // maxDownloads: 整数でなければ 400、範囲外の整数は 1〜10 にクランプ
    if (!maxRaw || !/^-?\d+$/.test(maxRaw.trim())) return jsonError(400, 'X-Max-Downloads が不正です');
    const maxDownloads = Math.min(10, Math.max(1, parseInt(maxRaw.trim(), 10)));

    const body = await c.req.arrayBuffer();
    // 念のため実バイト数でも再確認（Content-Length を偽装されたケース対策）
    if (body.byteLength > MAX_BODY_BYTES) return jsonError(413, 'ファイルサイズが上限（50MB）を超えています');
    // 最小でも 4バイト長 + GCM タグ 16 バイトはあるはず
    if (body.byteLength < 20) return jsonError(400, '暗号化データが空か不正です');

    const token = generateToken();
    const expiresAt = Date.now() + TTL_SECONDS * 1000;
    const size = body.byteLength;
    const chunks = Math.ceil(size / CHUNK_SIZE);

    // 1) チャンクを先にすべて保存（バイナリのまま）
    const puts: Promise<void>[] = [];
    for (let i = 0; i < chunks; i++) {
      const chunk = body.slice(i * CHUNK_SIZE, Math.min((i + 1) * CHUNK_SIZE, size));
      puts.push(c.env.KV.put(dataKey(token, i), chunk, { expirationTtl: TTL_SECONDS }));
    }
    await Promise.all(puts);

    // 2) 最後にメタを保存（メタが見える＝データが揃っている状態にする）
    const meta: FileMeta = { salt, iv, maxDownloads, currentDownloads: 0, expiresAt, chunks, size };
    await c.env.KV.put(metaKey(token), JSON.stringify(meta), { expirationTtl: TTL_SECONDS });

    return c.json({ token, url: `/download.html?t=${token}` }, 201);
  },
);

// ---------------------------------------------------------------------------
// GET /api/download/:token
// ---------------------------------------------------------------------------
app.get('/api/download/:token', async (c) => {
  const token = c.req.param('token');
  if (!TOKEN_RE.test(token)) return jsonError(404, 'not found');

  const kv = c.env.KV;
  const meta = await kv.get<FileMeta>(metaKey(token), 'json');
  if (!meta) return jsonError(404, 'not found');

  // 3日の絶対期限を過ぎていれば、メタ＋全チャンクを削除して 404
  const remainingSeconds = Math.floor((meta.expiresAt - Date.now()) / 1000);
  if (remainingSeconds <= 0) {
    await deleteFile(kv, token, meta.chunks);
    return jsonError(404, 'not found');
  }

  if (meta.currentDownloads >= meta.maxDownloads) {
    return jsonError(410, 'ダウンロード回数の上限に達しました');
  }

  // カウントを +1 して保存し直す。TTL は expiresAt までの残り秒数で再設定し、絶対期限を延ばさない。
  // （KV は 60 秒未満の TTL を受け付けないため下限 60 秒。期限判定は expiresAt で行うので実質延命しない）
  meta.currentDownloads += 1;
  const reachedLimit = meta.currentDownloads >= meta.maxDownloads;
  await kv.put(metaKey(token), JSON.stringify(meta), {
    expirationTtl: Math.max(KV_MIN_TTL_SECONDS, remainingSeconds),
  });

  // チャンクを 0..chunks-1 の順に取得。1つでも欠けていれば 503
  const parts = await Promise.all(
    Array.from({ length: meta.chunks }, (_, i) => kv.get(dataKey(token, i), 'arrayBuffer')),
  );
  if (parts.some((p) => p === null)) return jsonError(503, 'data not ready');

  const buffers = parts as ArrayBuffer[];
  const total = buffers.reduce((n, p) => n + p.byteLength, 0); // 通常は meta.size と一致
  const data = new Uint8Array(total);
  let offset = 0;
  for (const part of buffers) {
    data.set(new Uint8Array(part), offset);
    offset += part.byteLength;
  }

  // 今回のダウンロードで上限に達した場合は、読み終えた後にメタ＋全チャンクを削除
  if (reachedLimit) await deleteFile(kv, token, meta.chunks);

  return new Response(data, {
    status: 200,
    headers: {
      'Content-Type': 'application/octet-stream',
      'Content-Length': String(total),
      'Cache-Control': 'no-store',
      'X-Salt': meta.salt,
      'X-Iv': meta.iv,
    },
  });
});

app.notFound(() => jsonError(404, 'Not Found'));
app.onError((err) => {
  console.error(err);
  return jsonError(500, 'サーバーエラーが発生しました');
});

export default app;
