// crypto.js — 暗号化・復号化ロジック
//
// ブラウザ標準の Web Crypto API（グローバルの `crypto`）のみを使用する。
// window / document など window 固有の API には依存しない（Worker や Node でも動く）。
//
// 暗号化パラメータ（仕様）:
//   鍵導出 : PBKDF2 / SHA-256 / 600,000 回 / Salt 16 バイト
//   暗号化 : AES-GCM / 256 bit / IV 12 バイト
//
// 平文ペイロード形式:
//   [4バイト: ヘッダーJSON長（ビッグエンディアン）][ヘッダーJSON(UTF-8)][ファイル本体]
//   ヘッダーJSON = { "fileName": "...", "mimeType": "..." }
// ファイル名・MIME はこのペイロードごと暗号化されるため、サーバーには平文で渡らない。

export const PBKDF2_ITERATIONS = 600000;
export const PBKDF2_HASH = 'SHA-256';
export const SALT_LENGTH = 16; // bytes
export const IV_LENGTH = 12; // bytes
export const AES_KEY_LENGTH = 256; // bits

const subtle = globalThis.crypto.subtle;

/** 暗号学的に安全な乱数バイト列を返す */
export function randomBytes(length) {
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

/** パスワード + Salt から AES-GCM 鍵を PBKDF2 で導出する（鍵はエクスポート不可） */
export async function deriveKey(password, salt) {
  const baseKey = await subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: PBKDF2_HASH },
    baseKey,
    { name: 'AES-GCM', length: AES_KEY_LENGTH },
    false,
    ['encrypt', 'decrypt'],
  );
}

/** ヘッダー + ファイル本体を 1 本の平文ペイロードに組み立てる */
export function buildPayload(fileName, mimeType, fileBytes) {
  const header = new TextEncoder().encode(
    JSON.stringify({ fileName, mimeType: mimeType || 'application/octet-stream' }),
  );
  const body = fileBytes instanceof Uint8Array ? fileBytes : new Uint8Array(fileBytes);
  const out = new Uint8Array(4 + header.length + body.length);
  new DataView(out.buffer).setUint32(0, header.length, false); // big-endian
  out.set(header, 4);
  out.set(body, 4 + header.length);
  return out;
}

/** 平文ペイロードを分解して { fileName, mimeType, data } を返す */
export function parsePayload(payload) {
  const bytes = payload instanceof Uint8Array ? payload : new Uint8Array(payload);
  if (bytes.length < 4) throw new Error('payload too short');
  const headerLen = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0, false);
  if (headerLen > bytes.length - 4) throw new Error('invalid header length');
  const header = JSON.parse(new TextDecoder().decode(bytes.subarray(4, 4 + headerLen)));
  if (typeof header.fileName !== 'string') throw new Error('invalid header');
  return {
    fileName: header.fileName,
    mimeType: typeof header.mimeType === 'string' ? header.mimeType : 'application/octet-stream',
    data: bytes.subarray(4 + headerLen),
  };
}

/**
 * ファイルを暗号化する。
 * @returns {Promise<{ ciphertext: Uint8Array, salt: Uint8Array, iv: Uint8Array }>}
 */
export async function encryptFile({ fileName, mimeType, data }, password) {
  const salt = randomBytes(SALT_LENGTH);
  const iv = randomBytes(IV_LENGTH);
  const key = await deriveKey(password, salt);
  const plaintext = buildPayload(fileName, mimeType, data);
  const ciphertext = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext));
  return { ciphertext, salt, iv };
}

/**
 * 暗号文を復号する。パスワード違い・改ざん時は AES-GCM の認証に失敗して例外になる。
 * @returns {Promise<{ fileName: string, mimeType: string, data: Uint8Array }>}
 */
export async function decryptFile(ciphertext, password, salt, iv) {
  const key = await deriveKey(password, salt);
  const plaintext = await subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return parsePayload(new Uint8Array(plaintext));
}

/** Uint8Array → base64url（パディングなし） */
export function toBase64Url(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** base64url → Uint8Array */
export function fromBase64Url(str) {
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
