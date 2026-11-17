// receive.js — 受信画面の処理（暗号化データ取得 → ブラウザ内で復号 → 保存）
import { decryptFile, fromBase64Url } from './crypto.js';

const API_BASE = (document.querySelector('meta[name="api-base"]')?.content || '').replace(/\/+$/, '');

const $ = (id) => document.getElementById(id);
const form = $('receive-form');
const passwordInput = $('password');
const submitBtn = $('submit-btn');
const statusBox = $('status');
const progressWrap = $('progress-wrap');
const progressBar = $('progress-bar');

const STATUS_STYLES = {
  info: 'bg-slate-100 text-slate-700',
  error: 'bg-red-50 text-red-700 border border-red-200',
};
function showStatus(message, type = 'info') {
  statusBox.className = `rounded-lg px-4 py-3 text-sm ${STATUS_STYLES[type]}`;
  statusBox.textContent = message;
}
function setProgress(ratio) {
  progressWrap.classList.remove('hidden');
  progressBar.style.width = `${Math.round(ratio * 100)}%`;
}
function hideProgress() {
  progressWrap.classList.add('hidden');
}
function showFatal(title, message) {
  form.classList.add('hidden');
  $('fatal-title').textContent = title;
  $('fatal-message').textContent = message;
  $('fatal').classList.remove('hidden');
}

const token = new URLSearchParams(location.search).get('t');
const tokenValid = !!token && /^[A-Za-z0-9]{16}$/.test(token);
if (!tokenValid) {
  showFatal('URLが正しくありません', '共有URLが途中で切れていないか、送信者に確認してください。');
}

// ---------- 残り回数・有効期限の表示（/api/info はダウンロード回数を消費しない） ----------
function showFileInfo(message, type = 'info') {
  const el = $('file-info');
  el.className =
    type === 'error'
      ? 'rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700'
      : 'rounded-lg bg-emerald-50 px-4 py-3 text-sm text-emerald-800';
  el.textContent = message;
}

async function loadFileInfo() {
  let res;
  try {
    res = await fetch(`${API_BASE}/api/info/${encodeURIComponent(token)}`, { cache: 'no-store' });
  } catch {
    return; // 情報表示は補助なので、通信エラー時は何も出さない（受信フローはそのまま使える）
  }
  if (res.status === 404) {
    showFileInfo('ファイルが見つかりません（期限切れ・削除済みの可能性があります）', 'error');
    return;
  }
  if (res.status === 410) {
    showFileInfo('ダウンロード回数の上限に達しています', 'error');
    return;
  }
  if (!res.ok) return;
  let info;
  try {
    info = await res.json();
  } catch {
    return;
  }
  const d = new Date(info.expiresAt); // ユーザーのローカル時刻で整形
  showFileInfo(
    `あと${info.remainingDownloads}回ダウンロードできます（${d.getMonth() + 1}月${d.getDate()}日${d.getHours()}時まで有効）`,
  );
}
if (tokenValid) loadFileInfo();

// 一度取得した暗号化データはメモリに保持する。
// パスワードを間違えても再取得せずに済むので、ダウンロード回数を余分に消費しない。
let fetched = null; // { ciphertext: Uint8Array, salt: Uint8Array, iv: Uint8Array }

class FatalError extends Error {
  constructor(title, message) {
    super(message);
    this.title = title;
  }
}

async function fetchEncrypted() {
  let res;
  try {
    res = await fetch(`${API_BASE}/api/download/${encodeURIComponent(token)}`, { cache: 'no-store' });
  } catch {
    throw new Error('サーバーに接続できませんでした。通信環境を確認してください。');
  }

  if (res.status === 404) {
    throw new FatalError('ファイルが見つかりません', 'ファイルが存在しないか、保存期間（3日間）の経過またはダウンロード回数の上限到達により削除されました。');
  }
  if (res.status === 410) {
    throw new FatalError('ダウンロード回数の上限に達しました', 'このファイルは設定された回数ダウンロードされたため、取得できません。');
  }
  if (!res.ok) {
    let msg = `ファイルの取得に失敗しました（HTTP ${res.status}）`;
    try {
      msg = (await res.json()).error || msg;
    } catch {
      /* JSON 以外 */
    }
    throw new Error(msg);
  }

  const saltHeader = res.headers.get('X-Salt');
  const ivHeader = res.headers.get('X-Iv');
  if (!saltHeader || !ivHeader) throw new Error('サーバーの応答に必要な情報（Salt / IV）が含まれていません。');

  // 進捗表示のためストリームで読む
  const total = Number(res.headers.get('Content-Length')) || 0;
  const reader = res.body.getReader();
  const chunks = [];
  let received = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    received += value.length;
    if (total) {
      setProgress(received / total);
      showStatus(`暗号化データを取得中… ${Math.round((received / total) * 100)}%`);
    }
  }
  const ciphertext = new Uint8Array(received);
  let offset = 0;
  for (const c of chunks) {
    ciphertext.set(c, offset);
    offset += c.length;
  }

  return { ciphertext, salt: fromBase64Url(saltHeader), iv: fromBase64Url(ivHeader) };
}

function saveFile({ fileName, mimeType, data }) {
  const blob = new Blob([data], { type: mimeType || 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = fileName || 'download';
  document.body.appendChild(a);
  a.click();
  a.remove();

  // 自動ダウンロードが止められた場合に備えて、手動保存リンクも出しておく
  const link = $('save-link');
  link.href = url;
  link.download = fileName || 'download';
  link.textContent = `「${fileName}」を保存する`;
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const password = passwordInput.value;
  if (!password) return showStatus('パスワードを入力してください。', 'error');

  submitBtn.disabled = true;
  try {
    if (!fetched) {
      showStatus('暗号化データを取得中…');
      setProgress(0);
      fetched = await fetchEncrypted();
    }

    showStatus('ブラウザ内で復号しています…');
    let result;
    try {
      result = await decryptFile(fetched.ciphertext, password, fetched.salt, fetched.iv);
    } catch {
      hideProgress();
      showStatus('パスワードが違うか、ファイルが壊れています。', 'error');
      passwordInput.select();
      return;
    }

    hideProgress();
    saveFile(result);
    form.classList.add('hidden');
    $('done').classList.remove('hidden');
  } catch (err) {
    console.error(err);
    hideProgress();
    if (err instanceof FatalError) showFatal(err.title, err.message);
    else showStatus(err.message || 'エラーが発生しました。', 'error');
  } finally {
    submitBtn.disabled = false;
  }
});
