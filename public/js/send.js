// send.js — 送信画面の処理（ファイル選択 → ブラウザ内で暗号化 → アップロード）
import { encryptFile, toBase64Url, randomBytes } from './crypto.js';

const MAX_FILE_BYTES = 50 * 1024 * 1024; // 50MB
const API_BASE = (document.querySelector('meta[name="api-base"]')?.content || '').replace(/\/+$/, '');

const $ = (id) => document.getElementById(id);
const form = $('send-form');
const dropZone = $('drop-zone');
const fileInput = $('file-input');
const fileInfo = $('file-info');
const passwordInput = $('password');
const maxSelect = $('max-downloads');
const submitBtn = $('submit-btn');
const statusBox = $('status');
const progressWrap = $('progress-wrap');
const progressBar = $('progress-bar');

let selectedFile = null;

// ---------- 表示ヘルパー ----------
const STATUS_STYLES = {
  info: 'bg-slate-100 text-slate-700',
  error: 'bg-red-50 text-red-700 border border-red-200',
  success: 'bg-emerald-50 text-emerald-800 border border-emerald-200',
};

function showStatus(message, type = 'info') {
  statusBox.className = `rounded-lg px-4 py-3 text-sm ${STATUS_STYLES[type]}`;
  statusBox.textContent = message;
}
function hideStatus() {
  statusBox.className = 'hidden';
}
function setProgress(ratio) {
  progressWrap.classList.remove('hidden');
  progressBar.style.width = `${Math.round(ratio * 100)}%`;
}
function hideProgress() {
  progressWrap.classList.add('hidden');
  progressBar.style.width = '0';
}
function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

// ---------- ファイル選択 ----------
function selectFile(file) {
  if (!file) return;
  if (file.size > MAX_FILE_BYTES) {
    selectedFile = null;
    fileInput.value = '';
    fileInfo.classList.add('hidden');
    showStatus(`ファイルサイズが上限（50MB）を超えています（${formatBytes(file.size)}）。`, 'error');
    return;
  }
  selectedFile = file;
  fileInfo.textContent = `${file.name}（${formatBytes(file.size)}）`;
  fileInfo.classList.remove('hidden');
  hideStatus();
}

dropZone.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' || e.key === ' ') {
    e.preventDefault();
    fileInput.click();
  }
});
fileInput.addEventListener('change', () => selectFile(fileInput.files[0]));

['dragenter', 'dragover'].forEach((ev) =>
  dropZone.addEventListener(ev, (e) => {
    e.preventDefault();
    dropZone.classList.add('border-emerald-500', 'bg-emerald-50');
  }),
);
['dragleave', 'drop'].forEach((ev) =>
  dropZone.addEventListener(ev, (e) => {
    e.preventDefault();
    dropZone.classList.remove('border-emerald-500', 'bg-emerald-50');
  }),
);
dropZone.addEventListener('drop', (e) => {
  const files = e.dataTransfer?.files;
  if (!files || files.length === 0) return;
  if (files.length > 1) showStatus('1ファイルずつ送信できます。最初のファイルを選択しました。', 'info');
  selectFile(files[0]);
});
// ドロップゾーン外にファイルを落としてもブラウザがファイルを開かないようにする
window.addEventListener('dragover', (e) => e.preventDefault());
window.addEventListener('drop', (e) => e.preventDefault());

// ---------- パスワード ----------
$('toggle-password').addEventListener('click', (e) => {
  const show = passwordInput.type === 'password';
  passwordInput.type = show ? 'text' : 'password';
  e.currentTarget.textContent = show ? '隠す' : '表示';
});

$('gen-password').addEventListener('click', () => {
  // 紛らわしい文字（0/O, 1/l/I）を除いた 16 文字
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  const limit = 256 - (256 % chars.length);
  let pw = '';
  while (pw.length < 16) {
    for (const b of randomBytes(32)) {
      if (b < limit && pw.length < 16) pw += chars[b % chars.length];
    }
  }
  passwordInput.value = pw;
  passwordInput.type = 'text';
  $('toggle-password').textContent = '隠す';
});

// ---------- アップロード（進捗を出すため XHR を使用） ----------
function upload(ciphertext, saltB64, ivB64, maxDownloads) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', `${API_BASE}/api/upload`);
    xhr.setRequestHeader('Content-Type', 'application/octet-stream');
    xhr.setRequestHeader('X-Salt', saltB64);
    xhr.setRequestHeader('X-Iv', ivB64);
    xhr.setRequestHeader('X-Max-Downloads', String(maxDownloads));
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) {
        setProgress(e.loaded / e.total);
        showStatus(`アップロード中… ${Math.round((e.loaded / e.total) * 100)}%`);
      }
    };
    xhr.onload = () => {
      let data = null;
      try {
        data = JSON.parse(xhr.responseText);
      } catch {
        /* JSON 以外 */
      }
      if (xhr.status >= 200 && xhr.status < 300 && data?.token) resolve(data);
      else if (xhr.status === 413) reject(new Error('ファイルサイズが上限（50MB）を超えています。'));
      else reject(new Error(data?.error || `アップロードに失敗しました（HTTP ${xhr.status}）`));
    };
    xhr.onerror = () => reject(new Error('サーバーに接続できませんでした。通信環境を確認してください。'));
    xhr.send(ciphertext);
  });
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();

  if (!selectedFile) return showStatus('ファイルを選択してください。', 'error');
  if (selectedFile.size > MAX_FILE_BYTES) return showStatus('ファイルサイズが上限（50MB）を超えています。', 'error');
  const password = passwordInput.value;
  if (!password) return showStatus('パスワードを入力してください。', 'error');
  const maxDownloads = parseInt(maxSelect.value, 10);
  if (!Number.isInteger(maxDownloads) || maxDownloads < 1 || maxDownloads > 10) {
    return showStatus('ダウンロード回数は 1〜10 回で選択してください。', 'error');
  }

  submitBtn.disabled = true;
  try {
    showStatus('ブラウザ内で暗号化しています…（鍵の導出に数秒かかることがあります）');
    setProgress(0);
    const data = new Uint8Array(await selectedFile.arrayBuffer());
    const { ciphertext, salt, iv } = await encryptFile(
      { fileName: selectedFile.name, mimeType: selectedFile.type, data },
      password,
    );

    showStatus('アップロード中… 0%');
    const res = await upload(ciphertext, toBase64Url(salt), toBase64Url(iv), maxDownloads);

    const shareUrl = new URL(res.url, location.href).href;
    showResult(shareUrl, password, maxDownloads);
  } catch (err) {
    console.error(err);
    hideProgress();
    showStatus(err instanceof Error ? err.message : 'エラーが発生しました。', 'error');
  } finally {
    submitBtn.disabled = false;
  }
});

// ---------- 完了画面 ----------
function showResult(url, password, maxDownloads) {
  form.classList.add('hidden');
  $('result').classList.remove('hidden');
  $('share-url').value = url;
  $('share-password').value = password;
  $('result-summary').textContent =
    `ダウンロード可能回数: ${maxDownloads} 回 ／ 保存期間: アップロードから3日間。期限切れ・上限到達でサーバーから自動削除されます。`;
}

async function copyFrom(inputId, btn) {
  const input = $(inputId);
  try {
    await navigator.clipboard.writeText(input.value);
  } catch {
    input.select();
    document.execCommand('copy');
  }
  const label = btn.textContent;
  btn.textContent = 'コピーしました';
  setTimeout(() => (btn.textContent = label), 1500);
}
$('copy-url').addEventListener('click', (e) => copyFrom('share-url', e.currentTarget));
$('copy-password').addEventListener('click', (e) => copyFrom('share-password', e.currentTarget));

$('send-another').addEventListener('click', () => {
  selectedFile = null;
  form.reset();
  fileInfo.classList.add('hidden');
  passwordInput.type = 'password';
  $('toggle-password').textContent = '表示';
  $('share-password').value = '';
  hideStatus();
  hideProgress();
  $('result').classList.add('hidden');
  form.classList.remove('hidden');
});
