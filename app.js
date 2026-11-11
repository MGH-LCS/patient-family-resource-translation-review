// Translation review page.
//
// Flow: the reviewer types the shared password. It does two things at once:
// it unlocks the encrypted text files (the key is derived from the password in
// the browser, so the text never leaves this page readable), and it signs in to
// Supabase, where everyone's checks and suggestions are kept. Every edit goes
// into an outbox on this computer first and is then sent, so nothing typed is
// lost when the network drops.

import { SUPABASE_URL, SUPABASE_KEY, REVIEWER_EMAIL, TABLE, APP_SUBTITLE } from './config.js?v=2';

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

const $ = (sel, root = document) => root.querySelector(sel);

/** Escapes text for use inside HTML markup (content and attribute values). */
function esc(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const utf8 = new TextEncoder();
const utf8d = new TextDecoder();

function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToB64(bytes) {
  let bin = '';
  const arr = new Uint8Array(bytes);
  for (let i = 0; i < arr.length; i += 0x8000) bin += String.fromCharCode(...arr.subarray(i, i + 0x8000));
  return btoa(bin);
}

function uuid() {
  if (crypto.randomUUID) return crypto.randomUUID();
  const b = crypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** Lower case, no accents: "Cómo" matches "como". */
function fold(text) {
  return String(text ?? '').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();
}

function shortDate(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const opts = { month: 'short', day: 'numeric' };
  if (d.getFullYear() !== new Date().getFullYear()) opts.year = 'numeric';
  return d.toLocaleDateString('en-US', opts);
}

const timeOf = (iso) => {
  const t = Date.parse(iso);
  return Number.isNaN(t) ? 0 : t;
};

// Storage can throw (private windows, blocked site data); never let that break the page.
const store = {
  get(area, key) {
    try { return JSON.parse(area.getItem(key)); } catch { return null; }
  },
  set(area, key, value) {
    try { area.setItem(key, JSON.stringify(value)); return true; } catch { return false; }
  },
  remove(area, key) {
    try { area.removeItem(key); } catch { /* nothing to do */ }
  },
};
const LOCAL = (() => { try { return window.localStorage; } catch { return null; } })();
const SESSION = (() => { try { return window.sessionStorage; } catch { return null; } })();
const memoryArea = new Map();
const fallbackArea = {
  getItem: (k) => (memoryArea.has(k) ? memoryArea.get(k) : null),
  setItem: (k, v) => memoryArea.set(k, String(v)),
  removeItem: (k) => memoryArea.delete(k),
};
const localArea = LOCAL ?? fallbackArea;
const sessionArea = SESSION ?? fallbackArea;

const RTL_LANGS = new Set(['ar', 'he', 'fa', 'ur']);
const dirFor = (lang) => (RTL_LANGS.has(String(lang).split('-')[0]) ? 'rtl' : 'ltr');

/** English name of a language ("es" → "Spanish"), falling back to its own name. */
function englishName(lang, fallback) {
  try {
    const name = new Intl.DisplayNames(['en'], { type: 'language' }).of(lang);
    if (name && name !== lang) return name;
  } catch { /* older browser */ }
  return fallback || lang;
}

// ---------------------------------------------------------------------------
// Settings from the address bar
// ---------------------------------------------------------------------------

const params = new URLSearchParams(location.search);
const ENV = params.get('env') === 'test' ? 'test' : 'review';
const INDEX_URL = ENV === 'test' ? 'data/test/index.json' : 'data/index.json';
const DATA_DIR = INDEX_URL.slice(0, INDEX_URL.lastIndexOf('/') + 1);

/**
 * For trying the page out on this computer only: `?api=` may point the page at
 * a local stand-in server. Anything that isn't plain http on localhost or
 * 127.0.0.1 is ignored, so a link can never send the password somewhere else.
 */
function localApiOverride() {
  const raw = params.get('api');
  if (!raw || !(raw.startsWith('http://localhost:') || raw.startsWith('http://127.0.0.1:'))) return null;
  try {
    const u = new URL(raw);
    if (u.protocol !== 'http:' || u.username || u.password) return null;
    if (u.hostname !== 'localhost' && u.hostname !== '127.0.0.1') return null;
    return u.origin;
  } catch {
    return null;
  }
}
const LOCAL_API = localApiOverride();
const API = LOCAL_API ?? SUPABASE_URL.replace(/\/+$/, '');
// The reviewer account may only be swapped together with the local stand-in server.
const EMAIL = (LOCAL_API && params.get('email')) || REVIEWER_EMAIL;

// Storage keys. The outbox is per server so rows meant for one never go to another.
const K = {
  session: 'tr-session',
  outbox: `tr-outbox:${API}`,
  name: 'tr-name',
  reviewerId: 'tr-reviewer-id',
  lang: 'tr-lang',
  relockMsg: 'tr-relock-message',
};

function reviewerId() {
  let id = store.get(localArea, K.reviewerId);
  if (typeof id !== 'string' || !id) {
    id = uuid();
    store.set(localArea, K.reviewerId, id);
  }
  return id;
}

// ---------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------

async function deriveKey(password, saltB64, iterations) {
  const base = await crypto.subtle.importKey('raw', utf8.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt: b64ToBytes(saltB64), iterations },
    base,
    { name: 'AES-GCM', length: 256 },
    true,
    ['decrypt'],
  );
}

const importRawKey = (rawB64) =>
  crypto.subtle.importKey('raw', b64ToBytes(rawB64), { name: 'AES-GCM', length: 256 }, true, ['decrypt']);

const exportRawKey = async (key) => bytesToB64(await crypto.subtle.exportKey('raw', key));

class WrongKey extends Error {}
class NetworkError extends Error {}
class AuthRejected extends Error {}

async function fetchJson(url) {
  let res;
  try {
    res = await fetch(url, { cache: 'no-cache' });
  } catch {
    throw new NetworkError('offline');
  }
  if (!res.ok) throw new NetworkError(`status ${res.status}`);
  return res.json();
}

/** Fetches and decrypts one language file. Throws WrongKey when the key doesn't fit. */
async function loadSnapshot(key, file) {
  const box = await fetchJson(DATA_DIR + encodeURIComponent(file));
  let plain;
  try {
    plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64ToBytes(box.iv) }, key, b64ToBytes(box.data));
  } catch {
    throw new WrongKey('decrypt');
  }
  const snap = JSON.parse(utf8d.decode(plain));
  if (!snap || !Array.isArray(snap.entries) || !Array.isArray(snap.items)) throw new Error('unexpected file');
  return snap;
}

// ---------------------------------------------------------------------------
// Sign-in (Supabase auth)
// ---------------------------------------------------------------------------

const auth = { access: null, refresh: null, expiresAt: 0, remember: false, timer: null, inflight: null };

async function tokenRequest(grant, body) {
  let res;
  try {
    res = await fetch(`${API}/auth/v1/token?grant_type=${grant}`, {
      method: 'POST',
      headers: { apikey: SUPABASE_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  } catch {
    throw new NetworkError('offline');
  }
  if (res.status === 429 || res.status >= 500) throw new NetworkError(`status ${res.status}`);
  if (!res.ok) throw new AuthRejected(`status ${res.status}`);
  const json = await res.json();
  if (!json.access_token || !json.refresh_token) throw new AuthRejected('no token');
  return json;
}

function sessionArea_() {
  return auth.remember ? localArea : sessionArea;
}

function readStoredSession() {
  return store.get(localArea, K.session) ?? store.get(sessionArea, K.session);
}

function takeTokens(json) {
  auth.access = json.access_token;
  auth.refresh = json.refresh_token;
  auth.expiresAt = Date.now() + Math.max(60, Number(json.expires_in) || 3600) * 1000;
  const saved = readStoredSession();
  if (saved) store.set(sessionArea_(), K.session, { ...saved, refresh_token: auth.refresh });
  clearTimeout(auth.timer);
  // Refresh a minute before the token runs out.
  auth.timer = setTimeout(() => refreshNow().catch(onAuthError), Math.max(5_000, auth.expiresAt - Date.now() - 60_000));
}

async function signIn(password) {
  takeTokens(await tokenRequest('password', { email: EMAIL, password }));
}

/** One refresh at a time. Another tab may already have swapped the token, so look in storage first. */
function refreshNow() {
  if (auth.inflight) return auth.inflight;
  auth.inflight = (async () => {
    const stored = readStoredSession();
    let token = stored?.refresh_token || auth.refresh;
    if (!token) throw new AuthRejected('no refresh token');
    try {
      takeTokens(await tokenRequest('refresh_token', { refresh_token: token }));
    } catch (err) {
      const again = readStoredSession()?.refresh_token;
      if (err instanceof AuthRejected && again && again !== token) {
        token = again;
        takeTokens(await tokenRequest('refresh_token', { refresh_token: token }));
      } else {
        throw err;
      }
    }
  })().finally(() => { auth.inflight = null; });
  return auth.inflight;
}

async function accessToken() {
  if (auth.access && Date.now() < auth.expiresAt - 30_000) return auth.access;
  await refreshNow();
  return auth.access;
}

function onAuthError(err) {
  if (err instanceof AuthRejected) relock('Please type the password again.');
  // Network trouble: keep going; the next save or refresh tries again.
}

/** Calls the Supabase data API, refreshing the sign-in once if it has run out. */
async function api(path, init = {}) {
  for (let attempt = 0; attempt < 2; attempt++) {
    const token = await accessToken();
    let res;
    try {
      res = await fetch(API + path, {
        ...init,
        headers: { apikey: SUPABASE_KEY, Authorization: `Bearer ${token}`, ...(init.headers || {}) },
      });
    } catch {
      throw new NetworkError('offline');
    }
    if (res.status === 401) {
      auth.access = null;
      if (attempt === 0) continue;
      throw new AuthRejected('still 401');
    }
    return res;
  }
  throw new AuthRejected('still 401');
}

// ---------------------------------------------------------------------------
// Rows: everyone's checks and suggestions
// ---------------------------------------------------------------------------

const PAGE_ROWS = 1000;

async function fetchAllRows(lang) {
  const out = [];
  for (let from = 0; ; from += PAGE_ROWS) {
    const q = `select=*&lang=eq.${encodeURIComponent(lang)}&environment=eq.${ENV}&order=created_at.asc,submission_id.asc`;
    const res = await api(`/rest/v1/${TABLE}?${q}`, {
      headers: { Range: `${from}-${from + PAGE_ROWS - 1}`, 'Range-Unit': 'items' },
    });
    if (res.status === 416) break; // asked past the end
    if (res.status >= 500) throw new NetworkError(`status ${res.status}`);
    if (!res.ok) throw new Error(`status ${res.status}`);
    const page = await res.json();
    if (!Array.isArray(page)) throw new Error('unexpected reply');
    out.push(...page);
    if (page.length < PAGE_ROWS) break;
  }
  return out;
}

/** 'saved' | 'retry' | {failed: status, message} */
async function insertRow(row) {
  let res;
  try {
    res = await api(`/rest/v1/${TABLE}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Prefer: 'return=minimal' },
      body: JSON.stringify(row),
    });
  } catch (err) {
    if (err instanceof AuthRejected) throw err;
    return 'retry';
  }
  if (res.ok || res.status === 409) return 'saved'; // 409: this exact row is already there
  if (res.status >= 500 || res.status === 408 || res.status === 429) return 'retry';
  let message = '';
  try { message = (await res.json())?.message || ''; } catch { /* no body */ }
  return { failed: res.status, message };
}

// ---------------------------------------------------------------------------
// Outbox: edits wait here, on this computer, until they're saved
// ---------------------------------------------------------------------------

const outbox = {
  read() {
    const list = store.get(localArea, K.outbox);
    return Array.isArray(list) ? list : [];
  },
  write(list) {
    if (!store.set(localArea, K.outbox, list)) {
      // Storage refused (full or blocked): keep it in this tab at least.
      memoryArea.set(K.outbox, JSON.stringify(list));
    }
  },
  push(row) {
    const list = this.read();
    list.push({ row });
    this.write(list);
  },
};

let flushing = false;
let lastSendFailed = false;

async function withOutboxLock(fn) {
  // Several open tabs share one outbox; only one sends at a time.
  if (navigator.locks?.request) {
    return navigator.locks.request(`tr-outbox-lock:${API}`, { ifAvailable: true }, (lock) => (lock ? fn() : null));
  }
  return fn();
}

async function flush() {
  if (flushing || !state.unlocked) return;
  flushing = true;
  renderSaveState();
  try {
    await withOutboxLock(async () => {
      for (;;) {
        const list = outbox.read();
        const next = list.find((o) => !o.failed);
        if (!next) { lastSendFailed = false; break; }
        let result;
        try {
          result = await insertRow(next.row);
        } catch (err) {
          if (err instanceof AuthRejected) { onAuthError(err); return; }
          result = 'retry';
        }
        if (result === 'retry') { lastSendFailed = true; break; }
        lastSendFailed = false;
        const fresh = outbox.read();
        const key = next.row.entry_key;
        let updated;
        if (result === 'saved') {
          state.serverRows.push({ ...next.row, created_at: new Date().toISOString() });
          // A saved row also makes any older failed row for the same text moot.
          const idx = fresh.findIndex((o) => o.row.submission_id === next.row.submission_id);
          updated = fresh.filter((o, i) => i !== idx && !(o.failed && o.row.entry_key === key && i < idx));
        } else {
          updated = fresh.map((o) =>
            o.row.submission_id === next.row.submission_id ? { ...o, failed: { status: result.failed, message: result.message } } : o,
          );
        }
        outbox.write(updated);
        refreshDerived([key]);
      }
    });
  } finally {
    flushing = false;
    renderSaveState();
  }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const state = {
  unlocked: false,
  index: null,
  key: null,
  lang: null,
  langName: '', // English name, e.g. "Spanish"
  snap: null,
  entries: [],
  entryByKey: new Map(),
  itemById: new Map(),
  groupLabel: new Map(),
  itemTotals: new Map(),
  serverRows: [],
  info: new Map(), // entry key → derived status
  filter: 'unchecked',
  group: null,
  search: '',
  visible: [],
  shown: 0,
  rendered: new Map(), // entry key → row element
  cards: new Map(), // item id → card element
  lastRowsFetch: 0,
  rowsError: false,
};

const OUTCOME_TEXT = {
  updated: 'Updated in the app',
  kept: 'Mark kept the current wording',
  other_chosen: 'Mark chose another suggestion',
  next_update: 'In the next app update',
};

function outcomeOf(row) {
  const o = state.snap?.outcomes?.[row.submission_id];
  return OUTCOME_TEXT[o] || '';
}

function prepareSnapshot(snap) {
  state.snap = snap;
  state.itemById = new Map(snap.items.map((i) => [i.id, i]));
  state.groupLabel = new Map((snap.groups || []).map((g) => [g.id, g.label]));
  state.entries = snap.entries.map((e, order) => {
    const item = state.itemById.get(e.item) || { id: e.item, group: '', title: e.item };
    return {
      ...e,
      flags: Array.isArray(e.flags) ? e.flags : [],
      current: e.current ?? '',
      en: e.en ?? '',
      order,
      group: item.group,
      searchText: fold(`${e.en}\n${e.current}`),
    };
  });
  state.entryByKey = new Map(state.entries.map((e) => [e.key, e]));
  state.itemTotals = new Map();
  for (const e of state.entries) state.itemTotals.set(e.item, (state.itemTotals.get(e.item) || 0) + 1);
}

/** Rows for the current language: saved ones plus those still in the outbox. */
function allRows() {
  const seen = new Set();
  const rows = [];
  for (const r of state.serverRows) {
    if (!r || seen.has(r.submission_id)) continue;
    seen.add(r.submission_id);
    rows.push({ row: r, pending: false });
  }
  for (const o of outbox.read()) {
    const r = o.row;
    if (r.lang !== state.lang || r.environment !== ENV || seen.has(r.submission_id)) continue;
    if (o.failed) continue;
    seen.add(r.submission_id);
    rows.push({ row: r, pending: true });
  }
  return rows;
}

function deriveInfo(keys) {
  const me = reviewerId();
  const want = keys ? new Set(keys) : null;
  const byKey = new Map();
  for (const x of allRows()) {
    const k = x.row.entry_key;
    if (want && !want.has(k)) continue;
    if (!byKey.has(k)) byKey.set(k, []);
    byKey.get(k).push(x);
  }
  const outboxList = outbox.read().filter((o) => o.row.lang === state.lang && o.row.environment === ENV);
  const targets = want ? [...want] : state.entries.map((e) => e.key);
  for (const k of targets) {
    const newest = new Map(); // reviewer_id → row (newest by client_at; later wins on a tie)
    for (const { row } of byKey.get(k) || []) {
      const prev = newest.get(row.reviewer_id);
      if (!prev || timeOf(row.client_at) >= timeOf(prev.client_at)) newest.set(row.reviewer_id, row);
    }
    const latest = [...newest.values()];
    const mine = newest.get(me) || null;
    const others = latest.filter((r) => r.reviewer_id !== me).sort((a, b) => timeOf(b.client_at) - timeOf(a.client_at));
    const suggests = latest.filter((r) => r.verdict === 'suggest');
    let status = 'none';
    let by = null;
    if (latest.length) {
      status = suggests.length ? 'suggest' : 'ok';
      const pool = suggests.length ? suggests : latest;
      by = pool.reduce((a, b) => (timeOf(b.client_at) >= timeOf(a.client_at) ? b : a));
    }
    const mineOut = outboxList.filter((o) => o.row.entry_key === k);
    state.info.set(k, {
      status,
      by,
      reviewers: latest.length,
      mine,
      others,
      pending: mineOut.some((o) => !o.failed),
      failed: mineOut.find((o) => o.failed) || null,
    });
  }
}

const infoOf = (key) => state.info.get(key) || { status: 'none', mine: null, others: [], reviewers: 0 };

// ---------------------------------------------------------------------------
// Checks on what the reviewer typed (same rules as the "Check this first" lines)
// ---------------------------------------------------------------------------

const SAME_TEXT_OK = /address|name|web|phone|email|pdf/i;
const placeholdersIn = (t) => [...t.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
const linkTargetsIn = (t) => [...t.matchAll(/\]\(([^)\s]+)\)/g)].map((m) => m[1]).sort();
const sameList = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

function bracesBalance(text) {
  let depth = 0;
  for (const ch of text) {
    if (ch === '{') depth++;
    else if (ch === '}' && --depth < 0) return false;
  }
  return depth === 0;
}

function checkText(entry, text) {
  if (!text.trim()) return [];
  const reasons = [];
  const looksLikeWords = /[a-z]{3}/i.test(entry.en) && !/^(https?:|tel:|mailto:)/.test(entry.en.trim());
  if (text.trim() === entry.en.trim() && looksLikeWords && entry.en.trim().length > 3 && !SAME_TEXT_OK.test(entry.kind)) {
    reasons.push('This is the same as the English.');
  }
  const wanted = entry.placeholders?.length ? [...entry.placeholders].sort() : placeholdersIn(entry.en);
  const found = placeholdersIn(text);
  const missing = wanted.filter((p) => !found.includes(p));
  const extra = found.filter((p) => !wanted.includes(p));
  if (missing.length) reasons.push(`Keep ${missing.map((p) => `{${p}}`).join(', ')} exactly as it is — the app fills it in.`);
  if (extra.length) reasons.push(`${extra.map((p) => `{${p}}`).join(', ')} isn't in the English; the app can't fill it in.`);
  if (!bracesBalance(text)) reasons.push('A { or } is missing.');
  if (entry.markdown && !sameList(linkTargetsIn(entry.en), linkTargetsIn(text))) {
    reasons.push('The links differ from the English. Keep each web address in its ( ) exactly as it is.');
  }
  return reasons;
}

// ---------------------------------------------------------------------------
// Text rendering
// ---------------------------------------------------------------------------

let purifyReady = false;
function setUpPurify() {
  if (purifyReady || !window.DOMPurify) return;
  window.DOMPurify.addHook('afterSanitizeAttributes', (node) => {
    if (node.tagName === 'A') {
      node.setAttribute('target', '_blank');
      node.setAttribute('rel', 'noopener noreferrer');
    }
  });
  purifyReady = true;
}

const htmlCache = new Map();

/** Markdown through marked + DOMPurify; anything else (or no libraries) as escaped text. */
function textHtml(text, markdown) {
  if (markdown && window.marked && window.DOMPurify) {
    const cacheKey = text;
    if (htmlCache.has(cacheKey)) return { html: htmlCache.get(cacheKey), plain: false };
    setUpPurify();
    const html = window.DOMPurify.sanitize(window.marked.parse(text, { gfm: true }), {
      FORBID_TAGS: ['style', 'img', 'form', 'input', 'button', 'iframe'],
      FORBID_ATTR: ['style'],
    });
    htmlCache.set(cacheKey, html);
    return { html, plain: false };
  }
  return { html: esc(text), plain: true };
}

// ---------------------------------------------------------------------------
// Unlock screen
// ---------------------------------------------------------------------------

const ui = {
  unlock: $('#unlock'),
  app: $('#app'),
  form: $('#unlock-form'),
  status: $('#unlock-status'),
  fields: $('#unlock-fields'),
  password: $('#password'),
  remember: $('#remember'),
  unlockBtn: $('#unlock-btn'),
  error: $('#unlock-error'),
  waiting: $('#unlock-waiting'),
  list: $('#list'),
  more: $('#more'),
  results: $('#results'),
  filters: $('#filters'),
  groupNav: $('#group-nav'),
  search: $('#search'),
  saveState: $('#save-state'),
  banner: $('#banner'),
  langSelect: $('#lang-select'),
  dialog: $('#welcome'),
};

function showUnlock(message) {
  state.unlocked = false;
  ui.app.hidden = true;
  ui.unlock.hidden = false;
  ui.status.textContent = '';
  ui.fields.hidden = false;
  ui.error.textContent = message || '';
  const waiting = outbox.read().length;
  ui.waiting.hidden = waiting === 0;
  ui.waiting.textContent = waiting
    ? `${waiting} ${waiting === 1 ? 'change' : 'changes'} from this computer will be saved when you unlock.`
    : '';
  ui.password.focus();
}

function clearSession() {
  store.remove(localArea, K.session);
  store.remove(sessionArea, K.session);
}

/** Ends the session and starts over at the unlock screen. Unsaved edits stay in the outbox. */
function relock(message) {
  clearSession();
  if (message) store.set(sessionArea, K.relockMsg, message);
  location.reload();
}

function pickLanguage(index) {
  const saved = store.get(localArea, K.lang);
  return index.languages.find((l) => l.lang === saved) || index.languages[0];
}

async function boot() {
  $('#unlock-sub').textContent = APP_SUBTITLE;
  $('#app-sub').textContent = APP_SUBTITLE;
  try {
    state.index = await fetchJson(INDEX_URL);
    if (!Array.isArray(state.index?.languages) || !state.index.languages.length) throw new Error('no languages');
  } catch {
    ui.status.textContent = "The review couldn't load. Check your internet connection and reload the page.";
    return;
  }
  if (!EMAIL) {
    ui.status.textContent = "The review isn't set up yet. Mark will let you know when it's ready.";
    return;
  }

  const relockMsg = store.get(sessionArea, K.relockMsg);
  store.remove(sessionArea, K.relockMsg);

  const saved = readStoredSession();
  if (saved?.rawKey && saved?.refresh_token) {
    ui.status.textContent = 'Opening…';
    const resumed = await resume(saved).catch(() => false);
    if (resumed) return;
    clearSession();
  }
  showUnlock(relockMsg);
}

async function resume(saved) {
  if (saved.keySalt !== state.index.keySalt) return false; // the password has changed
  auth.remember = store.get(localArea, K.session) != null;
  auth.refresh = saved.refresh_token;
  const key = await importRawKey(saved.rawKey);
  const choice = pickLanguage(state.index);
  let snap;
  try {
    snap = await loadSnapshot(key, choice.file);
  } catch (err) {
    if (err instanceof WrongKey) return false;
    ui.status.textContent = "The review couldn't load. Check your internet connection and reload the page.";
    return true; // keep the saved session; it may work after a reload
  }
  try {
    await refreshNow();
  } catch (err) {
    if (err instanceof AuthRejected) return false;
    // Offline: the text is open; saves wait in the outbox until the sign-in can be renewed.
  }
  state.key = key;
  enterApp(choice, snap);
  return true;
}

ui.form.addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const password = ui.password.value;
  if (!password) {
    ui.error.textContent = 'Type the password first.';
    return;
  }
  ui.error.textContent = '';
  ui.unlockBtn.disabled = true;
  ui.unlockBtn.textContent = 'Unlocking…';
  try {
    const choice = pickLanguage(state.index);
    const keyPromise = deriveKey(password, state.index.keySalt, state.index.iterations);
    const [snapResult, signInResult] = await Promise.allSettled([
      keyPromise.then((key) => loadSnapshot(key, choice.file).then((snap) => ({ key, snap }))),
      signIn(password),
    ]);
    const bad = (r) => r.status === 'rejected' && (r.reason instanceof WrongKey || r.reason instanceof AuthRejected);
    if (bad(snapResult) || bad(signInResult)) {
      auth.access = auth.refresh = null;
      ui.error.textContent = "That password didn't work.";
      ui.password.select();
      return;
    }
    if (snapResult.status === 'rejected' || signInResult.status === 'rejected') {
      auth.access = auth.refresh = null;
      ui.error.textContent = "Couldn't connect. Check your internet connection and try again in a minute.";
      return;
    }
    const { key, snap } = snapResult.value;
    auth.remember = ui.remember.checked;
    clearSession();
    store.set(sessionArea_(), K.session, {
      refresh_token: auth.refresh,
      rawKey: await exportRawKey(key),
      keySalt: state.index.keySalt,
    });
    state.key = key;
    ui.password.value = '';
    enterApp(choice, snap);
  } catch {
    ui.error.textContent = "Something went wrong. Reload the page and try again.";
  } finally {
    ui.unlockBtn.disabled = false;
    ui.unlockBtn.textContent = 'Unlock';
  }
});

// ---------------------------------------------------------------------------
// The review itself
// ---------------------------------------------------------------------------

function myName() {
  const n = store.get(localArea, K.name);
  return typeof n === 'string' ? n : '';
}

function enterApp(choice, snap) {
  state.unlocked = true;
  ui.unlock.hidden = true;
  ui.app.hidden = false;
  ui.langSelect.innerHTML = state.index.languages
    .map((l) => `<option value="${esc(l.lang)}" lang="${esc(l.lang)}"${l.lang === choice.lang ? ' selected' : ''}>${esc(l.language)}</option>`)
    .join('');
  setLanguage(choice, snap);
  renderWho();
  if (!myName()) openDialog('welcome');
  startTimers();
  flush();
}

function setLanguage(choice, snap) {
  state.lang = choice.lang;
  state.langName = englishName(choice.lang, choice.language);
  store.set(localArea, K.lang, choice.lang);
  prepareSnapshot(snap);
  state.serverRows = [];
  state.info = new Map();
  deriveInfo();
  $('#lang-mark').textContent = choice.lang.split('-')[0].toUpperCase();
  const L = state.langName;
  $('#how-text').textContent =
    `Read the English and the ${L} the app shows now. If the ${L} is right, click “Looks good”. ` +
    `If not, type a better version — it saves when you click away from the box. Where there's no ${L} yet, write it. ` +
    'Everything saves as you go, and other reviewers see your work.';
  ui.search.placeholder = `Search English or ${L}`;
  $('#style-note').textContent = snap.styleNote || '';
  state.filter = 'unchecked';
  state.group = null;
  state.search = '';
  ui.search.value = '';
  rebuildList();
  loadRows();
}

ui.langSelect.addEventListener('change', async () => {
  commitFocusedBox();
  const choice = state.index.languages.find((l) => l.lang === ui.langSelect.value);
  if (!choice || choice.lang === state.lang) return;
  ui.list.innerHTML = '<p class="results">Loading…</p>';
  ui.more.innerHTML = '';
  try {
    const snap = await loadSnapshot(state.key, choice.file);
    setLanguage(choice, snap);
  } catch (err) {
    if (err instanceof WrongKey) { relock('Please type the password again.'); return; }
    ui.list.innerHTML = `<div class="empty"><p>${esc(`The ${englishName(choice.lang, choice.language)} text couldn't load. Check your internet connection and try again.`)}</p></div>`;
    ui.langSelect.value = state.lang;
  }
});

async function loadRows() {
  const lang = state.lang;
  state.lastRowsFetch = Date.now();
  try {
    const rows = await fetchAllRows(lang);
    if (lang !== state.lang) return;
    state.serverRows = rows;
    state.rowsError = false;
    // Rows we just sent may not be in this reply yet if it was already on its way.
    refreshDerived(null);
  } catch (err) {
    if (err instanceof AuthRejected) { onAuthError(err); return; }
    state.rowsError = true;
  }
  renderBanner();
}

function renderBanner() {
  ui.banner.hidden = !state.rowsError;
  ui.banner.textContent = state.rowsError
    ? "Can't reach the server just now, so other reviewers' work may be missing. Your changes are kept on this computer and will be saved."
    : '';
}

/** Recomputes status for some (or all) entries and updates what's on screen. */
function refreshDerived(keys) {
  if (!state.snap) return;
  deriveInfo(keys);
  const touched = keys || [...state.rendered.keys()];
  const items = new Set();
  for (const k of touched) {
    const el = state.rendered.get(k);
    if (el) patchEntry(el, state.entryByKey.get(k));
    const e = state.entryByKey.get(k);
    if (e) items.add(e.item);
  }
  for (const id of keys ? items : state.cards.keys()) patchCard(id);
  renderFilters();
  renderGroups();
  renderSaveState();
}

// ---------- Filters, groups, search ----------

const FILTERS = [
  { id: 'flagged', label: () => 'Check these first', test: (e) => e.flags.length > 0 },
  { id: 'unchecked', label: () => 'Not checked yet', test: (e) => infoOf(e.key).status === 'none' },
  { id: 'suggested', label: () => 'Has a suggestion', test: (e) => infoOf(e.key).status === 'suggest' },
  { id: 'missing', label: () => `Needs ${state.langName}`, test: (e) => !e.current.trim() },
  { id: 'all', label: () => 'All', test: () => true },
];

function inScope(e, q) {
  return (!state.group || e.group === state.group) && (!q || e.searchText.includes(q));
}

// Both lists are updated in place after the first draw, so keyboard focus stays where it was.
function renderFilters() {
  const q = fold(state.search.trim());
  const scoped = state.entries.filter((e) => inScope(e, q));
  if (ui.filters.querySelectorAll('[data-filter]').length !== FILTERS.length) {
    ui.filters.innerHTML =
      FILTERS.map((f) => `<button type="button" class="pill-btn" data-filter="${f.id}"><span class="lbl"></span><span class="n"></span></button>`).join('') +
      '<button type="button" class="text-btn" data-open-style>Style guide</button>';
  }
  for (const f of FILTERS) {
    const b = ui.filters.querySelector(`[data-filter="${f.id}"]`);
    b.setAttribute('aria-pressed', String(state.filter === f.id));
    b.querySelector('.lbl').textContent = f.label();
    b.querySelector('.n').textContent = String(scoped.filter(f.test).length);
  }
}

function renderGroups() {
  const counts = new Map();
  for (const e of state.entries) if (infoOf(e.key).status === 'none') counts.set(e.group, (counts.get(e.group) || 0) + 1);
  const total = [...counts.values()].reduce((a, b) => a + b, 0);
  const groups = [{ id: '', label: 'Everything', n: total }, ...(state.snap.groups || []).map((g) => ({ id: g.id, label: g.label, n: counts.get(g.id) || 0 }))];
  const sig = groups.map((g) => g.id).join('\n');
  if (ui.groupNav._sig !== sig) {
    ui.groupNav._sig = sig;
    ui.groupNav.innerHTML = groups
      .map((g) => `<button type="button" class="group-btn" data-group="${esc(g.id)}"><span>${esc(g.label)}</span><span class="group-count"></span></button>`)
      .join('');
  }
  groups.forEach((g, i) => {
    const b = ui.groupNav.children[i];
    b.setAttribute('aria-current', String((state.group || '') === g.id));
    b.querySelector('.group-count').textContent = g.n ? `${g.n} to check` : 'All checked';
  });
}

ui.filters.addEventListener('click', (ev) => {
  const b = ev.target.closest('button');
  if (!b) return;
  if (b.hasAttribute('data-open-style')) { openDialog('note'); return; }
  state.filter = b.getAttribute('data-filter');
  rebuildList();
});

ui.groupNav.addEventListener('click', (ev) => {
  const b = ev.target.closest('button[data-group]');
  if (!b) return;
  state.group = b.getAttribute('data-group') || null;
  rebuildList();
  ui.results.focus();
  ui.results.scrollIntoView({ block: 'start' });
});

let searchTimer = null;
ui.search.addEventListener('input', () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    state.search = ui.search.value;
    rebuildList();
  }, 200);
});

// ---------- The list ----------

const PAGE_ENTRIES = 60;
let moreObserver = null;

/** Works out which entries to show. The list then stays put while statuses change. */
function rebuildList() {
  commitFocusedBox();
  const q = fold(state.search.trim());
  const f = FILTERS.find((x) => x.id === state.filter) || FILTERS[1];
  state.visible = state.entries.filter((e) => inScope(e, q) && f.test(e));
  state.shown = 0;
  state.rendered = new Map();
  state.cards = new Map();
  ui.list.innerHTML = '';
  const n = state.visible.length;
  const where = state.group ? ` in ${state.groupLabel.get(state.group) || ''}` : '';
  ui.results.textContent = `${n} ${n === 1 ? 'piece' : 'pieces'} of text · ${f.label()}${where}${q ? ` · matching “${state.search.trim()}”` : ''}`;
  if (!n) {
    let msg;
    if (q) msg = `Nothing matches “${state.search.trim()}” here.`;
    else if (state.filter === 'unchecked') msg = 'Everything here has been checked. Thank you!';
    else msg = 'Nothing here right now.';
    ui.list.innerHTML = `<div class="empty"><p>${esc(msg)}</p>${state.filter !== 'all' ? '<button type="button" class="btn" data-show-all>Show all text</button>' : ''}</div>`;
  }
  renderFilters();
  renderGroups();
  showMore();
}

ui.list.addEventListener('click', (ev) => {
  if (ev.target.closest('[data-show-all]')) {
    state.filter = 'all';
    rebuildList();
  }
});

function showMore() {
  const end = Math.min(state.visible.length, state.shown + PAGE_ENTRIES);
  const fresh = [];
  for (let i = state.shown; i < end; i++) {
    const e = state.visible[i];
    let card = state.cards.get(e.item);
    // An item split across pages keeps adding to its card.
    if (!card || card !== ui.list.lastElementChild) {
      card = buildCard(e.item);
      state.cards.set(e.item, card);
      ui.list.appendChild(card);
    }
    const row = buildEntry(e, i);
    card.querySelector('.card-rows').appendChild(row);
    state.rendered.set(e.key, row);
    fresh.push(row);
  }
  state.shown = end;
  requestAnimationFrame(() => fresh.forEach((row) => row.querySelectorAll('textarea').forEach(grow)));
  renderMore();
}

function renderMore() {
  if (moreObserver) moreObserver.disconnect();
  const left = state.visible.length - state.shown;
  if (left <= 0) { ui.more.innerHTML = ''; return; }
  ui.more.innerHTML = `<button type="button" class="btn">Show more (${left} left)</button>`;
  const btn = ui.more.firstElementChild;
  btn.addEventListener('click', showMore);
  if ('IntersectionObserver' in window) {
    moreObserver = new IntersectionObserver((seen) => {
      if (seen.some((s) => s.isIntersecting)) showMore();
    }, { rootMargin: '600px 0px' });
    moreObserver.observe(btn);
  }
}

function buildCard(itemId) {
  const item = state.itemById.get(itemId) || { id: itemId, title: itemId };
  const card = document.createElement('section');
  card.className = 'card';
  card.setAttribute('data-item', itemId);
  const kicker = [state.groupLabel.get(item.group), item.subtitle].filter(Boolean).join(' · ');
  const L = state.langName;
  card.innerHTML = `
    <div class="card-head">
      <div class="card-head-main">
        ${kicker ? `<div class="card-kicker">${esc(kicker)}</div>` : ''}
        <h3 class="card-title">${esc(item.title)}</h3>
      </div>
      ${item.offered === false ? `<span class="badge">Not in ${esc(L)} yet</span>` : ''}
      <span class="card-count"></span>
    </div>
    <div class="col-heads" aria-hidden="true"><div>English</div><div>${esc(L)} now</div><div>Your ${esc(L)}</div></div>
    <div class="card-rows"></div>`;
  patchCard(itemId, card);
  return card;
}

function patchCard(itemId, card = state.cards.get(itemId)) {
  if (!card) return;
  const total = state.itemTotals.get(itemId) || 0;
  let checked = 0;
  for (const e of state.entries) if (e.item === itemId && infoOf(e.key).status !== 'none') checked++;
  card.querySelector('.card-count').textContent = `${checked} of ${total} checked`;
}

function buildEntry(e, i) {
  const L = state.langName;
  const lang = state.lang;
  const dir = dirFor(lang);
  const en = textHtml(e.en, e.markdown);
  const now = e.current.trim() ? textHtml(e.current, e.markdown) : null;
  const longText = e.en.length > 300 || e.en.split('\n').length > 6;
  const id = `e${i}`;
  const row = document.createElement('div');
  row.className = 'entry';
  row.setAttribute('data-key', e.key);
  row.innerHTML = `
    <div class="entry-top">
      <span class="chip">${esc(e.kind)}</span>
      <span class="status"></span>
      <span class="outcome" hidden></span>
      <span class="unsaved" hidden></span>
    </div>
    ${e.flags.length ? `<ul class="flags">${e.flags.map((f) => `<li>Check this first: ${esc(f)}</li>`).join('')}</ul>` : ''}
    <div class="cols">
      <div class="col col-en">
        <div class="col-label">English</div>
        <div class="text${en.plain ? ' plain' : ''}" lang="en">${en.html}</div>
        ${e.where ? `<p class="where">Where it appears: ${esc(e.where)}</p>` : ''}
      </div>
      <div class="col col-now">
        <div class="col-label">${esc(L)} now</div>
        ${now
          ? `<div class="text${now.plain ? ' plain' : ''}" lang="${esc(lang)}" dir="${dir}">${now.html}</div>`
          : `<div class="empty-now">No ${esc(L)} yet</div>`}
      </div>
      <div class="col col-box">
        <label class="col-label desk-hidden" for="${id}-box">Your ${esc(L)}</label>
        <textarea id="${id}-box" class="box" rows="3" maxlength="20000" lang="${esc(lang)}" dir="${dir}" spellcheck="true"
          placeholder="${esc(now ? 'Type a better version, or leave empty' : `Write the ${L} here`)}"></textarea>
        <ul class="warns" aria-live="polite"></ul>
        <p class="box-hint" aria-live="polite"></p>
        <p class="mine-outcome"></p>
        <div class="note-wrap" hidden>
          <label class="field-label" for="${id}-note">Note for Mark</label>
          <textarea id="${id}-note" class="box note-box" rows="2" maxlength="2000"></textarea>
        </div>
        <div class="failed" hidden></div>
        <div class="actions">
          <button type="button" class="btn btn-small ok-btn" aria-pressed="false"${now ? '' : ' disabled'}>Looks good</button>
          <button type="button" class="text-btn note-btn" aria-expanded="false">Add a note</button>
          ${longText ? '<button type="button" class="text-btn wide-btn" aria-expanded="false">Bigger box</button>' : ''}
        </div>
        <div class="others"></div>
      </div>
    </div>`;
  if (!now) row.querySelector('.ok-btn').title = `There's no ${L} to approve yet`;
  patchEntry(row, e);
  return row;
}

/** Updates the parts of a row that change with status. Leaves boxes alone while someone is typing in them. */
function patchEntry(row, e) {
  if (!row || !e) return;
  const info = infoOf(e.key);
  // Skip rows whose status hasn't changed (the list can hold all 1,500 rows).
  const sig = [info.status, info.by?.submission_id, info.reviewers, info.pending, info.failed?.row.submission_id,
    info.mine?.submission_id, info.others.map((o) => o.submission_id).join(',')].join('|');
  if (row._sig === sig) return;
  row._sig = sig;

  const status = row.querySelector('.status');
  status.className = `status s-${info.status}`;
  if (info.status === 'none') status.textContent = 'Not checked yet';
  else {
    const label = info.status === 'ok' ? 'Looks good' : 'Suggestion saved';
    const more = info.reviewers > 1 ? ` and ${info.reviewers - 1} more` : '';
    status.textContent = `${label} · ${info.by.reviewer || 'Someone'}, ${shortDate(info.by.client_at)}${more}`;
  }
  const outcome = row.querySelector('.outcome');
  const outcomeText = info.by ? outcomeOf(info.by) : '';
  outcome.hidden = !outcomeText;
  outcome.textContent = outcomeText;

  const unsaved = row.querySelector('.unsaved');
  unsaved.hidden = !info.pending;
  const sending = flushing && !lastSendFailed;
  unsaved.className = `unsaved${sending ? ' is-saving' : ''}`;
  unsaved.textContent = sending ? 'Saving…' : 'Not saved yet';

  const mine = info.mine;
  const box = row.querySelector('.box:not(.note-box)');
  const note = row.querySelector('.note-box');
  const wantBox = mine?.verdict === 'suggest' ? mine.suggested || '' : '';
  const wantNote = mine?.note || '';
  // Only overwrite a box that still shows what we last put there.
  if (document.activeElement !== box && box.value === (box._shown ?? '')) {
    box.value = wantBox;
    grow(box);
  }
  box._shown = wantBox;
  if (document.activeElement !== note && note.value === (note._shown ?? '')) note.value = wantNote;
  note._shown = wantNote;
  if (wantNote) {
    row.querySelector('.note-wrap').hidden = false;
    row.querySelector('.note-btn').hidden = true;
  }
  box.classList.toggle('has-text', box.value.trim() !== '');
  renderWarnings(row, e);

  const ok = row.querySelector('.ok-btn');
  ok.setAttribute('aria-pressed', String(mine?.verdict === 'ok'));
  ok.textContent = mine?.verdict === 'ok' ? '✓ Looks good' : 'Looks good';

  const mineOutcome = row.querySelector('.mine-outcome');
  mineOutcome.textContent = mine && mine.verdict === 'suggest' && outcomeOf(mine) ? `Your suggestion: ${outcomeOf(mine)}` : '';

  const failed = row.querySelector('.failed');
  failed.hidden = !info.failed;
  if (info.failed) {
    failed.innerHTML = `<span>${esc(`This change couldn't be saved (error ${info.failed.failed.status}). Please tell Mark.`)}</span>` +
      '<button type="button" class="btn btn-small retry-btn">Try again</button>';
  }

  const others = row.querySelector('.others');
  const dir = dirFor(state.lang);
  others.innerHTML = info.others
    .filter((r) => r.verdict === 'suggest' || r.note)
    .map((r) => {
      const who = esc(r.reviewer || 'Someone');
      const when = esc(shortDate(r.client_at));
      const oc = outcomeOf(r);
      const head = r.verdict === 'suggest'
        ? `<strong>${who}</strong> suggested (${when})${oc ? ` · ${esc(oc)}` : ''}:`
        : `<strong>${who}</strong> said it looks good (${when}).`;
      return `<div class="other" data-sid="${esc(r.submission_id)}">
        <p class="other-head">${head}</p>
        ${r.verdict === 'suggest' ? `<div class="other-text" lang="${esc(state.lang)}" dir="${dir}">${esc(r.suggested)}</div>` : ''}
        ${r.note ? `<p class="other-note">Note: ${esc(r.note)}</p>` : ''}
        ${r.verdict === 'suggest' ? `<button type="button" class="text-btn use-btn">Use this in my box</button>` : ''}
      </div>`;
    })
    .join('');
}

function renderWarnings(row, e) {
  const box = row.querySelector('.box:not(.note-box)');
  const warns = checkText(e, box.value);
  row.querySelector('.warns').innerHTML = warns.map((w) => `<li>${esc(w)}</li>`).join('');
}

function grow(t) {
  if (!t || !t.isConnected) return;
  t.style.height = 'auto';
  t.style.height = `${t.scrollHeight + 4}px`;
}

// ---------- Saving ----------

function save(e, verdict, suggested, note) {
  const name = myName();
  if (!name) { openDialog('welcome'); return false; }
  const row = {
    submission_id: uuid(),
    client_at: new Date().toISOString(),
    environment: ENV,
    lang: state.lang,
    entry_key: e.key,
    verdict,
    suggested: verdict === 'suggest' ? suggested : null,
    note: note?.trim() ? note.trim() : null,
    reviewer: name,
    reviewer_id: reviewerId(),
    seen_en: e.en,
    seen_current: e.current,
    snapshot: state.snap.id,
  };
  outbox.push(row);
  refreshDerived([e.key]);
  flush();
  return true;
}

function rowParts(row) {
  const e = state.entryByKey.get(row.getAttribute('data-key'));
  return {
    e,
    box: row.querySelector('.box:not(.note-box)'),
    note: row.querySelector('.note-box'),
    hint: row.querySelector('.box-hint'),
    okBtn: row.querySelector('.ok-btn'),
  };
}

/** Saves what's in the reviewer's box, if it's a real change. */
function commitBox(row) {
  const { e, box, note, hint } = rowParts(row);
  if (!e) return;
  const mine = infoOf(e.key).mine;
  const text = box.value.trim();
  const prev = mine?.verdict === 'suggest' ? (mine.suggested || '').trim() : '';
  hint.textContent = '';
  if (!text) {
    if (prev) hint.textContent = 'Your earlier suggestion is still saved. To go back to the current wording, click “Looks good”.';
    return;
  }
  if (text === prev) return;
  if (e.current.trim() && text === e.current.trim()) {
    hint.textContent = `That's the same as the ${state.langName} now. If it's right, click “Looks good”.`;
    return;
  }
  box._shown = text;
  box.value = text;
  save(e, 'suggest', text, note.value);
}

function commitFocusedBox() {
  const el = document.activeElement;
  if (el && el.classList?.contains('box') && !el.classList.contains('note-box')) {
    const row = el.closest('.entry');
    if (row) commitBox(row);
  }
}

ui.list.addEventListener('input', (ev) => {
  const t = ev.target;
  if (!(t instanceof HTMLTextAreaElement)) return;
  grow(t);
  const row = t.closest('.entry');
  if (!t.classList.contains('note-box')) {
    t.classList.toggle('has-text', t.value.trim() !== '');
    renderWarnings(row, state.entryByKey.get(row.getAttribute('data-key')));
  }
});

ui.list.addEventListener('focusout', (ev) => {
  const t = ev.target;
  if (!(t instanceof HTMLTextAreaElement)) return;
  const row = t.closest('.entry');
  if (!row) return;
  const { e, note } = rowParts(row);
  if (t === note) {
    const mine = infoOf(e.key).mine;
    const text = note.value.trim();
    if (text === (mine?.note || '').trim()) return;
    const hint = row.querySelector('.box-hint');
    if (!mine) {
      hint.textContent = 'Your note will be saved with your suggestion, or when you click “Looks good”.';
      return;
    }
    note._shown = text;
    save(e, mine.verdict, mine.suggested, text);
    return;
  }
  // Always save on leaving the box, even when the next stop is "Looks good":
  // keyboard users tab through it. A click on "Looks good" then saves a newer row.
  commitBox(row);
});

ui.list.addEventListener('click', (ev) => {
  const btn = ev.target.closest('button');
  const row = btn?.closest('.entry');
  if (!row) return;
  const { e, box, note, hint } = rowParts(row);
  if (btn.classList.contains('ok-btn')) {
    if (!e.current.trim()) return;
    const mine = infoOf(e.key).mine;
    if (mine?.verdict === 'ok' && (mine.note || '') === note.value.trim()) return;
    hint.textContent = '';
    box.value = '';
    box._shown = '';
    grow(box);
    save(e, 'ok', null, note.value);
  } else if (btn.classList.contains('note-btn')) {
    row.querySelector('.note-wrap').hidden = false;
    btn.hidden = true;
    note.focus();
  } else if (btn.classList.contains('wide-btn')) {
    const wide = row.classList.toggle('is-wide');
    btn.setAttribute('aria-expanded', String(wide));
    btn.textContent = wide ? 'Smaller box' : 'Bigger box';
    grow(box);
    box.focus();
  } else if (btn.classList.contains('use-btn')) {
    const sid = btn.closest('.other')?.getAttribute('data-sid');
    const r = infoOf(e.key).others.find((x) => x.submission_id === sid);
    if (r) {
      box.value = r.suggested || '';
      box.classList.add('has-text');
      grow(box);
      renderWarnings(row, e);
      box.focus();
      hint.textContent = 'Change it if you like. It saves when you click away from the box.';
    }
  } else if (btn.classList.contains('retry-btn')) {
    const list = outbox.read().map((o) => (o.row.entry_key === e.key && o.failed ? { row: o.row } : o));
    outbox.write(list);
    refreshDerived([e.key]);
    flush();
  }
});

// ---------- Save state in the header ----------

function renderSaveState() {
  const list = outbox.read();
  const pending = list.filter((o) => !o.failed).length;
  const failed = list.length - pending;
  const el = ui.saveState;
  if (!list.length) {
    el.className = 'save-state is-saved';
    el.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 6 9 17l-5-5"></path></svg>All changes saved';
  } else if (pending && flushing && !lastSendFailed) {
    el.className = 'save-state is-saving';
    el.textContent = `Saving… (${pending})`;
  } else if (pending) {
    el.className = 'save-state is-waiting';
    el.textContent = `Not saved yet — will retry (${pending})`;
  } else {
    el.className = 'save-state is-failed';
    el.textContent = `${failed} ${failed === 1 ? "change couldn't" : "changes couldn't"} be saved`;
  }
  // Keep each visible row's "Saving…" / "Not saved yet" line in step.
  for (const [k, row] of state.rendered) {
    const info = state.info.get(k);
    if (!info?.pending) continue;
    const u = row.querySelector('.unsaved');
    const sending = flushing && !lastSendFailed;
    u.className = `unsaved${sending ? ' is-saving' : ''}`;
    u.textContent = sending ? 'Saving…' : 'Not saved yet';
  }
}

// ---------- Name and style guide dialog ----------

function renderWho() {
  $('#who-name').textContent = myName() || '—';
}

let dialogMode = 'welcome';
function openDialog(mode) {
  dialogMode = mode;
  $('#welcome-title').textContent =
    mode === 'welcome' ? 'Welcome' : mode === 'name' ? 'Your name' : 'Style guide';
  $('#name-part').hidden = mode === 'note';
  $('#note-part').hidden = mode === 'name';
  $('#welcome-go').textContent = mode === 'welcome' ? 'Start reviewing' : mode === 'name' ? 'Save' : 'Close';
  $('#welcome-cancel').hidden = mode !== 'name';
  $('#name-input').value = myName();
  $('#name-error').textContent = '';
  if (!ui.dialog.open) ui.dialog.showModal();
  (mode === 'note' ? $('#welcome-go') : $('#name-input')).focus();
}

$('#welcome-form').addEventListener('submit', (ev) => {
  ev.preventDefault();
  if (dialogMode !== 'note') {
    const name = $('#name-input').value.trim().replace(/\s+/g, ' ');
    if (!name) {
      $('#name-error').textContent = 'Please type your first name and last initial.';
      $('#name-input').focus();
      return;
    }
    store.set(localArea, K.name, name);
    renderWho();
  }
  ui.dialog.close();
});

$('#welcome-cancel').addEventListener('click', () => ui.dialog.close());

ui.dialog.addEventListener('cancel', (ev) => {
  // Esc can't skip giving a name the first time.
  if (dialogMode === 'welcome' && !myName()) ev.preventDefault();
});

$('#change-name').addEventListener('click', () => openDialog('name'));
$('#style-link-side').addEventListener('click', () => openDialog('note'));

// ---------- Lock ----------

$('#lock-btn').addEventListener('click', () => {
  commitFocusedBox();
  clearSession();
  location.reload();
});

// ---------- Timers and wake-ups ----------

let timersStarted = false;
function startTimers() {
  if (timersStarted) return;
  timersStarted = true;
  setInterval(() => { if (outbox.read().some((o) => !o.failed)) flush(); }, 20_000);
  setInterval(() => { if (state.unlocked && !document.hidden) loadRows(); }, 60_000);
  window.addEventListener('online', () => { flush(); loadRows(); });
  window.addEventListener('focus', () => {
    if (!state.unlocked) return;
    flush();
    if (Date.now() - state.lastRowsFetch > 10_000) loadRows();
  });
  window.addEventListener('storage', (ev) => {
    if (ev.key === K.outbox && state.unlocked) refreshDerived(null);
    if (ev.key === K.session && ev.newValue === null && state.unlocked && !readStoredSession()) location.reload();
  });
}

// Typing in a box and then closing the tab still keeps the text.
document.addEventListener('visibilitychange', () => { if (document.hidden) commitFocusedBox(); });
window.addEventListener('pagehide', commitFocusedBox);

boot();
