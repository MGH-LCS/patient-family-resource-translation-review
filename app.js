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
  mode: 'tr-mode',
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
  rowsLoaded: false, // the first load of reviewers' rows for this language has come back
  mode: store.get(localArea, 'tr-mode') === 'table' ? 'table' : 'guided', // 'guided' | 'table'
  tableBuilt: false,
  entriesByItem: new Map(),
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
  state.entriesByItem = new Map();
  for (const e of state.entries) {
    state.itemTotals.set(e.item, (state.itemTotals.get(e.item) || 0) + 1);
    if (!state.entriesByItem.has(e.item)) state.entriesByItem.set(e.item, []);
    state.entriesByItem.get(e.item).push(e);
  }
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
  if (SUMMARY_KEY.test(entry.key) && text.trim().length > SUMMARY_MAX) {
    reasons.push(`Too long for the app's cards: ${text.trim().length} characters, ${SUMMARY_MAX} at most.`);
  }
  return reasons;
}

/** A resource's summary must fit the app's cards. */
const SUMMARY_KEY = /^res\/[^/]+\/description$/;
const SUMMARY_MAX = 150;

/** An AI draft is shown only where there's no translation yet. */
const draftOf = (e) => (!e.current.trim() && e.aiDraft ? e.aiDraft.trim() : '');
/** A saved suggestion that is the AI draft word for word. */
const approvesDraft = (e, row) => !!row && row.verdict === 'suggest' && !!draftOf(e) && (row.suggested || '').trim() === draftOf(e);

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
  layout: $('#layout'),
  guided: $('#guided'),
  modeBtn: $('#mode-btn'),
  skipLink: $('#skip-link'),
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
    `If not, type a better version — it saves when you click away from the box. Where there's no ${L} yet, ` +
    'check the AI draft and click “Use this draft”, then change what needs changing. ' +
    'Everything saves as you go, and other reviewers see your work.';
  ui.search.placeholder = `Search English or ${L}`;
  $('#style-note').textContent = snap.styleNote || '';
  state.filter = 'unchecked';
  state.group = null;
  state.search = '';
  ui.search.value = '';
  state.rowsLoaded = false;
  Object.assign(guided, { step: 'start', itemId: null, index: 0, editing: false, picking: false, pickQuery: '' });
  state.tableBuilt = false;
  setMode(state.mode);
  loadRows();
}

ui.langSelect.addEventListener('change', async () => {
  commitFocusedBox();
  commitGuided();
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
    state.rowsLoaded = true;
    // Rows we just sent may not be in this reply yet if it was already on its way.
    refreshDerived(null);
  } catch (err) {
    if (err instanceof AuthRejected) { onAuthError(err); return; }
    state.rowsError = true;
    guidedPatch();
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
  guidedPatch();
  pvSchedule();
}

// ---------- Filters, groups, search ----------

const FILTERS = [
  { id: 'flagged', label: () => 'Check these first', test: (e) => e.flags.length > 0 },
  { id: 'unchecked', label: () => 'Not checked yet', test: (e) => infoOf(e.key).status === 'none' },
  { id: 'suggested', label: () => 'Has a suggestion', test: (e) => infoOf(e.key).status === 'suggest' },
  { id: 'missing', label: () => `No ${state.langName} yet`, test: (e) => !e.current.trim() },
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
  pvReset();
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
          : draftOf(e)
            ? `<div class="ai-draft"><span class="badge badge-draft">AI draft · please check closely</span>
                <div class="text${textHtml(draftOf(e), e.markdown).plain ? ' plain' : ''}" lang="${esc(lang)}" dir="${dir}">${textHtml(draftOf(e), e.markdown).html}</div>
                <button type="button" class="text-btn draft-btn">Use this draft</button></div>`
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
    const label = info.status === 'ok' ? 'Looks good' : approvesDraft(e, info.by) ? 'AI draft approved' : 'Suggestion saved';
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
  } else if (btn.classList.contains('draft-btn')) {
    box.value = draftOf(e);
    box.classList.add('has-text');
    grow(box);
    renderWarnings(row, e);
    box.focus();
    hint.textContent = 'Change what needs changing. It saves when you click away from the box.';
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
  guidedRender();
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
  commitGuided();
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

// ---------------------------------------------------------------------------
// Phone preview: the resource or page you're working in, drawn the way the
// app draws it. The piece you're on is ringed; your changes are yellow.
// Everything goes through esc() or textHtml() (DOMPurify), like the list.
// ---------------------------------------------------------------------------

const PREVIEW_GROUPS = new Set(['resources', 'category_pages']);
const pv = {
  el: $('#preview'),
  screen: $('#pv-screen'),
  note: $('#pv-note'),
  openBtn: $('#pv-open'),
  view: 'mine', // 'now' | 'mine' | 'en'
  item: null,
  key: null,
  queued: false,
};

const ICONS = {
  phone: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M22 16.9v3a2 2 0 0 1-2.2 2 19.8 19.8 0 0 1-8.6-3.1 19.5 19.5 0 0 1-6-6A19.8 19.8 0 0 1 2.1 4.2 2 2 0 0 1 4.1 2h3a2 2 0 0 1 2 1.7c.1.9.4 1.8.7 2.7a2 2 0 0 1-.5 2.1L8 9.8a16 16 0 0 0 6 6l1.3-1.3a2 2 0 0 1 2.1-.4c.9.3 1.8.6 2.7.7a2 2 0 0 1 1.7 2z"/></svg>',
  mail: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 7-10 6L2 7"/></svg>',
  link: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7"/><path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7"/></svg>',
  play: '<svg width="22" height="22" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M8 5v14l11-7z"/></svg>',
  doc: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg>',
  box: '<span class="pv-tick" aria-hidden="true"></span>',
};

/** The reviewer's own text for a piece: what's in their box now, else their saved suggestion. */
function myText(e) {
  const box = state.mode === 'guided'
    ? (guided.editing && pv.key === e.key ? ui.guided.querySelector('.g-box') : null)
    : state.rendered.get(e.key)?.querySelector('.box:not(.note-box)');
  const typed = box?.value.trim();
  if (typed) return typed;
  const mine = infoOf(e.key).mine;
  return mine?.verdict === 'suggest' ? (mine.suggested || '').trim() : '';
}

/** Which tokens of `after` are new compared with `before` (word level). */
function addedTokens(before, after) {
  const a = before.split(/(\s+)/).filter(Boolean);
  const b = after.split(/(\s+)/).filter(Boolean);
  if (a.length * b.length > 400000) return b.map((t) => ({ t, added: true }));
  const L = Array.from({ length: a.length + 1 }, () => new Uint32Array(b.length + 1));
  for (let i = a.length - 1; i >= 0; i--) {
    for (let j = b.length - 1; j >= 0; j--) L[i][j] = a[i] === b[j] ? L[i + 1][j + 1] + 1 : Math.max(L[i + 1][j], L[i][j + 1]);
  }
  const out = [];
  let i = 0;
  let j = 0;
  while (j < b.length) {
    if (i < a.length && a[i] === b[j]) { out.push({ t: b[j], added: false }); i++; j++; }
    else if (i < a.length && L[i + 1][j] >= L[i][j + 1]) i++;
    else { out.push({ t: b[j], added: true }); j++; }
  }
  return out;
}

const MARK_OPEN = '';
const MARK_CLOSE = '';

/** `after` rendered with the words that differ from `before` in yellow. */
function changedHtml(before, after, markdown) {
  // In markdown only plain words are marked, so the markers never land inside link or emphasis syntax.
  const plainWord = /^[^\s[\]()*_#`<>|~\\!]+$/;
  const text = addedTokens(before, after)
    .map(({ t, added }) => (added && /\S/.test(t) && (!markdown || plainWord.test(t)) ? MARK_OPEN + t + MARK_CLOSE : t))
    .join('');
  return textHtml(text, markdown).html.split(MARK_OPEN).join('<mark>').split(MARK_CLOSE).join('</mark>');
}

/** One reviewable piece, in the view chosen. */
function pvPiece(e, tag = 'div', cls = '') {
  if (!e) return '';
  let html;
  let fallback = false;
  let isDraft = false;
  let lang = state.lang;
  const now = e.current.trim() ? e.current : '';
  // "With my changes" shows AI drafts (dashed) where there's no translation; "Now" shows what the app shows today.
  const base = now || (pv.view === 'mine' ? draftOf(e) : '');
  if (pv.view === 'en') {
    html = textHtml(e.en, e.markdown).html;
    lang = 'en';
  } else {
    const mine = pv.view === 'mine' ? myText(e) : '';
    if (mine && mine !== base) html = changedHtml(base, mine, e.markdown);
    else if (base) {
      html = textHtml(base, e.markdown).html;
      isDraft = !now;
    } else {
      html = textHtml(e.en, e.markdown).html; // the app falls back to English
      fallback = true;
      lang = 'en';
    }
  }
  if (!html) return '';
  const classes = ['pv-piece', cls, fallback ? 'pv-fallback' : '', isDraft ? 'pv-draft' : '', e.key === pv.key ? 'pv-ring' : ''].filter(Boolean).join(' ');
  return `<${tag} class="${classes}" data-key="${esc(e.key)}" lang="${esc(lang)}" dir="${lang === 'en' ? 'ltr' : dirFor(lang)}">${html}</${tag}>`;
}

/** Entries grouped by the block they belong to, in order. */
function pvBlocks(list) {
  const blocks = [];
  for (const e of list) {
    const id = e.block || e.key;
    const last = blocks[blocks.length - 1];
    if (last && last.id === id) last.list.push(e);
    else blocks.push({ id, type: e.blockType || '', list: [e] });
  }
  return blocks;
}

/** Sub-items of a block (`cards/<id>/…`, `groups/<id>/…`) in order, each a list of its fields. */
function pvSubItems(list, prefix) {
  const groups = new Map();
  for (const e of list) {
    const m = new RegExp(`^${prefix}/([^/]+)/(.+)$`).exec(e.field || '');
    if (!m) continue;
    if (!groups.has(m[1])) groups.set(m[1], []);
    groups.get(m[1]).push({ ...e, sub: m[2] });
  }
  return [...groups.values()];
}

function pvBlock(block, tint) {
  const by = (name) => block.list.find((e) => e.field === name);
  const P = pvPiece;
  // Colours go in data attributes and are applied from script: the page's CSP forbids inline style attributes.
  const band = `data-bar="${esc(tint.bar)}" data-band="${esc(tint.band)}"`;
  switch (block.type) {
    case 'text':
      return P(by('markdown'), 'div', 'pv-text');
    case 'section':
      return `<div class="pv-band" ${band}>${P(by('title'), 'div', 'pv-band-title')}</div>` +
        (by('chipLabel') ? `<div class="pv-chiprow">${P(by('chipLabel'), 'span', 'pv-chip')}</div>` : '') +
        P(by('intro'), 'div', 'pv-text');
    case 'video':
      return `<div class="pv-media"><span class="pv-play">${ICONS.play}</span></div>${P(by('caption'), 'div', 'pv-caption')}`;
    case 'image':
      return `<div class="pv-media pv-image">${by('alt') ? `<span class="pv-alt-label">Read aloud:</span>${P(by('alt'), 'span', 'pv-alt')}` : ''}</div>${P(by('caption'), 'div', 'pv-caption')}`;
    case 'pdf':
      return `<div class="pv-row"><span class="pv-icon">${ICONS.doc}</span>${P(by('label'), 'div', 'pv-link')}</div>`;
    case 'link':
      return `<div class="pv-row"><span class="pv-icon">${ICONS.link}</span><div class="pv-row-body">${P(by('label'), 'div', 'pv-link')}${P(by('description'), 'div', 'pv-sub')}${P(by('url'), 'div', 'pv-url')}</div></div>`;
    case 'phone':
    case 'email':
      return `<div class="pv-row"><span class="pv-icon">${block.type === 'phone' ? ICONS.phone : ICONS.mail}</span><div class="pv-row-body">${P(by('label'), 'div', 'pv-link')}${P(by('description'), 'div', 'pv-sub')}</div></div>`;
    case 'listing': {
      const sub = (prefix, icon) => pvSubItems(block.list, prefix)
        .map((fields) => `<div class="pv-row pv-row-tight"><span class="pv-icon">${icon}</span><div class="pv-row-body">${fields.map((f) => P(f, 'div', f.sub === 'url' ? 'pv-url' : 'pv-link')).join('')}</div></div>`)
        .join('');
      return `<div class="pv-card">${P(by('name'), 'div', 'pv-card-title')}` +
        `${by('address') || by('distance') ? `<div class="pv-sub">${P(by('address'), 'span')}${by('address') && by('distance') ? ' · ' : ''}${P(by('distance'), 'span')}</div>` : ''}` +
        `${P(by('notes'), 'div', 'pv-text pv-small')}${sub('phones', ICONS.phone)}${sub('emails', ICONS.mail)}${sub('links', ICONS.link)}${P(by('details'), 'div', 'pv-text pv-small')}</div>`;
    }
    case 'checklist': {
      const groups = pvSubItems(block.list, 'groups')
        .map((fields) => fields.map((f) => (f.sub === 'title' ? P(f, 'div', 'pv-check-group') : `<div class="pv-check">${ICONS.box}${P(f, 'span')}</div>`)).join(''))
        .join('');
      return `<div class="pv-card">${P(by('title'), 'div', 'pv-card-title')}${P(by('subtitle'), 'div', 'pv-sub')}${groups}</div>`;
    }
    case 'hero':
      return `<div class="pv-hero">${P(by('eyebrow'), 'div', 'pv-eyebrow')}${P(by('headline'), 'div', 'pv-headline')}${P(by('body'), 'div', 'pv-text')}</div>`;
    case 'callout':
      return `<div class="pv-callout">${P(by('title'), 'div', 'pv-card-title')}${P(by('body'), 'div', 'pv-text')}</div>`;
    case 'infoCards': {
      const cards = pvSubItems(block.list, 'cards')
        .map((fields) => {
          const f = (name) => fields.find((x) => x.sub === name);
          return `<div class="pv-info">${P(f('title'), 'div', 'pv-card-title')}${P(f('subtitle'), 'div', 'pv-sub')}${P(f('body'), 'div', 'pv-text pv-small')}${P(f('meta'), 'div', 'pv-sub')}${P(f('link/label'), 'div', 'pv-link')}</div>`;
        })
        .join('');
      return `${P(by('title'), 'div', 'pv-cards-title')}${cards}`;
    }
    case 'subcategory':
      return `<div class="pv-card pv-subcat"><div class="pv-row-body">${P(by('title'), 'div', 'pv-card-title')}${P(by('description'), 'div', 'pv-sub')}</div><span aria-hidden="true">›</span></div>`;
    default:
      return block.list.map((e) => P(e, 'div', 'pv-text')).join('');
  }
}

function pvRender() {
  pv.queued = false;
  if (!state.snap) return;
  for (const b of document.querySelectorAll('[data-view]')) b.setAttribute('aria-pressed', String(b.getAttribute('data-view') === pv.view));
  if (!pv.screen.isConnected) return;
  const item = state.itemById.get(pv.item);
  if (!item || !PREVIEW_GROUPS.has(item.group)) {
    pv.screen.innerHTML = `<div class="pv-empty">${esc(item ? 'There’s no phone picture for this part. “Where it appears” under the English says where it is in the app.' : 'Click a piece of text in a resource or a category page to see it here as families do.')}</div>`;
    pv.note.textContent = '';
    return;
  }
  const tint = item.tint || { bar: '#01828E', band: '#E6EFF6' };
  const list = state.entries.filter((e) => e.item === item.id);
  const scrollTop = pv.screen.scrollTop;
  let html = '';
  if (item.group === 'resources') {
    const title = list.find((e) => /\/title$/.test(e.key) && !e.block);
    const summary = list.find((e) => /\/description$/.test(e.key) && !e.block);
    if (summary) html += `<div class="pv-listcard"><div class="pv-listcard-label">In a list</div>${pvPiece(title, 'div', 'pv-card-title')}${pvPiece(summary, 'div', 'pv-sub')}</div>`;
    html += `<div class="pv-sheet"><div class="pv-grabber"></div>${pvPiece(title, 'h3', 'pv-apptitle')}`;
    html += pvBlocks(list.filter((e) => e.block)).map((b) => pvBlock(b, tint)).join('');
    html += '</div>';
  } else {
    const [unit, cat] = item.id.split('/').slice(1);
    const name = state.entryByKey.get(`units/${unit}/rcat/${cat}/label`);
    html += `<div class="pv-sheet pv-page">${name ? pvPiece(name, 'h3', 'pv-apptitle') : `<h3 class="pv-apptitle">${esc(item.title)}</h3>`}`;
    html += pvBlocks(list).map((b) => pvBlock(b, tint)).join('');
    html += '</div>';
  }
  pv.screen.innerHTML = html;
  const hex = /^#[0-9a-f]{6}$/i;
  for (const el of pv.screen.querySelectorAll('.pv-band')) {
    const bar = el.getAttribute('data-bar');
    const bg = el.getAttribute('data-band');
    if (hex.test(bar)) el.style.setProperty('--bar', bar);
    if (hex.test(bg)) el.style.setProperty('--band', bg);
  }
  pv.screen.scrollTop = scrollTop;
  const ring = pv.screen.querySelector('.pv-ring');
  if (ring) {
    const top = ring.offsetTop - pv.screen.offsetTop;
    if (top < pv.screen.scrollTop || top > pv.screen.scrollTop + pv.screen.clientHeight - 60) pv.screen.scrollTop = Math.max(0, top - 80);
  }
  pv.note.textContent = pv.view === 'en'
    ? 'The English version. Drawn like the app; small details may differ.'
    : `${pv.view === 'mine' ? 'Yellow = your changes. Dashed = AI draft, not yet checked. ' : ''}Grey = no ${state.langName} yet, so the app shows the English. Drawn like the app; small details may differ.`;
}

function pvSchedule() {
  if (pv.queued) return;
  pv.queued = true;
  requestAnimationFrame(pvRender);
}

/** Follow the card at the top of the screen while nothing in the list has focus. */
function pvFollowScroll() {
  if (state.mode !== 'table' || ui.list.contains(document.activeElement)) return;
  const cards = ui.list.querySelectorAll('.card[data-item]');
  for (const card of cards) {
    if (card.getBoundingClientRect().bottom > 140) {
      const id = card.getAttribute('data-item');
      if (id !== pv.item) { pv.item = id; pv.key = null; pvSchedule(); }
      return;
    }
  }
}

let pvScrollQueued = false;
window.addEventListener('scroll', () => {
  if (pvScrollQueued || !state.unlocked) return;
  pvScrollQueued = true;
  requestAnimationFrame(() => { pvScrollQueued = false; pvFollowScroll(); });
}, { passive: true });

ui.list.addEventListener('focusin', (ev) => {
  const row = ev.target.closest('.entry');
  if (!row) return;
  const e = state.entryByKey.get(row.getAttribute('data-key'));
  if (!e) return;
  pv.item = e.item;
  pv.key = e.key;
  pvSchedule();
});

ui.list.addEventListener('input', (ev) => {
  const row = ev.target.closest?.('.entry');
  const e = row && state.entryByKey.get(row.getAttribute('data-key'));
  if (e && e.item === pv.item) pvSchedule();
});

pv.el.addEventListener('click', (ev) => {
  const view = ev.target.closest('[data-view]')?.getAttribute('data-view');
  if (view) { pv.view = view; pvSchedule(); return; }
  if (ev.target.closest('#pv-close')) { pv.el.classList.remove('is-open'); pv.openBtn.focus(); return; }
  // A tap on a piece jumps to its row in the list.
  const key = ev.target.closest('.pv-piece')?.getAttribute('data-key');
  const row = key && state.rendered.get(key);
  if (row) {
    pv.el.classList.remove('is-open');
    row.scrollIntoView({ block: 'center', behavior: 'smooth' });
    row.querySelector('.box:not(.note-box)')?.focus({ preventScroll: true });
  }
});

pv.openBtn.addEventListener('click', () => {
  commitFocusedBox();
  pv.el.classList.add('is-open');
  pvRender();
  $('#pv-close').focus();
});

document.addEventListener('keydown', (ev) => {
  if (ev.key === 'Escape' && pv.el.classList.contains('is-open')) { pv.el.classList.remove('is-open'); pv.openBtn.focus(); }
});

/** Called when the list is rebuilt or the language changes. */
function pvReset() {
  if (state.mode !== 'table') return;
  pv.screen = $('#pv-screen');
  pv.note = $('#pv-note');
  pv.key = null;
  pv.item = null;
  pv.openBtn.hidden = false;
  requestAnimationFrame(() => { pvFollowScroll(); pvSchedule(); });
}

// Typing in a box and then closing the tab still keeps the text.
document.addEventListener('visibilitychange', () => { if (document.hidden) { commitFocusedBox(); commitGuided(); } });
window.addEventListener('pagehide', () => { commitFocusedBox(); commitGuided(); });

// ---------------------------------------------------------------------------
// Guided review: one resource (or part of the app) at a time — start screen,
// read it through, each piece in turn, done. The table ("Show me
// everything") stays for anyone who wants it all at once.
// ---------------------------------------------------------------------------

/** Resources first (most of the work, easiest with the phone picture), app buttons near the end. */
const GUIDED_GROUPS = ['resources', 'category_pages', 'essentials', 'tour', 'phase_cards', 'names', 'app', 'feedback'];
/** Someone else saved to an item this recently: they're probably still on it. */
const RECENT_MS = 2 * 60 * 60 * 1000;

const guided = { step: 'start', itemId: null, index: 0, editing: false, picking: false, pickQuery: '' };
let guidedHtml = '';

// Pieces this reviewer chose to skip stay "not checked" for everyone else, but aren't offered to them again.
const skippedKey = () => `tr-skipped:${ENV}:${state.lang}`;
function skippedSet() {
  const v = store.get(localArea, skippedKey());
  return new Set(Array.isArray(v) ? v : []);
}
function setSkipped(key, on) {
  const s = skippedSet();
  if (on === s.has(key)) return;
  if (on) s.add(key);
  else s.delete(key);
  store.set(localArea, skippedKey(), [...s]);
}

function setMode(mode) {
  commitFocusedBox();
  commitGuided();
  state.mode = mode;
  store.set(localArea, K.mode, mode);
  const isGuided = mode === 'guided';
  ui.guided.hidden = !isGuided;
  ui.layout.hidden = isGuided;
  ui.modeBtn.textContent = isGuided ? 'Show me everything' : 'Back to guided review';
  ui.skipLink.setAttribute('href', isGuided ? '#guided' : '#results');
  if (isGuided) {
    pv.el.classList.remove('is-open');
    pv.openBtn.hidden = true;
    guidedHtml = '';
    guidedRender();
  } else if (!state.tableBuilt) {
    state.tableBuilt = true;
    rebuildList();
  } else {
    pvReset();
  }
}

ui.modeBtn.addEventListener('click', () => {
  setMode(state.mode === 'guided' ? 'table' : 'guided');
  (state.mode === 'guided' ? ui.guided : ui.results).focus();
});

function guidedItems() {
  const rank = (item) => {
    const r = GUIDED_GROUPS.indexOf(item.group);
    return r === -1 ? GUIDED_GROUPS.length : r;
  };
  return state.snap.items
    .map((item, order) => ({ item, order }))
    .sort((a, b) => rank(a.item) - rank(b.item) || a.order - b.order)
    .map((x) => x.item);
}

function itemProgress(itemId) {
  const list = state.entriesByItem.get(itemId) || [];
  const skipped = skippedSet();
  const now = Date.now();
  const p = { total: list.length, open: 0, openForMe: 0, touched: false, mine: false, recentOther: false, drafts: 0 };
  for (const e of list) {
    const info = infoOf(e.key);
    if (draftOf(e)) p.drafts++;
    if (info.status === 'none') {
      p.open++;
      if (!skipped.has(e.key)) p.openForMe++;
    } else p.touched = true;
    if (info.mine) p.mine = true;
    if (info.others.some((r) => now - timeOf(r.created_at || r.client_at) < RECENT_MS)) p.recentOther = true;
  }
  return p;
}

/**
 * The next item for this reviewer: one they started themselves, else one
 * nobody has touched, else one others left partly done, else (only when
 * nothing else is left) one someone else is working on now. A random pick
 * among the first three, so two people starting together rarely collide.
 */
function pickNext(exclude) {
  const tiers = [[], [], [], []];
  for (const item of guidedItems()) {
    if (item.id === exclude) continue;
    const p = itemProgress(item.id);
    if (p.openForMe === 0) continue;
    tiers[p.mine ? 0 : p.recentOther ? 3 : p.touched ? 2 : 1].push(item.id);
  }
  const tier = tiers.find((t) => t.length) || [];
  if (tier === tiers[0]) return tier[0] || null;
  const first = tier.slice(0, 3);
  return first.length ? first[Math.floor(Math.random() * first.length)] : null;
}

const itemNoun = (item) => (item.group === 'resources' ? 'resource' : item.group === 'category_pages' ? 'category page' : 'part of the app');
const hasPhone = (item) => PREVIEW_GROUPS.has(item.group);
const firstOpenIndex = (list) => {
  const skipped = skippedSet();
  const i = list.findIndex((e) => infoOf(e.key).status === 'none' && !skipped.has(e.key));
  return i === -1 ? 0 : i;
};

function stepsHtml(n) {
  const s = (i, label) => `<span class="g-step${n === i ? ' is-on' : ''}"${n === i ? ' aria-current="step"' : ''}>${i} · ${label}</span>`;
  return `<div class="g-steps">${s(1, 'Read it through')}<span class="g-arrow" aria-hidden="true">→</span>${s(2, 'Check each piece')}</div>`;
}

function phoneColHtml() {
  return `<div class="g-phone-col">
    <div class="pv-views" role="group" aria-label="Which text to show">
      <button type="button" data-view="now" aria-pressed="false">Now</button>
      <button type="button" data-view="mine" aria-pressed="true">With my changes</button>
      <button type="button" data-view="en" aria-pressed="false">English</button>
    </div>
    <div class="pv-phone"><div id="g-screen" class="pv-screen"></div></div>
    <p id="g-note" class="pv-note"></p>
  </div>`;
}

function startHtml() {
  const name = myName();
  const L = state.langName;
  const item = state.itemById.get(guided.itemId);
  const checkedByMe = state.entries.filter((e) => infoOf(e.key).mine).length;
  let card;
  if (!item) {
    card = `<section class="g-card"><h2 class="g-card-title">Everything has been checked</h2>
      <p>Thank you! There's nothing left to check right now. You can still look through all the text.</p>
      <button type="button" class="btn btn-primary g-big" data-g="table">Show me everything</button></section>`;
  } else {
    const p = itemProgress(item.id);
    const kicker = item.group === 'resources' ? 'Your next resource' : `Next: ${state.groupLabel.get(item.group) || ''}`;
    const sub = [item.group === 'resources' ? item.subtitle : state.groupLabel.get(item.group), `${p.total} short ${p.total === 1 ? 'piece' : 'pieces'}`]
      .filter(Boolean).join(' · ');
    card = `<section class="g-card">
      <div class="g-kicker">${esc(kicker)}</div>
      <div class="g-title-row"><span class="g-bar"${item.tint ? ` data-bar="${esc(item.tint.bar)}"` : ''}></span>
        <div><h2 class="g-card-title">${esc(item.title)}</h2><div class="g-sub">${esc(sub)}</div></div></div>
      ${p.touched && p.open < p.total ? `<p class="g-meta">${p.mine ? 'You started this one' : 'Someone started this one'}: ${p.openForMe} of ${p.total} pieces still to check.</p>` : ''}
      ${p.drafts ? `<p class="g-draftnote">${p.drafts} ${p.drafts === 1 ? 'piece is an' : 'pieces are'} <strong>AI ${p.drafts === 1 ? 'draft' : 'drafts'}</strong>: a computer wrote ${p.drafts === 1 ? 'it' : 'them'} and no person has checked ${p.drafts === 1 ? 'it' : 'them'} yet. They have a dashed outline. Please read those closely.</p>` : ''}
      <button type="button" class="btn btn-primary g-big" data-g="start">Start</button>
    </section>`;
  }
  return `<div class="g-wrap g-narrow">
    <h1 class="g-hello" tabindex="-1">${name ? `Hello, ${esc(name)}` : 'Welcome'}</h1>
    <p class="g-lead">Thank you for helping families read the app in ${esc(L)}. We'll go one ${item ? esc(itemNoun(item)) : 'resource'} at a time. Stop whenever you like; your work is saved as you go.</p>
    ${card}
    <div class="g-links">
      <span>${checkedByMe ? `You've checked ${checkedByMe} ${checkedByMe === 1 ? 'piece' : 'pieces'} so far.` : 'Nothing checked yet.'}</span>
      <button type="button" class="link-btn" data-g="style">How to write for families</button>
      <button type="button" class="link-btn" data-g="pick" aria-expanded="${guided.picking}">Pick a different one</button>
      <button type="button" class="link-btn" data-g="table">Show me everything</button>
    </div>
    ${guided.picking ? pickHtml() : ''}
  </div>`;
}

function pickListItems() {
  const q = fold(guided.pickQuery.trim());
  return guidedItems()
    .filter((i) => i.id !== guided.itemId && (!q || fold(i.title).includes(q)))
    .map((i) => ({ i, p: itemProgress(i.id) }))
    .filter(({ p }) => p.open > 0)
    .slice(0, 40)
    .map(({ i, p }) => `<li><button type="button" class="g-pick-item" data-g="pick-item" data-item="${esc(i.id)}">
      <span>${esc(i.title)}</span><span class="g-pick-meta">${esc(state.groupLabel.get(i.group) || '')} · ${p.open} to check</span></button></li>`)
    .join('') || '<li class="g-pick-none">Nothing matches.</li>';
}

function pickHtml() {
  return `<section class="g-pick" aria-label="Pick a different one">
    <label class="search"><span class="sr-only">Find a resource or part of the app</span>
      <input class="g-pick-search" type="search" autocomplete="off" placeholder="Find a resource or part of the app" value="${esc(guided.pickQuery)}"></label>
    <ul class="g-pick-list">${pickListItems()}</ul>
  </section>`;
}

function readHtml(item, list) {
  const L = state.langName;
  const lang = state.lang;
  const dir = dirFor(lang);
  const drafts = list.filter((e) => draftOf(e)).length;
  const body = hasPhone(item)
    ? `<p>This is how it looks in the app, in ${esc(L)}. Read it through once. Does it sound natural? Is anything confusing?</p>`
    : `<p>These are the words families see in this part of the app. Read them through once. Do they sound natural? Is anything confusing?</p>`;
  const reading = hasPhone(item) ? '' : `<div class="g-reading">${list.map((e) => {
    const text = e.current.trim() || draftOf(e);
    const html = text ? textHtml(text, e.markdown) : null;
    return `<div class="g-readrow">
      <div class="g-readkind">${esc(e.kind)}${e.where ? ` · ${esc(e.where)}` : ''}</div>
      ${html ? `<div class="text${html.plain ? ' plain' : ''}${e.current.trim() ? '' : ' g-is-draft'}" lang="${esc(lang)}" dir="${dir}">${html.html}</div>` : `<div class="empty-now">No ${esc(L)} yet</div>`}
      <div class="g-readen" lang="en">English: ${esc(e.en)}</div>
    </div>`;
  }).join('')}</div>`;
  return `<div class="g-wrap">
    ${stepsHtml(1)}
    <div class="g-split">
      <div class="g-main">
        <div class="g-kicker">${esc(item.title)}</div>
        <h1 class="g-h1" tabindex="-1">Read it the way a family would</h1>
        ${body}
        ${drafts ? `<p>Pieces with a <span class="g-dashed">dashed outline</span> are AI drafts that nobody has checked yet.</p>` : ''}
        <p>You don't need to fix anything here; next you'll go through it piece by piece.</p>
        ${reading}
        <div class="g-actions">
          <button type="button" class="btn btn-primary g-big" data-g="read-next">Next: check each piece →</button>
          <button type="button" class="link-btn" data-g="back">Back</button>
        </div>
      </div>
      ${hasPhone(item) ? phoneColHtml() : ''}
    </div>
  </div>`;
}

function pieceHtml(item, list) {
  const e = list[guided.index];
  const L = state.langName;
  const lang = state.lang;
  const dir = dirFor(lang);
  const info = infoOf(e.key);
  const en = textHtml(e.en, e.markdown);
  const now = e.current.trim() ? textHtml(e.current, e.markdown) : null;
  const draft = draftOf(e);
  const draftHtml = draft ? textHtml(draft, e.markdown) : null;
  const editing = guided.editing || (!now && !draft);
  const mine = info.mine;
  const prefill = mine?.verdict === 'suggest' && !approvesDraft(e, mine) ? mine.suggested || '' : draft || e.current;
  const isSummary = SUMMARY_KEY.test(e.key);
  return `<div class="g-wrap">
    ${stepsHtml(2)}
    <div class="g-progress"><progress max="${list.length}" value="${guided.index + 1}"></progress><span>Piece ${guided.index + 1} of ${list.length}</span></div>
    <div class="g-split">
      <div class="g-main">
        <section class="g-piece">
          <div class="g-piece-head"><span class="chip">${esc(e.kind)}</span>${hasPhone(item) ? '<span class="g-ringed">ringed on the phone</span>' : ''}</div>
          ${e.where ? `<p class="where">Where it appears: ${esc(e.where)}</p>` : ''}
          ${e.flags.length ? `<ul class="flags">${e.flags.map((f) => `<li>Check this first: ${esc(f)}</li>`).join('')}</ul>` : ''}
          <div class="g-block">
            <div class="col-label">English</div>
            <div class="text g-big-text${en.plain ? ' plain' : ''}" lang="en">${en.html}</div>
          </div>
          <div class="g-block">
            <div class="g-label-row"><span class="col-label">${esc(L)}</span>${!now && draft ? '<span class="badge badge-draft">AI draft · please check closely</span>' : ''}</div>
            ${now
              ? `<div class="text g-big-text${now.plain ? ' plain' : ''}" lang="${esc(lang)}" dir="${dir}">${now.html}</div>`
              : draftHtml
                ? `<div class="text g-big-text g-is-draft${draftHtml.plain ? ' plain' : ''}" lang="${esc(lang)}" dir="${dir}">${draftHtml.html}</div>`
                : `<div class="empty-now">No ${esc(L)} yet. Please write it below.</div>`}
          </div>
          <p class="g-status" aria-live="polite"></p>
          ${editing ? `<div class="g-edit">
            <label class="field-label" for="g-box">${now || draft ? 'Your version' : `Your ${esc(L)}`}</label>
            <textarea id="g-box" class="box g-box has-text" rows="3" maxlength="20000" lang="${esc(lang)}" dir="${dir}" spellcheck="true">${esc(prefill)}</textarea>
            ${isSummary ? '<p class="g-counter" aria-live="polite"></p>' : ''}
            <ul class="warns" aria-live="polite"></ul>
          </div>` : ''}
          <label class="sr-only" for="g-note">Note for Mark (optional)</label>
          <input id="g-note" class="input g-note" maxlength="2000" placeholder="Note for Mark (optional)" value="${esc(mine?.note || '')}">
          <p class="g-hint" aria-live="polite"></p>
          <div class="g-actions">
            ${editing
              ? `<button type="button" class="btn btn-primary g-big" data-g="save">Save my version and go on</button>
                 ${now || draft ? '<button type="button" class="btn" data-g="cancel">Cancel</button>' : ''}`
              : `<button type="button" class="btn btn-primary g-big" data-g="ok">Looks right</button>
                 <button type="button" class="btn g-big" data-g="edit">Suggest a change</button>`}
            <span class="g-spacer"></span>
            <button type="button" class="link-btn" data-g="prev">← Previous</button>
            <button type="button" class="link-btn" data-g="skip">Skip for now</button>
          </div>
        </section>
      </div>
      ${hasPhone(item) ? phoneColHtml() : ''}
    </div>
  </div>`;
}

function doneHtml(item, list) {
  const name = myName();
  let right = 0;
  let changes = 0;
  let skipped = 0;
  const skippedKeys = skippedSet();
  for (const e of list) {
    const mine = infoOf(e.key).mine;
    if (mine?.verdict === 'ok' || approvesDraft(e, mine)) right++;
    else if (mine?.verdict === 'suggest') changes++;
    else if (skippedKeys.has(e.key)) skipped++;
  }
  const parts = [];
  if (right) parts.push(`${right} looked right`);
  if (changes) parts.push(`your ${changes === 1 ? 'change is' : `${changes} changes are`} on the way to Mark`);
  if (skipped) parts.push(`${skipped} skipped for now`);
  const next = pickNext(item.id);
  return `<div class="g-wrap g-narrow g-center">
    <div class="g-tick" aria-hidden="true">✓</div>
    <h1 class="g-hello" tabindex="-1">Done. Thank you${name ? `, ${esc(name)}` : ''}.</h1>
    <p class="g-lead">You went through all ${list.length} ${list.length === 1 ? 'piece' : 'pieces'} of <strong>${esc(item.title)}</strong>.${parts.length ? ` ${esc(parts.join(', ').replace(/^./, (c) => c.toUpperCase()))}.` : ''}</p>
    <div class="g-actions g-center-row">
      ${next ? '<button type="button" class="btn btn-primary g-big" data-g="next-item">Next one</button>' : ''}
      <button type="button" class="btn g-big" data-g="stop">Stop for today</button>
    </div>
    ${next ? '' : '<p class="g-meta">That was the last one for now. Thank you!</p>'}
  </div>`;
}

function stoppedHtml() {
  return `<div class="g-wrap g-narrow g-center">
    <h1 class="g-hello" tabindex="-1">Thank you</h1>
    <p class="g-lead">Everything is saved. You can close this page. When you come back, we'll pick up where you left off.</p>
    <div class="g-actions g-center-row"><button type="button" class="btn btn-primary g-big" data-g="keep-going">Keep going</button></div>
  </div>`;
}

function guidedRender() {
  if (state.mode !== 'guided' || !state.snap) return;
  let html;
  if (!state.rowsLoaded && !state.rowsError) {
    html = '<div class="g-wrap g-narrow"><p class="g-lead">Loading…</p></div>';
  } else {
    if (guided.step === 'start' && (!guided.itemId || itemProgress(guided.itemId).openForMe === 0)) guided.itemId = pickNext(null);
    const item = state.itemById.get(guided.itemId);
    const list = item ? state.entriesByItem.get(item.id) || [] : [];
    if (!item && guided.step !== 'stopped') guided.step = 'start';
    guided.index = Math.min(Math.max(0, guided.index), Math.max(0, list.length - 1));
    html = guided.step === 'read' ? readHtml(item, list)
      : guided.step === 'piece' ? pieceHtml(item, list)
      : guided.step === 'done' ? doneHtml(item, list)
      : guided.step === 'stopped' ? stoppedHtml()
      : startHtml();
    if (state.rowsError) html = `<div class="banner g-banner" role="status">Can't reach the server just now, so other reviewers' work may be missing. Your changes are kept on this computer and will be saved.</div>${html}`;
  }
  // Re-draw only when something changed, so focus and scroll stay where they are.
  if (html !== guidedHtml) {
    const focused = document.activeElement?.closest?.('[data-g]')?.getAttribute('data-g');
    guidedHtml = html;
    ui.guided.innerHTML = html;
    for (const el of ui.guided.querySelectorAll('.g-bar[data-bar]')) {
      const bar = el.getAttribute('data-bar');
      if (/^#[0-9a-f]{6}$/i.test(bar)) el.style.setProperty('--bar', bar);
    }
    const box = ui.guided.querySelector('.g-box');
    if (box) { grow(box); guidedWarnings(); }
    if (focused) ui.guided.querySelector(`[data-g="${focused}"]`)?.focus({ preventScroll: true });
    if (ui.guided.querySelector('#g-screen')) {
      pv.screen = $('#g-screen');
      pv.note = $('#g-note');
    }
  }
  pv.item = guided.itemId;
  pv.key = guided.step === 'piece' ? (state.entriesByItem.get(guided.itemId) || [])[guided.index]?.key ?? null : null;
  guidedStatus();
  if (ui.guided.querySelector('#g-screen')) pvRender();
}

/** Status lines that change with saving; kept out of the re-draw check. */
function guidedStatus() {
  const el = ui.guided.querySelector('.g-status');
  if (!el || guided.step !== 'piece') return;
  const e = (state.entriesByItem.get(guided.itemId) || [])[guided.index];
  if (!e) return;
  const info = infoOf(e.key);
  const mine = info.mine;
  let text = '';
  if (mine) {
    text = mine.verdict === 'ok' ? 'You said this looks right.' : approvesDraft(e, mine) ? 'You approved the AI draft.' : 'You suggested a change.';
    if (info.pending) text += flushing && !lastSendFailed ? ' Saving…' : ' Not saved yet — will retry.';
  } else if (info.by) {
    text = `Checked by ${info.by.reviewer || 'someone'}${info.by.verdict === 'suggest' ? ', who suggested a change' : ''}.`;
  }
  el.textContent = text;
}

function guidedPatch() {
  if (state.mode !== 'guided') return;
  const a = document.activeElement;
  const typing = a && ui.guided.contains(a) && (a.tagName === 'TEXTAREA' || a.tagName === 'INPUT');
  if (guided.editing || typing) { guidedStatus(); return; }
  guidedRender();
}

function guidedWarnings() {
  const e = (state.entriesByItem.get(guided.itemId) || [])[guided.index];
  const box = ui.guided.querySelector('.g-box');
  if (!e || !box) return;
  ui.guided.querySelector('.warns').innerHTML = checkText(e, box.value).map((w) => `<li>${esc(w)}</li>`).join('');
  const counter = ui.guided.querySelector('.g-counter');
  if (counter) counter.textContent = `${box.value.trim().length} of ${SUMMARY_MAX} characters`;
}

const currentPiece = () => (guided.step === 'piece' ? (state.entriesByItem.get(guided.itemId) || [])[guided.index] : null);
const noteValue = () => (ui.guided.querySelector('.g-note')?.value || '').trim();
const guidedHint = (text) => { const h = ui.guided.querySelector('.g-hint'); if (h) h.textContent = text; };

/** "Looks right": the current text, or the AI draft where there's none. */
function lookRight(e) {
  const note = noteValue();
  const mine = infoOf(e.key).mine;
  if (e.current.trim()) {
    if (!(mine?.verdict === 'ok' && (mine.note || '') === note) && !save(e, 'ok', null, note)) return false;
  } else if (draftOf(e)) {
    // Approving a draft is a suggestion of its text: an "ok" would leave Mark nothing to accept.
    if (!(approvesDraft(e, mine) && (mine.note || '') === note) && !save(e, 'suggest', draftOf(e), note)) return false;
  } else return false;
  setSkipped(e.key, false);
  return true;
}

/** Saves what's in the box; false when there's nothing to save. */
function saveTyped(e) {
  const box = ui.guided.querySelector('.g-box');
  const text = (box?.value || '').trim();
  const note = noteValue();
  if (!text) { guidedHint('Type your version, or click “Skip for now”.'); return false; }
  if ((e.current.trim() && text === e.current.trim()) || (!e.current.trim() && text === draftOf(e))) return lookRight(e);
  const mine = infoOf(e.key).mine;
  if (!(mine?.verdict === 'suggest' && (mine.suggested || '').trim() === text && (mine.note || '') === note) && !save(e, 'suggest', text, note)) return false;
  setSkipped(e.key, false);
  return true;
}

/** Leaving a piece with a changed box keeps the change (going back, skipping, closing the tab). */
function commitGuided() {
  if (state.mode !== 'guided' || !guided.editing) return;
  const e = currentPiece();
  const box = ui.guided.querySelector('.g-box');
  if (!e || !box) return;
  const text = box.value.trim();
  const mine = infoOf(e.key).mine;
  const saved = mine?.verdict === 'suggest' ? (mine.suggested || '').trim() : '';
  if (!text || text === saved || text === e.current.trim() || text === draftOf(e)) return;
  if (save(e, 'suggest', text, noteValue())) setSkipped(e.key, false);
}

function goTo(step, extra = {}) {
  Object.assign(guided, { editing: false, ...extra, step });
  guidedRender();
  window.scrollTo({ top: 0 });
  const target = ui.guided.querySelector('.g-hello, .g-h1') || (step === 'piece' ? ui.guided.querySelector('.g-big') : null);
  target?.focus({ preventScroll: true });
}

function advance() {
  const list = state.entriesByItem.get(guided.itemId) || [];
  if (guided.index + 1 >= list.length) goTo('done');
  else goTo('piece', { index: guided.index + 1 });
}

ui.guided.addEventListener('click', (ev) => {
  const view = ev.target.closest('[data-view]')?.getAttribute('data-view');
  if (view) { pv.view = view; pvSchedule(); return; }
  // A tap on a piece in the phone goes to that piece.
  const tapped = ev.target.closest('.pv-piece')?.getAttribute('data-key');
  if (tapped) {
    commitGuided();
    const list = state.entriesByItem.get(guided.itemId) || [];
    const i = list.findIndex((e) => e.key === tapped);
    if (i !== -1) goTo('piece', { index: i });
    return;
  }
  const btn = ev.target.closest('[data-g]');
  if (!btn) return;
  const e = currentPiece();
  switch (btn.getAttribute('data-g')) {
    case 'start':
      goTo('read', { index: firstOpenIndex(state.entriesByItem.get(guided.itemId) || []) });
      break;
    case 'read-next':
      if (!myName()) { openDialog('welcome'); return; }
      goTo('piece');
      break;
    case 'back':
      goTo('start');
      break;
    case 'ok':
      if (e && lookRight(e)) advance();
      break;
    case 'edit':
      guided.editing = true;
      guidedRender();
      ui.guided.querySelector('.g-box')?.focus();
      break;
    case 'cancel':
      guided.editing = false;
      guidedRender();
      ui.guided.querySelector('[data-g="edit"]')?.focus();
      break;
    case 'save':
      if (e && saveTyped(e)) advance();
      break;
    case 'prev':
      commitGuided();
      if (guided.index > 0) goTo('piece', { index: guided.index - 1 });
      else goTo('read');
      break;
    case 'skip':
      commitGuided();
      if (e && !infoOf(e.key).mine) setSkipped(e.key, true);
      advance();
      break;
    case 'next-item':
      goTo('start', { itemId: pickNext(guided.itemId), index: 0 });
      break;
    case 'stop':
      goTo('stopped');
      break;
    case 'keep-going':
      goTo('start', { itemId: null });
      break;
    case 'style':
      openDialog('note');
      break;
    case 'pick':
      guided.picking = !guided.picking;
      guidedRender();
      ui.guided.querySelector(guided.picking ? '.g-pick-search' : '[data-g="pick"]')?.focus();
      break;
    case 'pick-item':
      goTo('start', { itemId: btn.getAttribute('data-item'), picking: false, pickQuery: '' });
      break;
    case 'table':
      setMode('table');
      ui.results.focus();
      break;
    default:
  }
});

ui.guided.addEventListener('input', (ev) => {
  const t = ev.target;
  if (t.classList.contains('g-pick-search')) {
    guided.pickQuery = t.value;
    const list = ui.guided.querySelector('.g-pick-list');
    if (list) list.innerHTML = pickListItems();
    return;
  }
  if (t.classList.contains('g-box')) {
    grow(t);
    guidedWarnings();
    guidedHint('');
    pvSchedule();
  }
});

// Enter in the note saves like the main button.
ui.guided.addEventListener('keydown', (ev) => {
  if (ev.key !== 'Enter' || !ev.target.classList?.contains('g-note')) return;
  ev.preventDefault();
  ui.guided.querySelector('[data-g="save"], [data-g="ok"]')?.click();
});

boot();
