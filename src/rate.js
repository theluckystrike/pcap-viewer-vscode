'use strict';
// Shared Zovo rating ask, v2 (factory/sprint/rating/rate.js, copied to src/rate.js in each extension).
// No network and no telemetry. State lives only in context.globalState. The one outbound action is the
// Marketplace review page, opened by the user's own click on "Rate it".
//
// Rules:
// - Ask only after the user opened 3 files without an error, on at least 2 different days.
// - "Rate it" opens the review page and ends it. "No thanks" ends it.
// - "Later" (or closing the message) asks again one time, 7 days later at the earliest.
// - At most 2 asks in all, at most 1 per window session.
// - Never after an error: no ask in a session where a file failed to open, and none for 24 hours after a failure.
// - The setting <section>.askForRating = false turns it off.
// The rules are pure functions (recordSuccess, recordFailure, decide, recordAnswer) for unit tests.

const STATE_KEY = 'zovo.rating.v2';
const OLD_KEY = 'zovo.rating.v1';
const DAY_MS = 24 * 60 * 60 * 1000;
const MIN_FILES = 3; // files opened without an error before the first ask
const MIN_DAYS = 2; // different calendar days with a success before the first ask
const LATER_DAYS = 7; // "Later" waits this long
const MAX_ASKS = 2; // asks in all
const ERROR_QUIET_MS = DAY_MS; // no ask for this long after a failure
const RATE = 'Rate it';
const LATER = 'Later';
const NEVER = 'No thanks';
// Fake clock for manual and VS Code tests: shifts "now" by this many days. Unset in normal use.
const CLOCK_ENV = 'ZOVO_RATING_CLOCK_OFFSET_DAYS';

function freshState() {
  return { count: 0, days: [], asks: 0, nextAskAt: 0, lastErrorAt: 0, done: false };
}

const num = (v, d) => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? Math.floor(v) : d);
const isDay = (d) => typeof d === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(d);

function normalize(raw) {
  const s = freshState();
  if (!raw || typeof raw !== 'object') return s;
  s.count = num(raw.count, 0);
  s.days = Array.isArray(raw.days) ? [...new Set(raw.days.filter(isDay))].slice(0, MIN_DAYS) : [];
  s.asks = Math.min(MAX_ASKS, num(raw.asks, 0));
  s.nextAskAt = num(raw.nextAskAt, 0);
  s.lastErrorAt = num(raw.lastErrorAt, 0);
  s.done = raw.done === true || s.asks >= MAX_ASKS;
  return s;
}

/** Local calendar day of a timestamp, as YYYY-MM-DD. */
function dayKey(now) {
  const d = new Date(now);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

/** State of the v1 prompt (5 files and 2 days, "Don't ask again"): keep its answers and asks. */
function fromV1(old) {
  const s = freshState();
  if (!old || typeof old !== 'object') return s;
  s.count = num(old.count, 0);
  const first = num(old.firstUse, 0);
  if (first) s.days = [dayKey(first)];
  s.asks = Math.min(MAX_ASKS, num(old.asks, 0));
  s.done = old.done === true || s.asks >= MAX_ASKS;
  return s;
}

/** A file opened without an error. */
function recordSuccess(state, now) {
  const s = normalize(state);
  s.count += 1;
  const k = dayKey(now);
  if (!s.days.includes(k) && s.days.length < MIN_DAYS) s.days.push(k);
  return s;
}

/** A file failed to open. */
function recordFailure(state, now) {
  const s = normalize(state);
  s.lastErrorAt = Math.max(s.lastErrorAt, num(now, 0));
  return s;
}

/**
 * Should the ask show now? Call it right after recordSuccess.
 * env: { now, enabled, focused, askedThisSession, errorThisSession }
 */
function decide(state, env) {
  const s = normalize(state);
  if (s.done || !env.enabled) return false;
  if (env.askedThisSession || env.errorThisSession || env.focused === false) return false;
  if (s.asks >= MAX_ASKS) return false;
  if (s.count < MIN_FILES || s.days.length < MIN_DAYS) return false;
  if (s.lastErrorAt && env.now - s.lastErrorAt < ERROR_QUIET_MS) return false;
  return env.now >= s.nextAskAt;
}

/**
 * Apply an answer. 'shown' is saved before the message opens, so an ask is used up even if VS Code
 * quits with the message open. "Rate it" and "No thanks" end it; "Later" or no answer wait 7 days.
 */
function recordAnswer(state, answer, now) {
  const s = normalize(state);
  if (answer === 'shown') {
    s.asks += 1;
    s.nextAskAt = num(now, 0) + LATER_DAYS * DAY_MS;
  } else if (answer === RATE || answer === NEVER) {
    s.done = true;
  }
  if (s.asks >= MAX_ASKS) s.done = true;
  return s;
}

function reviewUrl(extensionId) {
  return `https://marketplace.visualstudio.com/items?itemName=${encodeURIComponent(extensionId)}&ssr=false#review-details`;
}

function messageFor(name) {
  return `Is ${name} useful? A rating helps others find it.`;
}

/** Days to add to the clock, from ZOVO_RATING_CLOCK_OFFSET_DAYS (0 to 3650), else 0. */
function clockOffsetMs(envVars) {
  const v = Number(envVars && envVars[CLOCK_ENV]);
  return Number.isFinite(v) && v > 0 && v <= 3650 ? v * DAY_MS : 0;
}

/**
 * opts: { vscode, context, extensionId, section, name, now? }
 * Returns { success(), failure() }. Call success() once per file that opened without an error,
 * failure() when a file could not be opened. Both never throw.
 */
function createRatingPrompt(opts) {
  const { vscode, context, extensionId, section, name } = opts;
  const offset = clockOffsetMs(typeof process !== 'undefined' ? process.env : null);
  const now = typeof opts.now === 'function' ? opts.now : () => Date.now() + offset;
  const store = context && context.globalState;
  const usable = !!(store && typeof store.get === 'function' && typeof store.update === 'function');
  let askedThisSession = false;
  let errorThisSession = false;
  let busy = false;
  const safe = (fn, d) => { try { return fn(); } catch { return d; } };

  function load() {
    const cur = store.get(STATE_KEY);
    if (cur && typeof cur === 'object') return normalize(cur);
    return fromV1(store.get(OLD_KEY));
  }

  const env = () => ({
    now: now(),
    enabled: safe(() => vscode.workspace.getConfiguration(section).get('askForRating', true) !== false, false),
    focused: safe(() => vscode.window.state.focused !== false, true),
    askedThisSession,
    errorThisSession,
  });

  async function ask(s, e) {
    askedThisSession = true;
    let st = recordAnswer(s, 'shown', e.now);
    await store.update(STATE_KEY, st);
    const pick = await vscode.window.showInformationMessage(messageFor(name), RATE, LATER, NEVER);
    st = recordAnswer(load(), pick, now());
    await store.update(STATE_KEY, st);
    if (pick === RATE) await vscode.env.openExternal(vscode.Uri.parse(reviewUrl(extensionId)));
  }

  async function success() {
    if (!usable) return;
    const e = env();
    const s = recordSuccess(load(), e.now);
    await store.update(STATE_KEY, s);
    if (busy || !decide(s, e)) return;
    busy = true;
    try { await ask(s, e); } finally { busy = false; }
  }

  async function failure() {
    errorThisSession = true;
    if (!usable) return;
    await store.update(STATE_KEY, recordFailure(load(), now()));
  }

  return {
    success: () => success().catch(() => {}),
    failure: () => failure().catch(() => {}),
  };
}

module.exports = {
  createRatingPrompt, decide, recordSuccess, recordFailure, recordAnswer, normalize, freshState, fromV1,
  dayKey, reviewUrl, messageFor, clockOffsetMs,
  STATE_KEY, OLD_KEY, DAY_MS, MIN_FILES, MIN_DAYS, LATER_DAYS, MAX_ASKS, ERROR_QUIET_MS, RATE, LATER, NEVER, CLOCK_ENV,
};
