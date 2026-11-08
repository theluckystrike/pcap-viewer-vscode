'use strict';
// Tests for the shared rating ask (factory/sprint/rating). Copied unchanged into each extension's test/.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const R = require('../src/rate.js');

const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
const DAY = R.DAY_MS;
const T0 = new Date(2026, 10, 2, 10, 0, 0).getTime(); // local 10:00, so +n days stays on day n
const env = (over = {}) => ({ now: T0 + DAY, enabled: true, focused: true, askedThisSession: false, errorThisSession: false, ...over });

function opens(n, now = T0, state) {
  let s = state;
  for (let i = 0; i < n; i++) s = R.recordSuccess(s, now);
  return s;
}
// 3 opens on day 0 and 1 on day 1: ready for the first ask on day 1.
const ready = () => opens(1, T0 + DAY, opens(3));

test('rating: message and buttons', () => {
  assert.equal(R.messageFor('DOCX Viewer'), 'Is DOCX Viewer useful? A rating helps others find it.');
  assert.deepEqual([R.RATE, R.LATER, R.NEVER], ['Rate it', 'Later', 'No thanks']);
});

test('rating: no ask before 3 files opened without an error', () => {
  assert.equal(R.decide(opens(1, T0 + DAY, opens(1)), env()), false, '2 files on 2 days');
  assert.equal(R.decide(opens(1, T0 + DAY, opens(2)), env()), true, '3 files on 2 days');
});

test('rating: no ask while all files were opened on one day', () => {
  const s = opens(50);
  assert.equal(s.days.length, 1);
  assert.equal(R.decide(s, env({ now: T0 })), false);
  assert.equal(R.decide(s, env({ now: T0 + 5 * DAY })), false, 'time alone does not count, a second day of use does');
  const s2 = opens(1, T0 + 5 * DAY, s);
  assert.equal(s2.days.length, 2);
  assert.equal(R.decide(s2, env({ now: T0 + 5 * DAY })), true);
});

test('rating: 2 different calendar days, not 24 hours', () => {
  const late = new Date(2026, 10, 2, 23, 50).getTime();
  const early = new Date(2026, 10, 3, 0, 10).getTime();
  const s = opens(1, early, opens(2, late));
  assert.equal(R.decide(s, env({ now: early })), true);
  assert.equal(R.dayKey(late), '2026-11-02');
  assert.equal(R.dayKey(early), '2026-11-03');
});

test('rating: never after an error', () => {
  const s = ready();
  assert.equal(R.decide(s, env({ errorThisSession: true })), false, 'a failure in this session');
  const f = R.recordFailure(s, T0 + DAY - 1000);
  assert.equal(R.decide(f, env()), false, 'failure 1 s ago');
  assert.equal(R.decide(f, env({ now: T0 + 2 * DAY - 2000 })), false, 'failure 23 h ago');
  assert.equal(R.decide(f, env({ now: T0 + 2 * DAY })), true, 'failure more than 24 h ago, new session');
  assert.equal(R.recordFailure(s, 5).count, s.count, 'a failure does not count as a file');
});

test('rating: "Later" asks again one time, 7 days later', () => {
  const t1 = T0 + DAY;
  let s = R.recordAnswer(ready(), 'shown', t1);
  s = R.recordAnswer(s, R.LATER, t1);
  assert.equal(s.done, false);
  assert.equal(s.asks, 1);
  assert.equal(R.decide(opens(5, t1 + 6 * DAY, s), env({ now: t1 + 6 * DAY })), false, 'after 6 days');
  assert.equal(R.decide(opens(1, t1 + 7 * DAY, s), env({ now: t1 + 7 * DAY })), true, 'after 7 days');
  s = R.recordAnswer(opens(1, t1 + 7 * DAY, s), 'shown', t1 + 7 * DAY);
  s = R.recordAnswer(s, R.LATER, t1 + 7 * DAY);
  assert.equal(s.done, true, 'the second ask is the last');
  assert.equal(R.decide(opens(100, t1 + 60 * DAY, s), env({ now: t1 + 60 * DAY })), false);
});

test('rating: never more than 2 asks in all, whatever the answers', () => {
  let s = opens(3);
  let asks = 0;
  for (let d = 1; d < 400; d++) {
    const now = T0 + d * DAY;
    s = R.recordSuccess(s, now);
    if (R.decide(s, env({ now }))) {
      asks++;
      s = R.recordAnswer(s, 'shown', now);
      s = R.recordAnswer(s, undefined, now); // closed without an answer
    }
  }
  assert.equal(asks, 2);
  assert.equal(s.done, true);
});

test('rating: closing the message counts like "Later"', () => {
  const s = R.recordAnswer(R.recordAnswer(ready(), 'shown', T0 + DAY), undefined, T0 + DAY);
  assert.equal(s.done, false);
  assert.equal(R.decide(s, env({ now: T0 + 2 * DAY })), false);
  assert.equal(R.decide(s, env({ now: T0 + 8 * DAY })), true);
});

test('rating: "Rate it" and "No thanks" end it', () => {
  for (const a of [R.RATE, R.NEVER]) {
    const s = R.recordAnswer(R.recordAnswer(ready(), 'shown', T0 + DAY), a, T0 + DAY);
    assert.equal(s.done, true);
    assert.equal(R.decide(opens(500, T0 + 30 * DAY, s), env({ now: T0 + 30 * DAY })), false);
  }
});

test('rating: setting off, unfocused window, already asked in this session', () => {
  const s = ready();
  assert.equal(R.decide(s, env({ enabled: false })), false);
  assert.equal(R.decide(s, env({ focused: false })), false);
  assert.equal(R.decide(s, env({ askedThisSession: true })), false);
});

test('rating: bad stored state is reset safely', () => {
  for (const bad of [null, 'x', 42, { count: -3, days: 'x', asks: NaN, nextAskAt: -1 }, { days: ['2026-11-02', 7, 'junk'] }]) {
    const s = R.normalize(bad);
    assert.equal(s.count, 0);
    assert.equal(s.asks, 0);
    assert.equal(s.done, false);
    assert.ok(s.days.length <= 1);
  }
  assert.equal(R.normalize({ asks: 9 }).done, true, 'more asks than allowed means done');
});

test('rating: v1 state keeps its answers', () => {
  assert.equal(R.fromV1({ count: 9, firstUse: T0, asks: 1, done: true }).done, true, '"Don\'t ask again" or "Rate it" in v1');
  const s = R.fromV1({ count: 9, firstUse: T0, asks: 1, done: false });
  assert.equal(s.asks, 1, 'a v1 ask counts toward the 2');
  assert.deepEqual(s.days, [R.dayKey(T0)]);
  assert.equal(R.fromV1({ asks: 3 }).done, true);
  assert.deepEqual(R.fromV1(undefined), R.freshState());
});

test('rating: fake clock only from the env variable, bounded', () => {
  assert.equal(R.clockOffsetMs({}), 0);
  assert.equal(R.clockOffsetMs({ [R.CLOCK_ENV]: '1' }), DAY);
  assert.equal(R.clockOffsetMs({ [R.CLOCK_ENV]: '-3' }), 0);
  assert.equal(R.clockOffsetMs({ [R.CLOCK_ENV]: 'x' }), 0);
  assert.equal(R.clockOffsetMs({ [R.CLOCK_ENV]: '99999' }), 0);
});

test('rating: review link points at this extension', () => {
  const id = `${pkg.publisher}.${pkg.name}`;
  assert.equal(R.reviewUrl(id), `https://marketplace.visualstudio.com/items?itemName=${id}&ssr=false#review-details`);
});

test('rating: manifest has an askForRating setting, default true', () => {
  const props = pkg.contributes.configuration.properties || {};
  const key = Object.keys(props).find((k) => k.endsWith('.askForRating'));
  assert.ok(key, 'askForRating setting');
  assert.equal(props[key].type, 'boolean');
  assert.equal(props[key].default, true);
});

function fake(o = {}) {
  const calls = { shown: [], opened: [] };
  let answer = o.answer;
  const vscode = {
    env: { openExternal: async (u) => { calls.opened.push(String(u)); return true; } },
    Uri: { parse: (s) => ({ toString: () => s }) },
    window: {
      state: { focused: true },
      showInformationMessage: async (msg, ...items) => { calls.shown.push([msg, items]); return answer; },
    },
    workspace: { getConfiguration: () => ({ get: (k, d) => (k === 'askForRating' && 'enabled' in o ? o.enabled : d) }) },
  };
  const data = new Map(o.data || []);
  const context = { globalState: { get: (k) => data.get(k), update: async (k, v) => { data.set(k, v); } } };
  const clock = { t: T0 };
  const make = () => R.createRatingPrompt({ vscode, context, extensionId: 'zovo.x', section: 'x', name: 'X Viewer', now: () => clock.t });
  return { vscode, context, calls, data, clock, make, setAnswer: (a) => { answer = a; } };
}

test('rating: wiring asks once on day 2, opens the review page on "Rate it"', async () => {
  const f = fake({ answer: R.RATE });
  let p = f.make();
  for (let i = 0; i < 5; i++) await p.success();
  assert.equal(f.calls.shown.length, 0, 'day 1');
  f.clock.t = T0 + DAY;
  p = f.make();
  await p.success();
  await p.success();
  assert.equal(f.calls.shown.length, 1);
  assert.deepEqual(f.calls.shown[0], ['Is X Viewer useful? A rating helps others find it.', [R.RATE, R.LATER, R.NEVER]]);
  assert.deepEqual(f.calls.opened, [R.reviewUrl('zovo.x')]);
  assert.equal(f.data.get(R.STATE_KEY).done, true);
  f.clock.t = T0 + 30 * DAY;
  await f.make().success();
  assert.equal(f.calls.shown.length, 1, 'never again after "Rate it"');
});

test('rating: wiring, a failure in the session blocks the ask; "Later" then 7 days', async () => {
  const f = fake({ answer: R.LATER });
  let p = f.make();
  for (let i = 0; i < 3; i++) await p.success();
  f.clock.t = T0 + 2 * DAY;
  p = f.make();
  await p.failure();
  await p.success();
  assert.equal(f.calls.shown.length, 0, 'never after an error');
  f.clock.t = T0 + 4 * DAY;
  p = f.make();
  await p.success();
  assert.equal(f.calls.shown.length, 1, 'next session, 2 days after the failure');
  assert.equal(f.calls.opened.length, 0, '"Later" opens nothing');
  f.clock.t = T0 + 10 * DAY;
  await f.make().success();
  assert.equal(f.calls.shown.length, 1, '6 days later: no');
  f.clock.t = T0 + 11 * DAY;
  await f.make().success();
  assert.equal(f.calls.shown.length, 2, '7 days later: the last ask');
  f.clock.t = T0 + 40 * DAY;
  await f.make().success();
  assert.equal(f.calls.shown.length, 2, 'never a third time');
});

test('rating: wiring respects the setting, v1 answers and a missing globalState', async () => {
  const off = fake({ answer: R.RATE, enabled: false });
  let p = off.make();
  for (let i = 0; i < 3; i++) await p.success();
  off.clock.t = T0 + DAY;
  await off.make().success();
  assert.equal(off.calls.shown.length, 0, 'setting off');

  const v1 = fake({ answer: R.RATE, data: [[R.OLD_KEY, { count: 40, firstUse: T0 - 9 * DAY, asks: 1, done: true }]] });
  v1.clock.t = T0;
  await v1.make().success();
  assert.equal(v1.calls.shown.length, 0, '"Don\'t ask again" in v1 is kept');

  const none = R.createRatingPrompt({ vscode: off.vscode, context: {}, extensionId: 'zovo.x', section: 'x', name: 'X' });
  await none.success();
  await none.failure();
});

test('rating: wiring never throws when VS Code calls fail', async () => {
  const f = fake();
  f.vscode.window.showInformationMessage = async () => { throw new Error('boom'); };
  f.context.globalState.update = async () => { throw new Error('disk'); };
  const p = f.make();
  await p.success();
  await p.failure();
});
