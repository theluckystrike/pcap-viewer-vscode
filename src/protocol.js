'use strict';
// Checks every message from the webview before the extension host acts on it. Pure; no vscode module.
const isInt = (v, min = 0, max = Number.MAX_SAFE_INTEGER) => Number.isSafeInteger(v) && v >= min && v <= max;
const isStr = (v, max) => typeof v === 'string' && v.length <= max;
const TIME = new Set(['relative', 'utc', 'local', 'delta']);

function validate(m) {
  if (!m || typeof m !== 'object' || typeof m.type !== 'string') return null;
  switch (m.type) {
    case 'ready': case 'rendered': case 'stats': case 'openSettings': case 'more': case 'cancel':
      return { type: m.type };
    case 'rows':
      if (!isInt(m.start) || !isInt(m.count, 1, 2000) || !isInt(m.seq)) return null;
      return { type: 'rows', start: m.start, count: m.count, seq: m.seq, names: !!m.names, time: TIME.has(m.time) ? m.time : 'relative' };
    case 'packet': case 'follow': case 'find':
      if (!isInt(m.no, 1)) return null;
      return { type: m.type, no: m.no };
    case 'filter':
      if (!isStr(m.expr, 4000) || !isInt(m.seq)) return null;
      return { type: 'filter', expr: m.expr, seq: m.seq };
    case 'export':
      if (m.which === 'view') return { type: 'export', which: 'view' };
      if (!Array.isArray(m.which) || m.which.length === 0 || m.which.length > 5000000 || !m.which.every(n => isInt(n, 1))) return null;
      return { type: 'export', which: m.which };
    case 'saveFilter':
      if (!isStr(m.expr, 4000) || !m.expr.trim()) return null;
      return { type: 'saveFilter', expr: m.expr.trim() };
    case 'manageFilters':
      return { type: 'manageFilters' };
    case 'copy':
      if (!isStr(m.text, 32 << 20)) return null;
      return { type: 'copy', text: m.text, what: isStr(m.what, 80) ? m.what : 'text' };
    case 'saveStream':
      if (!isStr(m.text, 64 << 20) || !isStr(m.name, 200)) return null;
      return { type: 'saveStream', text: m.text, name: m.name };
    case 'error':
      return { type: 'error', message: String(m.message || '').slice(0, 2000) };
    default:
      return null;
  }
}

module.exports = { validate };
