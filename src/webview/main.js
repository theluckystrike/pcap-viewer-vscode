'use strict';
// PCAP Viewer webview: virtual packet list, display filter, protocol tree and a linked hex pane,
// follow stream and statistics. Every byte comes from the extension host by postMessage; no network.
const { compile } = require('../core/filter');

const vscode = acquireVsCodeApi();
const $ = (sel, el = document) => el.querySelector(sel);
const h = (tag, attrs = {}, ...kids) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') e.className = v; else if (k === 'text') e.textContent = v; else if (k === 'style') e.style.cssText = v; // CSSOM: allowed by the CSP, a style attribute is not
     else if (k.startsWith('on')) e.addEventListener(k.slice(2), v); else e.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat()) if (c !== null && c !== undefined && c !== false) e.append(c.nodeType ? c : document.createTextNode(String(c)));
  return e;
};
const fmt = n => Number(n).toLocaleString('en-US');
function fmtSize(n) { if (n < 1024) return `${n} B`; const u = ['KB', 'MB', 'GB', 'TB']; let i = -1; do { n /= 1024; i++; } while (n >= 1024 && i < 3); return `${n.toFixed(n < 10 ? 2 : 1)} ${u[i]}`; }
const hex2 = b => b.toString(16).padStart(2, '0');

const ROW_H = 22, HEX_ROW_H = 18, CHUNK = 200, MAX_SCROLL_PX = 8000000;
const S = {
  info: null, settings: {}, name: '', total: 0, viewCount: 0, filter: '', filterSeq: 0, rowSeq: 0,
  chunks: new Map(), pendingChunks: new Set(), selectedPos: -1, selectedNo: 0, selection: new Set(), anchorPos: -1,
  packet: null, selNode: null, hexSel: null, names: true, time: 'relative', rendered: false, statsData: null,
};

window.addEventListener('error', e => vscode.postMessage({ type: 'error', message: String(e.message) + ' ' + (e.filename || '') + ':' + (e.lineno || '') }));

// ---------- layout ----------
const app = $('#app');
function buildLayout() {
  app.textContent = '';
  const filterInput = h('input', { id: 'filter', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: 'Display filter: tcp.port == 443 && ip.addr == 10.0.0.1', title: 'Display filter. Enter applies, Esc clears. Examples: dns, ip.addr == 10.0.0.0/24, tls.sni == "example.com", tcp.stream == 3', 'aria-label': 'Display filter' });
  const bar = h('div', { class: 'toolbar', role: 'toolbar' },
    h('div', { class: 'filterbox' },
      h('button', { id: 'savedBtn', class: 'icon', title: 'Saved filters', 'aria-haspopup': 'menu' }, '★'),
      filterInput,
      h('button', { id: 'applyBtn', class: 'primary', title: 'Apply the filter (Enter)' }, 'Apply'),
      h('button', { id: 'clearBtn', title: 'Show every packet (Esc in the filter box)' }, 'Clear')),
    h('div', { class: 'tools' },
      h('label', { class: 'sel', title: 'Time column format' }, 'Time ', h('select', { id: 'timeSel' },
        h('option', { value: 'relative' }, 'Seconds since start'), h('option', { value: 'delta' }, 'Since previous shown'),
        h('option', { value: 'utc' }, 'Date and time (UTC)'), h('option', { value: 'local' }, 'Date and time (local)'))),
      h('label', { class: 'chk', title: 'Show names from DNS answers and name blocks in this capture. Nothing is looked up on the network.' }, h('input', { id: 'namesChk', type: 'checkbox' }), ' Names'),
      h('button', { id: 'followBtn', title: 'Follow the TCP or UDP stream of the selected packet' }, 'Follow stream'),
      h('button', { id: 'statsBtn', title: 'Protocol hierarchy, conversations, endpoints and names' }, 'Statistics'),
      h('button', { id: 'exportBtn', title: 'Export packets as a pcap file', 'aria-haspopup': 'menu' }, 'Export ▾')));
  const err = h('div', { id: 'filterErr', class: 'filter-err', role: 'status', 'aria-live': 'polite' });
  const notices = h('div', { id: 'notices' });
  const head = h('div', { class: 'row head', role: 'row' }, ...['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info'].map((t, i) => h('div', { class: 'c c' + i, role: 'columnheader' }, t)));
  const list = h('div', { id: 'list', class: 'list', tabindex: '0', role: 'grid', 'aria-label': 'Packets', 'aria-multiselectable': 'true' },
    h('div', { id: 'spacer', class: 'spacer' }), h('div', { id: 'rows', class: 'rows', role: 'rowgroup' }));
  const tree = h('div', { id: 'tree', class: 'tree', tabindex: '0', role: 'tree', 'aria-label': 'Packet details' }, h('p', { class: 'hint' }, 'Select a packet to see its layers.'));
  const hexv = h('div', { id: 'hex', class: 'hex', tabindex: '0', 'aria-label': 'Packet bytes' }, h('div', { id: 'hexSpacer', class: 'spacer' }), h('div', { id: 'hexRows', class: 'hexrows' }));
  const status = h('div', { class: 'statusline' }, h('span', { id: 'count' }), h('span', { id: 'fileinfo' }), h('span', { id: 'live', class: 'sr', 'aria-live': 'polite' }));
  const footer = $('#zovo-footer');
  app.append(bar, err, notices,
    h('div', { class: 'main' },
      h('div', { class: 'top', id: 'top' }, head, list),
      h('div', { class: 'split', id: 'split', title: 'Drag to resize', role: 'separator', 'aria-orientation': 'horizontal' }),
      h('div', { class: 'bottom', id: 'bottom' }, tree, h('div', { class: 'vsplit' }), hexv)),
    status);
  if (footer && footer.innerHTML.trim()) { const f = document.createElement('div'); f.className = 'footer'; f.innerHTML = footer.innerHTML; app.append(f); }
  wire();
}

function wire() {
  const fi = $('#filter');
  fi.addEventListener('input', () => checkFilter(fi.value));
  fi.addEventListener('keydown', e => {
    if (e.key === 'Enter') { e.preventDefault(); applyFilter(fi.value); }
    if (e.key === 'Escape') { e.preventDefault(); fi.value = ''; checkFilter(''); applyFilter(''); }
  });
  $('#applyBtn').onclick = () => applyFilter(fi.value);
  $('#clearBtn').onclick = () => { fi.value = ''; checkFilter(''); applyFilter(''); };
  $('#savedBtn').onclick = e => savedMenu(e.currentTarget);
  $('#exportBtn').onclick = e => exportMenu(e.currentTarget);
  $('#followBtn').onclick = () => follow();
  $('#statsBtn').onclick = () => showStats();
  $('#timeSel').onchange = e => { S.time = e.target.value; refreshRows(); };
  $('#namesChk').onchange = e => { S.names = e.target.checked; refreshRows(); };
  const list = $('#list');
  list.addEventListener('scroll', () => renderRows(), { passive: true });
  list.addEventListener('keydown', listKey);
  // Rows are drawn again on each selection, so a double-click is read from the second mousedown (detail 2):
  // a dblclick event would need the same element under both clicks.
  list.addEventListener('mousedown', e => {
    if (e.button !== 0) return;
    const r = e.target.closest('.row[data-pos]'); if (!r) return;
    list.focus();
    if (e.detail === 2 && !e.shiftKey && !e.metaKey && !e.ctrlKey) { e.preventDefault(); follow(); return; }
    clickRow(Number(r.dataset.pos), e);
  });
  list.addEventListener('contextmenu', e => { const r = e.target.closest('.row[data-pos]'); if (!r) return; e.preventDefault(); const pos = Number(r.dataset.pos); if (!S.selection.has(rowAt(pos)?.no)) clickRow(pos, {}); rowMenu(e.clientX, e.clientY, rowAt(pos)); });
  new ResizeObserver(() => { renderRows(); renderHex(); }).observe(list);
  $('#hex').addEventListener('scroll', () => renderHex(), { passive: true });
  $('#hex').addEventListener('mousedown', e => { const b = e.target.closest('[data-i]'); if (b) byteClick(Number(b.dataset.i)); });
  $('#tree').addEventListener('click', treeClick);
  $('#tree').addEventListener('keydown', treeKey);
  // splitter
  const split = $('#split');
  split.addEventListener('mousedown', e => {
    e.preventDefault();
    const top = $('#top'), main = top.parentElement, y0 = e.clientY, h0 = top.getBoundingClientRect().height;
    const mv = ev => { const nh = Math.max(80, Math.min(main.getBoundingClientRect().height - 120, h0 + ev.clientY - y0)); top.style.flex = `0 0 ${nh}px`; };
    const up = () => { window.removeEventListener('mousemove', mv); window.removeEventListener('mouseup', up); renderRows(); };
    window.addEventListener('mousemove', mv); window.addEventListener('mouseup', up);
  });
  document.addEventListener('keydown', e => {
    const mod = e.metaKey || e.ctrlKey;
    if (mod && e.key.toLowerCase() === 'f' && !e.shiftKey) { e.preventDefault(); $('#filter').focus(); $('#filter').select(); }
    if (e.key === 'Escape') { if (document.querySelector('.menu')) closeMenus(); else if ($('#overlay') && !e.target.closest('#filter')) closeOverlay(); }
  });
  document.addEventListener('mousedown', e => { if (!e.target.closest('.menu')) closeMenus(); });
}

// ---------- filter ----------
function checkFilter(v) {
  const fi = $('#filter'), err = $('#filterErr');
  if (!v.trim()) { fi.classList.remove('ok', 'bad'); err.textContent = ''; return true; }
  const c = compile(v);
  fi.classList.toggle('ok', c.ok); fi.classList.toggle('bad', !c.ok);
  err.textContent = c.ok ? '' : c.error + (c.at !== undefined ? ` (at character ${c.at + 1})` : '');
  return c.ok;
}

function applyFilter(v) {
  if (!checkFilter(v)) return;
  S.filterSeq++;
  $('#count').textContent = v.trim() ? 'Filtering...' : '';
  vscode.postMessage({ type: 'filter', expr: v, seq: S.filterSeq });
}

function setFilter(v, apply = true) { $('#filter').value = v; checkFilter(v); if (apply) applyFilter(v); }

// ---------- menus ----------
function closeMenus() { document.querySelectorAll('.menu').forEach(m => m.remove()); }
function menu(x, y, items) {
  closeMenus();
  const m = h('div', { class: 'menu', role: 'menu' });
  for (const it of items) {
    if (it === '-') { m.append(h('div', { class: 'sep', role: 'separator' })); continue; }
    if (it.header) { m.append(h('div', { class: 'mhead' }, it.header)); continue; }
    m.append(h('button', { class: 'mi', role: 'menuitem', title: it.title || '', disabled: it.disabled, onclick: () => { closeMenus(); it.run(); } }, it.label, it.hint ? h('span', { class: 'mhint' }, it.hint) : null));
  }
  document.body.append(m);
  const r = m.getBoundingClientRect();
  m.style.left = Math.max(4, Math.min(x, innerWidth - r.width - 4)) + 'px';
  m.style.top = Math.max(4, Math.min(y, innerHeight - r.height - 4)) + 'px';
  const first = m.querySelector('button:not([disabled])'); if (first) first.focus();
  m.addEventListener('keydown', e => {
    const bs = [...m.querySelectorAll('button:not([disabled])')], i = bs.indexOf(document.activeElement);
    if (e.key === 'ArrowDown') { e.preventDefault(); bs[(i + 1) % bs.length].focus(); }
    if (e.key === 'ArrowUp') { e.preventDefault(); bs[(i - 1 + bs.length) % bs.length].focus(); }
  });
}
function below(el) { const r = el.getBoundingClientRect(); return [r.left, r.bottom + 2]; }

function savedMenu(btn) {
  const cur = $('#filter').value.trim();
  const items = [{ header: 'Saved filters' }];
  for (const f of S.settings.savedFilters || []) items.push({ label: f.name || f.filter, hint: f.name && f.name !== f.filter ? f.filter : '', title: f.filter, run: () => setFilter(f.filter) });
  if (!(S.settings.savedFilters || []).length) items.push({ label: 'No saved filters yet', disabled: true, run() {} });
  items.push('-', { label: 'Save the current filter...', disabled: !cur || !compile(cur).ok, run: () => vscode.postMessage({ type: 'saveFilter', expr: cur }) },
    { label: 'Edit saved filters in Settings', run: () => vscode.postMessage({ type: 'manageFilters' }) });
  menu(...below(btn), items);
}

function exportMenu(btn) {
  const sel = [...S.selection];
  menu(...below(btn), [
    { label: `Export selected packets (${fmt(sel.length)})`, disabled: !sel.length, run: () => vscode.postMessage({ type: 'export', which: sel.sort((a, b) => a - b) }) },
    { label: S.filter ? `Export shown packets (${fmt(S.viewCount)}, filtered)` : `Export all packets (${fmt(S.total)})`, run: () => vscode.postMessage({ type: 'export', which: 'view' }) },
  ]);
}

function rowMenu(x, y, row) {
  if (!row) return;
  const isIp = a => /^\d+\.\d+\.\d+\.\d+$/.test(a), isV6 = a => a.includes(':') && !/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(a);
  const fld = a => (isIp(a) ? 'ip.addr' : isV6(a) ? 'ipv6.addr' : 'eth.addr');
  const items = [
    { label: 'Follow stream', hint: 'double-click', run: () => follow() },
    '-',
    row.srcAddr ? { label: `Filter on source ${row.srcAddr}`, run: () => setFilter(`${fld(row.srcAddr)} == ${row.srcAddr}`) } : null,
    row.dstAddr ? { label: `Filter on destination ${row.dstAddr}`, run: () => setFilter(`${fld(row.dstAddr)} == ${row.dstAddr}`) } : null,
    row.srcAddr && row.dstAddr ? { label: 'Filter on this conversation', run: () => setFilter(`${fld(row.srcAddr)} == ${row.srcAddr} && ${fld(row.dstAddr)} == ${row.dstAddr}`) } : null,
    { label: `Filter on protocol ${row.proto}`, run: () => setFilter(protoFilter(row.proto)) },
    '-',
    { label: 'Copy row as text', run: () => vscode.postMessage({ type: 'copy', what: `packet ${row.no}`, text: [row.no, row.time, row.src, row.dst, row.proto, row.len, row.info].join('\t') }) },
    { label: `Export selected packets (${fmt(S.selection.size)})`, run: () => vscode.postMessage({ type: 'export', which: [...S.selection].sort((a, b) => a - b) }) },
  ].filter(Boolean);
  menu(x, y, items);
}

function protoFilter(p) {
  const m = p.toLowerCase();
  if (m.startsWith('tlsv') || m === 'tls') return 'tls';
  if (m === 'ipv4') return 'ip';
  if (m === '802.11') return 'wlan';
  return m.replace(/[^a-z0-9.]/g, '');
}

// ---------- packet list ----------
function rowAt(pos) { const c = S.chunks.get(Math.floor(pos / CHUNK)); return c ? c[pos % CHUNK] : null; }

function scrollGeom() {
  const list = $('#list');
  const full = S.viewCount * ROW_H, spacerH = Math.min(full, MAX_SCROLL_PX);
  const viewH = Math.max(0, list.clientHeight);
  const visible = Math.ceil(viewH / ROW_H) + 1;
  let first;
  if (full <= MAX_SCROLL_PX) first = Math.floor(list.scrollTop / ROW_H);
  else { const maxTop = Math.max(1, spacerH - viewH); first = Math.round((list.scrollTop / maxTop) * Math.max(0, S.viewCount - Math.floor(viewH / ROW_H))); }
  return { full, spacerH, viewH, visible, first: Math.max(0, Math.min(first, Math.max(0, S.viewCount - 1))), scaled: full > MAX_SCROLL_PX };
}

function scrollToPos(pos) {
  const list = $('#list'), g = scrollGeom();
  if (pos >= g.first && pos < g.first + Math.floor(g.viewH / ROW_H)) return;
  if (!g.scaled) { const top = pos * ROW_H; if (top < list.scrollTop) list.scrollTop = top; else list.scrollTop = top - g.viewH + ROW_H + 2; }
  else { const maxTop = Math.max(1, g.spacerH - g.viewH), span = Math.max(1, S.viewCount - Math.floor(g.viewH / ROW_H)); list.scrollTop = Math.round((Math.min(span, Math.max(0, pos - Math.floor(g.visible / 2))) / span) * maxTop); }
  renderRows();
}

function requestChunk(ci) {
  if (S.chunks.has(ci) || S.pendingChunks.has(ci)) return;
  S.pendingChunks.add(ci);
  vscode.postMessage({ type: 'rows', start: ci * CHUNK, count: CHUNK, seq: S.rowSeq, names: S.names, time: S.time });
}

function renderRows() {
  const list = $('#list'); if (!list) return;
  const g = scrollGeom();
  $('#spacer').style.height = g.spacerH + 'px';
  const rowsEl = $('#rows');
  rowsEl.style.transform = `translateY(${list.scrollTop}px)`;
  const end = Math.min(S.viewCount, g.first + g.visible);
  const need = new Set();
  for (let p = g.first; p < end; p++) need.add(Math.floor(p / CHUNK));
  // read ahead one chunk each way
  if (g.first > 0) need.add(Math.floor(Math.max(0, g.first - 40) / CHUNK));
  if (end < S.viewCount) need.add(Math.floor(Math.min(S.viewCount - 1, end + 40) / CHUNK));
  for (const ci of need) requestChunk(ci);
  const frag = document.createDocumentFragment();
  for (let p = g.first; p < end; p++) {
    const r = rowAt(p);
    const sel = r && S.selection.has(r.no);
    const el = h('div', { class: `row ${r ? 'p-' + (r.cls || 'x') : 'loading'}${sel ? ' sel' : ''}${p === S.selectedPos ? ' cur' : ''}`, role: 'row', 'data-pos': p, 'aria-rowindex': p + 1, 'aria-selected': sel ? 'true' : 'false' });
    if (r) {
      el.append(h('div', { class: 'c c0' }, r.no), h('div', { class: 'c c1' }, r.time), h('div', { class: 'c c2', title: r.src !== r.srcAddr ? r.srcAddr : '' }, r.src),
        h('div', { class: 'c c3', title: r.dst !== r.dstAddr ? r.dstAddr : '' }, r.dst), h('div', { class: 'c c4' }, r.proto), h('div', { class: 'c c5' }, r.len), h('div', { class: 'c c6', title: r.info }, r.info));
    } else el.append(h('div', { class: 'c c0' }, ''), h('div', { class: 'c c6' }, '...'));
    frag.append(el);
  }
  rowsEl.replaceChildren(frag);
  // drop far chunks so memory stays flat on a million-packet capture
  if (S.chunks.size > 60) { const keep = Math.floor(g.first / CHUNK); for (const k of [...S.chunks.keys()]) if (Math.abs(k - keep) > 20) S.chunks.delete(k); }
  updateCount();
}

function refreshRows() { S.chunks.clear(); S.pendingChunks.clear(); S.rowSeq++; renderRows(); }

function clickRow(pos, e) {
  const r = rowAt(pos); if (!r) return;
  if (e.shiftKey && S.anchorPos >= 0) {
    const a = Math.min(S.anchorPos, pos), b = Math.max(S.anchorPos, pos);
    if (!(e.metaKey || e.ctrlKey)) S.selection.clear();
    for (let p = a; p <= b; p++) { const x = rowAt(p); if (x) S.selection.add(x.no); }
  } else if (e.metaKey || e.ctrlKey) {
    if (S.selection.has(r.no)) S.selection.delete(r.no); else S.selection.add(r.no);
    S.anchorPos = pos;
  } else { S.selection = new Set([r.no]); S.anchorPos = pos; }
  select(pos, r.no);
}

function select(pos, no) {
  S.selectedPos = pos; S.selectedNo = no;
  scrollToPos(pos); renderRows();
  vscode.postMessage({ type: 'packet', no });
  $('#live').textContent = `Packet ${no} selected`;
}

function moveTo(pos, e) {
  pos = Math.max(0, Math.min(S.viewCount - 1, pos)); if (pos < 0) return;
  const go = () => { const r = rowAt(pos); if (!r) { requestChunk(Math.floor(pos / CHUNK)); setTimeout(go, 40); return; } clickRow(pos, e || {}); };
  scrollToPos(pos); go();
}

function listKey(e) {
  const g = scrollGeom(), cur = S.selectedPos < 0 ? -1 : S.selectedPos;
  const k = e.key;
  const ev = { shiftKey: e.shiftKey };
  if (k === 'ArrowDown') { e.preventDefault(); moveTo(cur + 1, ev); }
  else if (k === 'ArrowUp') { e.preventDefault(); moveTo(cur - 1, ev); }
  else if (k === 'PageDown') { e.preventDefault(); moveTo(cur + g.visible - 2, ev); }
  else if (k === 'PageUp') { e.preventDefault(); moveTo(cur - g.visible + 2, ev); }
  else if (k === 'Home') { e.preventDefault(); moveTo(0, ev); }
  else if (k === 'End') { e.preventDefault(); moveTo(S.viewCount - 1, ev); }
  else if (k === 'Enter') { e.preventDefault(); follow(); }
  else if ((e.metaKey || e.ctrlKey) && k.toLowerCase() === 'a') { e.preventDefault(); selectAllLoaded(); }
}

function selectAllLoaded() {
  // Select every shown packet (rows not loaded yet are added when the export runs as "shown packets").
  for (const c of S.chunks.values()) for (const r of c) S.selection.add(r.no);
  renderRows();
}

function updateCount() {
  const c = $('#count'); if (!c || !S.info) return;
  const sel = S.selection.size;
  c.textContent = (S.filter ? `${fmt(S.viewCount)} of ${fmt(S.total)} packets match` : `${fmt(S.total)} packets`) + (sel > 1 ? ` · ${fmt(sel)} selected` : '');
}

// ---------- detail tree ----------
function renderTree(p) {
  const t = $('#tree'); t.textContent = '';
  if (p.error) { t.append(h('p', { class: 'hint' }, p.error)); return; }
  const mk = (nodes, depth, parentEl) => {
    for (const n of nodes) {
      const has = n.c && n.c.length;
      const open = depth === 0 ? !!S.openLayers?.has(layerKey(n)) : false;
      const li = h('div', { class: 'tn' + (has ? ' has' : '') + (open ? ' open' : ''), role: 'treeitem', 'aria-expanded': has ? String(open) : null, 'data-s': n.s, 'data-l': n.l, tabindex: '-1', style: `padding-left:${depth * 14 + 4}px` },
        h('span', { class: 'tw', 'aria-hidden': 'true' }, has ? '' : ''), h('span', { class: 'tl' }, n.n));
      li._node = n;
      parentEl.append(li);
      if (has) { const kids = h('div', { class: 'kids', role: 'group' }); li._kids = kids; parentEl.append(kids); mk(n.c, depth + 1, kids); if (!open) kids.hidden = true; }
    }
  };
  mk(p.tree, 0, t);
  if (p.names && p.names.length) t.append(h('div', { class: 'names-note' }, 'Names: ' + p.names.map(x => `${x.addr} = ${x.name} (${x.from})`).join('; ')));
}

function layerKey(n) { return n.n.split(/[,:(]/)[0].trim(); }
S.openLayers = new Set();

function toggle(li, open) {
  if (!li._kids) return;
  const o = open ?? li._kids.hidden;
  li._kids.hidden = !o; li.classList.toggle('open', o); li.setAttribute('aria-expanded', String(o));
  if (li.parentElement && li.parentElement.id === 'tree') { const k = layerKey(li._node); if (o) S.openLayers.add(k); else S.openLayers.delete(k); }
}

function selectNode(li, scroll) {
  document.querySelectorAll('#tree .tn.sel').forEach(x => x.classList.remove('sel'));
  if (!li) { S.hexSel = null; renderHex(); return; }
  li.classList.add('sel'); li.focus({ preventScroll: true });
  if (scroll) li.scrollIntoView({ block: 'nearest' });
  const s = Number(li.dataset.s), l = Number(li.dataset.l);
  S.hexSel = l > 0 ? [s, s + l] : null;
  renderHex();
  if (S.hexSel) scrollHexTo(s, s + l);
}

function treeClick(e) {
  const li = e.target.closest('.tn'); if (!li) return;
  if (e.target.closest('.tw') || e.detail === 2) toggle(li);
  selectNode(li, false);
}

function treeKey(e) {
  const items = [...document.querySelectorAll('#tree .tn')].filter(x => x.offsetParent !== null);
  const cur = document.activeElement.closest && document.activeElement.closest('.tn');
  const i = items.indexOf(cur);
  if (e.key === 'ArrowDown') { e.preventDefault(); selectNode(items[Math.min(items.length - 1, i + 1)], true); }
  if (e.key === 'ArrowUp') { e.preventDefault(); selectNode(items[Math.max(0, i - 1)], true); }
  if (e.key === 'ArrowRight' && cur) { e.preventDefault(); toggle(cur, true); }
  if (e.key === 'ArrowLeft' && cur) { e.preventDefault(); toggle(cur, false); }
  if (e.key === 'Enter' && cur) { e.preventDefault(); toggle(cur); }
}

/** Click on a byte: select the smallest tree field that covers it, opening its parents. */
function byteClick(i) {
  let best = null;
  for (const li of document.querySelectorAll('#tree .tn')) {
    const s = Number(li.dataset.s), l = Number(li.dataset.l);
    if (l > 0 && i >= s && i < s + l && (!best || l < best.l || (l === best.l && li.compareDocumentPosition(best.li) & Node.DOCUMENT_POSITION_PRECEDING))) best = { li, l };
  }
  if (!best) { S.hexSel = [i, i + 1]; renderHex(); return; }
  // open every ancestor
  let el = best.li.parentElement;
  while (el && el.id !== 'tree') { if (el.classList.contains('kids')) { const owner = el.previousElementSibling; if (owner) toggle(owner, true); } el = el.parentElement; }
  selectNode(best.li, true);
  $('#live').textContent = `Byte ${i}: ${best.li.textContent}`;
}

// ---------- hex pane ----------
function renderHex() {
  const hx = $('#hex'); if (!hx) return;
  const rowsEl = $('#hexRows');
  if (!S.packet || !S.packet.bytes) { $('#hexSpacer').style.height = '0px'; rowsEl.textContent = ''; return; }
  const b = S.packet.bytes, n = Math.ceil(b.length / 16);
  $('#hexSpacer').style.height = n * HEX_ROW_H + 'px';
  const first = Math.floor(hx.scrollTop / HEX_ROW_H), count = Math.ceil(hx.clientHeight / HEX_ROW_H) + 1;
  rowsEl.style.transform = `translateY(${first * HEX_ROW_H}px)`;
  const [s0, s1] = S.hexSel || [-1, -1];
  const frag = document.createDocumentFragment();
  for (let r = first; r < Math.min(n, first + count); r++) {
    const row = h('div', { class: 'hrow' }, h('span', { class: 'hoff' }, (r * 16).toString(16).padStart(4, '0')));
    const hexs = h('span', { class: 'hbytes' }), txt = h('span', { class: 'htext' });
    for (let k = 0; k < 16; k++) {
      const i = r * 16 + k;
      if (i >= b.length) { hexs.append(h('span', { class: 'hb pad' }, '  ')); continue; }
      const on = i >= s0 && i < s1;
      hexs.append(h('span', { class: 'hb' + (on ? ' on' : '') + (k === 8 ? ' gap' : ''), 'data-i': i }, hex2(b[i])));
      const c = b[i];
      txt.append(h('span', { class: 'ht' + (on ? ' on' : ''), 'data-i': i }, c >= 32 && c < 127 ? String.fromCharCode(c) : '·'));
    }
    row.append(hexs, txt); frag.append(row);
  }
  rowsEl.replaceChildren(frag);
}

function scrollHexTo(s, e) {
  const hx = $('#hex'); const r0 = Math.floor(s / 16) * HEX_ROW_H, r1 = Math.floor((e - 1) / 16) * HEX_ROW_H + HEX_ROW_H;
  if (r0 < hx.scrollTop || r1 > hx.scrollTop + hx.clientHeight) hx.scrollTop = Math.max(0, r0 - HEX_ROW_H);
  renderHex();
}

// ---------- overlays: follow stream, statistics ----------
function overlay(title, body, actions = []) {
  closeOverlay();
  const o = h('div', { class: 'overlay', id: 'overlay', role: 'dialog', 'aria-label': title },
    h('div', { class: 'ohead' }, h('h2', {}, title), h('div', { class: 'oacts' }, ...actions, h('button', { onclick: closeOverlay, title: 'Close (Esc)' }, 'Close'))),
    h('div', { class: 'obody' }, body));
  o.addEventListener('keydown', e => { if (e.key === 'Escape') { e.stopPropagation(); closeOverlay(); } });
  $('.main').append(o);
  const f = o.querySelector('button, select'); if (f) f.focus();
  return o;
}
function closeOverlay() { const o = $('#overlay'); if (o) o.remove(); const l = $('#list'); if (l) l.focus(); }

function follow() {
  if (!S.selectedNo) { notice('info', 'Select a TCP or UDP packet first, then press Follow stream (or double-click the packet).'); return; }
  overlay(`Follow stream: packet ${S.selectedNo}`, h('p', { class: 'hint' }, 'Collecting the stream...'));
  vscode.postMessage({ type: 'follow', no: S.selectedNo });
}

const dec = new TextDecoder('utf-8', { fatal: false });
function showFollow(m) {
  if (m.error) { overlay('Follow stream', h('p', { class: 'hint' }, m.error)); return; }
  const P = m.proto.toUpperCase();
  let mode = 'ascii', dir = 'both';
  const body = h('div', { class: 'follow' });
  const render = () => {
    body.textContent = '';
    let shown = 0; const LIMIT = 4 * 1048576;
    for (const s of m.segments) {
      if (dir !== 'both' && String(s.dir) !== dir) continue;
      if (shown > LIMIT) { body.append(h('p', { class: 'hint' }, 'The rest of the stream is not shown here (more than 4 MB). Use "Save as" to get all of it.')); break; }
      shown += s.bytes.length;
      body.append(h('pre', { class: 'seg d' + s.dir, title: `Packets ${s.first}${s.last !== s.first ? ' to ' + s.last : ''} (${s.dir ? 'server to client' : 'client to server'})` }, segText(s.bytes, mode)));
    }
    if (!m.segments.length) body.append(h('p', { class: 'hint' }, 'This stream has no payload bytes (only handshake or empty packets).'));
  };
  const modeSel = h('select', { 'aria-label': 'Show as', onchange: e => { mode = e.target.value; render(); } }, h('option', { value: 'ascii' }, 'ASCII'), h('option', { value: 'utf8' }, 'UTF-8'), h('option', { value: 'hex' }, 'Hex dump'));
  const dirSel = h('select', { 'aria-label': 'Direction', onchange: e => { dir = e.target.value; render(); } },
    h('option', { value: 'both' }, `Both directions (${fmtSize(m.bytes[0] + m.bytes[1])})`), h('option', { value: '0' }, `${m.client} → ${m.server} (${fmtSize(m.bytes[0])})`), h('option', { value: '1' }, `${m.server} → ${m.client} (${fmtSize(m.bytes[1])})`));
  const all = () => m.segments.filter(s => dir === 'both' || String(s.dir) === dir).map(s => segText(s.bytes, mode)).join(mode === 'hex' ? '\n' : '');
  overlay(`Follow ${P} stream ${m.stream} (${m.filter})`, h('div', {},
    h('div', { class: 'fbar' }, modeSel, dirSel,
      h('span', { class: 'legend' }, h('span', { class: 'sw d0' }), ' client to server  ', h('span', { class: 'sw d1' }), ' server to client'),
      m.truncated ? h('span', { class: 'warn' }, ' Only the first 16 MB are collected.') : null),
    body), [
    h('button', { onclick: () => { closeOverlay(); setFilter(m.filter); } }, 'Filter on this stream'),
    h('button', { onclick: () => vscode.postMessage({ type: 'copy', what: `${P} stream ${m.stream}`, text: all() }) }, 'Copy'),
    h('button', { onclick: () => vscode.postMessage({ type: 'saveStream', name: `${S.name.replace(/\.[^.]*$/, '').replace(/\.pcap(ng)?$/, '')}-${m.proto}-stream-${m.stream}.txt`, text: all() }) }, 'Save as...'),
  ]);
  render();
}

function segText(b, mode) {
  if (mode === 'utf8') return dec.decode(b);
  if (mode === 'ascii') { let s = ''; for (let i = 0; i < b.length; i++) { const c = b[i]; s += c === 10 || c === 13 || c === 9 || (c >= 32 && c < 127) ? String.fromCharCode(c) : '.'; } return s; }
  const out = [];
  for (let o = 0; o < b.length; o += 16) {
    const sl = b.subarray(o, o + 16);
    out.push(o.toString(16).padStart(8, '0') + '  ' + [...sl].map(hex2).join(' ').padEnd(48) + '  ' + [...sl].map(c => (c >= 32 && c < 127 ? String.fromCharCode(c) : '.')).join(''));
  }
  return out.join('\n') + '\n';
}

function showStats() {
  overlay('Statistics', h('p', { class: 'hint' }, 'Reading every packet...'));
  vscode.postMessage({ type: 'stats' });
}

function table(cols, rows, onRow) {
  let sortBy = cols.findIndex(c => c.sort) >= 0 ? cols.findIndex(c => c.sort) : -1, desc = true;
  const wrap = h('div', { class: 'tablewrap' });
  const draw = () => {
    const sorted = sortBy < 0 ? rows : [...rows].sort((a, b) => { const x = cols[sortBy].v(a), y = cols[sortBy].v(b); return (x < y ? -1 : x > y ? 1 : 0) * (desc ? -1 : 1); });
    const t = h('table', { class: 'stats' },
      h('thead', {}, h('tr', {}, ...cols.map((c, i) => h('th', { class: c.num ? 'num' : '', onclick: () => { if (sortBy === i) desc = !desc; else { sortBy = i; desc = !!c.num; } draw(); }, title: 'Sort' }, c.t + (sortBy === i ? (desc ? ' ▾' : ' ▴') : ''))))),
      h('tbody', {}, ...sorted.slice(0, 5000).map(r => h('tr', { tabindex: onRow ? '0' : null, title: onRow ? 'Click to filter on this row' : '', onclick: onRow ? () => onRow(r) : null, onkeydown: onRow ? e => { if (e.key === 'Enter') onRow(r); } : null }, ...cols.map(c => h('td', { class: c.num ? 'num' : '' }, c.f ? c.f(r) : c.v(r)))))));
    wrap.replaceChildren(t);
    if (sorted.length > 5000) wrap.append(h('p', { class: 'hint' }, `Showing 5,000 of ${fmt(sorted.length)} rows.`));
  };
  draw();
  return wrap;
}

function showStatsData(m) {
  S.statsData = m;
  const tabs = ['Protocol hierarchy', 'Conversations', 'Endpoints', 'Names'];
  let cur = 0, kind = null;
  const body = h('div', { class: 'statbody' });
  const tabBar = h('div', { class: 'tabs', role: 'tablist' });
  const kindsOf = list => [...new Set(list.map(x => x.kind))];
  const pct = (a, b) => (b ? (100 * a / b).toFixed(1) + ' %' : '');
  const draw = () => {
    tabBar.replaceChildren(...tabs.map((t, i) => h('button', { role: 'tab', 'aria-selected': String(i === cur), class: i === cur ? 'on' : '', onclick: () => { cur = i; kind = null; draw(); } }, t)));
    body.textContent = '';
    if (cur === 0) {
      // fold the protocol paths into a tree with counts
      const root = { c: new Map(), packets: 0, bytes: 0 };
      for (const r of m.hierarchy) { let n = root; for (const p of r.path.split('/').filter(Boolean)) { if (!n.c.has(p)) n.c.set(p, { c: new Map(), packets: 0, bytes: 0 }); n = n.c.get(p); n.packets += r.packets; n.bytes += r.bytes; } }
      const rows = [];
      const walk = (n, depth) => { for (const [k, v] of [...n.c.entries()].sort((a, b) => b[1].packets - a[1].packets)) { rows.push({ name: k, depth, packets: v.packets, bytes: v.bytes }); walk(v, depth + 1); } };
      walk(root, 0);
      body.append(h('table', { class: 'stats' }, h('thead', {}, h('tr', {}, h('th', {}, 'Protocol'), h('th', { class: 'num' }, 'Packets'), h('th', { class: 'num' }, '% packets'), h('th', { class: 'num' }, 'Bytes'))),
        h('tbody', {}, ...rows.map(r => h('tr', { tabindex: '0', title: 'Click to filter on this protocol', onclick: () => { closeOverlay(); setFilter(protoFilter(r.name)); } },
          h('td', { style: `padding-left:${r.depth * 16 + 6}px` }, r.name), h('td', { class: 'num' }, fmt(r.packets)), h('td', { class: 'num' }, pct(r.packets, m.total)), h('td', { class: 'num' }, fmt(r.bytes)))))));
    } else if (cur === 1 || cur === 2) {
      const list = cur === 1 ? m.conversations : m.endpoints;
      const kinds = kindsOf(list); if (!kind || !kinds.includes(kind)) kind = kinds.includes('TCP') ? 'TCP' : kinds[0];
      body.append(h('div', { class: 'kinds' }, ...kinds.map(k => h('button', { class: k === kind ? 'on' : '', onclick: () => { kind = k; draw(); } }, `${k} (${list.filter(x => x.kind === k).length})`))));
      const rows = list.filter(x => x.kind === kind);
      const fld = k => ({ Ethernet: 'eth.addr', IPv4: 'ip.addr', IPv6: 'ipv6.addr' }[k]);
      const split = a => { const m2 = /^\[?(.*?)\]?:(\d+)$/.exec(a); return m2 ? [m2[1], m2[2]] : [a, '']; };
      if (cur === 1) {
        body.append(table([
          { t: 'Address A', v: r => r.a }, { t: 'Address B', v: r => r.b }, { t: 'Packets', v: r => r.packets, num: 1, sort: 1, f: r => fmt(r.packets) }, { t: 'Bytes', v: r => r.bytes, num: 1, f: r => fmt(r.bytes) },
          { t: 'A → B', v: r => r.abp, num: 1, f: r => fmt(r.abp) }, { t: 'B → A', v: r => r.bap, num: 1, f: r => fmt(r.bap) }, { t: 'Start (s)', v: r => r.start, num: 1, f: r => r.start.toFixed(3) }, { t: 'Duration (s)', v: r => r.end - r.start, num: 1, f: r => (r.end - r.start).toFixed(3) },
        ], rows, r => { closeOverlay(); if (r.stream !== undefined && (kind === 'TCP' || kind === 'UDP')) setFilter(`${kind.toLowerCase()}.stream == ${r.stream}`); else setFilter(`${fld(kind)} == ${r.a} && ${fld(kind)} == ${r.b}`); }));
      } else {
        body.append(table([
          { t: 'Address', v: r => r.addr }, { t: 'Name (from the capture)', v: r => r.name || '' }, { t: 'Packets', v: r => r.packets, num: 1, sort: 1, f: r => fmt(r.packets) }, { t: 'Bytes', v: r => r.bytes, num: 1, f: r => fmt(r.bytes) },
          { t: 'Sent', v: r => r.txp, num: 1, f: r => fmt(r.txp) }, { t: 'Received', v: r => r.rxp, num: 1, f: r => fmt(r.rxp) },
        ], rows, r => { closeOverlay(); if (kind === 'TCP' || kind === 'UDP') { const [a, p] = split(r.addr); setFilter(`${a.includes(':') ? 'ipv6' : 'ip'}.addr == ${a} && ${kind.toLowerCase()}.port == ${p}`); } else setFilter(`${fld(kind)} == ${r.addr}`); }));
      }
      if ((cur === 1 ? m.convCount : m.epCount) > list.length) body.append(h('p', { class: 'hint' }, `The largest ${fmt(list.length)} by bytes are listed.`));
    } else {
      body.append(h('p', { class: 'hint' }, 'Names come only from this capture: DNS answers in its packets and name resolution blocks in pcapng files. Nothing is looked up on the network.'));
      body.append(table([{ t: 'Address', v: r => r.addr }, { t: 'Name', v: r => r.name, sort: 0 }, { t: 'Source', v: r => r.from }], m.names, r => { closeOverlay(); setFilter(`${r.addr.includes(':') ? 'ipv6' : 'ip'}.addr == ${r.addr}`); }));
      if (!m.names.length) body.append(h('p', { class: 'hint' }, 'This capture has no DNS answers or name blocks.'));
    }
  };
  draw();
  overlay(`Statistics: ${fmt(m.total)} packets`, h('div', {}, tabBar, body));
}

// ---------- notices ----------
function notice(level, text, sticky) {
  const box = $('#notices'); if (!box) return;
  const n = h('div', { class: 'notice ' + level, role: level === 'error' ? 'alert' : 'status' }, h('span', {}, text), h('button', { class: 'x', title: 'Dismiss', 'aria-label': 'Dismiss', onclick: () => n.remove() }, '×'));
  box.append(n);
  if (!sticky) setTimeout(() => n.remove(), 6000);
}

// ---------- progress / error views ----------
function showProgress(m) {
  if (S.info) {
    if (m.phase === 'filter') $('#count').textContent = `Filtering... ${Math.floor(100 * m.done / Math.max(1, m.total))} % (${fmt(m.matches)} match so far)`;
    if (m.phase === 'stats') { const o = $('#overlay .obody .hint'); if (o) o.textContent = `Reading every packet... ${Math.floor(100 * m.done / Math.max(1, m.total))} %`; }
    return;
  }
  let box = $('#progress');
  if (!box) { app.textContent = ''; box = h('div', { id: 'progress', class: 'progress', role: 'progressbar', 'aria-valuemin': '0', 'aria-valuemax': '100' }, h('p', { id: 'ptext' }), h('div', { class: 'pbar' }, h('div', { id: 'pfill', class: 'pfill' }))); app.append(box); }
  const pct = Math.floor(100 * m.done / Math.max(1, m.total));
  box.setAttribute('aria-valuenow', String(pct));
  $('#pfill').style.width = pct + '%';
  $('#ptext').textContent = m.phase === 'unzip' ? `Unpacking the .gz file: ${fmtSize(m.done)} of ${fmtSize(m.total)} read, ${fmtSize(m.out)} unpacked` : `Indexing packets: ${pct} % of ${fmtSize(m.total)}${m.packets ? `, ${fmt(m.packets)} packets` : ''}`;
}

function showError(info) {
  app.textContent = '';
  app.append(h('div', { class: 'errorview', role: 'alert' }, h('h2', {}, `${S.name} cannot be shown`), h('p', {}, info.error),
    h('p', { class: 'hint' }, 'PCAP Viewer opens pcap (microsecond and nanosecond, either byte order), pcapng and the same files compressed as .gz.'),
    ...(info.warnings || []).map(w => h('p', { class: 'hint' }, w))));
}

// ---------- messages ----------
window.addEventListener('message', ev => {
  const m = ev.data;
  switch (m.type) {
    case 'progress': showProgress(m); break;
    case 'init': {
      S.name = m.name; S.settings = m.settings || {};
      if (!m.info || (m.info.error && !m.info.count)) { showError(m.info || { error: 'The file could not be opened.' }); return; }
      S.info = m.info; S.total = m.info.count; S.viewCount = m.viewCount ?? m.info.count;
      S.names = S.settings.resolveNames !== false; S.time = S.settings.timeFormat || 'relative';
      buildLayout();
      $('#namesChk').checked = S.names; $('#timeSel').value = S.time;
      const I = m.info;
      $('#fileinfo').textContent = `${I.format}${I.compressed ? ' (gzip, ' + fmtSize(I.compressed) + ' packed)' : ''} · ${fmtSize(I.size)} · ${I.interfaces.map(f => f.linkName + (f.name ? ` (${f.name})` : '')).filter((v, i, a) => a.indexOf(v) === i).join(', ')} · ${I.duration.toFixed(3)} s${I.names ? ` · ${fmt(I.names)} name${I.names === 1 ? '' : 's'} from the capture` : ''} · indexed in ${fmt(I.ms)} ms`;
      for (const w of I.warnings || []) notice('warn', w, true);
      if (!S.total) notice('info', 'This capture is valid but holds no packets.', true);
      if (m.filter) { $('#filter').value = m.filter; S.filter = m.filter; checkFilter(m.filter); }
      renderRows();
      if (S.total) setTimeout(() => moveTo(0), 0);
      $('#list').focus();
      vscode.postMessage({ type: 'rendered' });
      break;
    }
    case 'rows': {
      if (m.seq !== S.rowSeq) break;
      const ci = Math.floor(m.start / CHUNK);
      S.pendingChunks.delete(ci); S.chunks.set(ci, m.rows);
      renderRows();
      break;
    }
    case 'packet': S.packet = m; S.hexSel = null; $('#hex').scrollTop = 0; renderTree(m); renderHex(); break;
    case 'filtered': {
      if (m.seq !== S.filterSeq) break;
      if (!m.ok) { $('#filterErr').textContent = m.error || ''; $('#filter').classList.add('bad'); updateCount(); break; }
      S.filter = (m.expr || '').trim(); S.viewCount = m.count; S.selection.clear(); S.selectedPos = -1;
      $('#list').scrollTop = 0; refreshRows();
      if (S.selectedNo) vscode.postMessage({ type: 'find', no: S.selectedNo });
      if (S.filter && !m.count) notice('info', 'No packet matches this filter.');
      break;
    }
    case 'found': if (m.pos >= 0) { S.selectedPos = m.pos; S.selection = new Set([m.no]); scrollToPos(m.pos); renderRows(); } else if (S.viewCount) moveTo(0); break;
    case 'follow': showFollow(m); break;
    case 'stats': showStatsData(m); break;
    case 'notice': notice(m.level || 'info', m.message, m.level === 'error'); break;
    case 'config': S.settings = m.settings || S.settings; break;
    case 'focusFilter': $('#filter') && ($('#filter').focus(), $('#filter').select()); break;
    case 'followSelected': follow(); break;
    case 'showStats': showStats(); break;
    case 'exportSelected': if (S.selection.size) vscode.postMessage({ type: 'export', which: [...S.selection].sort((a, b) => a - b) }); else notice('info', 'Select packets first (Shift or Ctrl/Cmd + click selects more than one).'); break;
    case 'goto': {
      const no = m.no;
      if (!S.filter) moveTo(no - 1); else { S.selectedNo = no; vscode.postMessage({ type: 'find', no }); vscode.postMessage({ type: 'packet', no }); }
      break;
    }
  }
});

// Read-only state for the release check (scripts/e2e-vscode.mjs). Nothing calls it in normal use.
window.pcapViewerProbe = () => ({
  rendered: !!S.info, error: !S.info ? ($('.errorview') || {}).textContent || '' : '', progress: ($('#ptext') || {}).textContent || '',
  total: S.total, viewCount: S.viewCount, filter: S.filter, selectedNo: S.selectedNo, selection: S.selection.size,
  count: ($('#count') || {}).textContent || '', fileinfo: ($('#fileinfo') || {}).textContent || '', filterErr: ($('#filterErr') || {}).textContent || '',
  rows: [...document.querySelectorAll('#rows .row[data-pos]')].slice(0, 40).map(r => [...r.children].map(c => c.textContent)),
  tree: [...document.querySelectorAll('#tree .tn')].filter(x => x.offsetParent !== null).map(x => x.textContent),
  treeSel: ($('#tree .tn.sel') || {}).textContent || '', hexSel: S.hexSel, hexOn: [...document.querySelectorAll('#hexRows .hb.on')].map(x => x.textContent).join(' '),
  notices: [...document.querySelectorAll('#notices .notice span')].map(x => x.textContent), overlay: ($('#overlay') || {}).innerText || '',
  packetLen: S.packet && S.packet.bytes ? S.packet.bytes.length : 0,
});

vscode.postMessage({ type: 'ready' });
