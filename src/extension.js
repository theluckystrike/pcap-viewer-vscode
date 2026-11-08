'use strict';
const vscode = require('vscode');
const path = require('path');
const { Worker } = require('worker_threads');
const { buildHtml } = require('./html');
const { validate } = require('./protocol');
const { createRatingPrompt } = require('./rate');
const { registerSupport, commandUris, showLinks } = require('./support');

const VIEW_CAP = 'pcapViewer.capture';   // default for .pcap, .pcapng and their .gz forms
const VIEW_ANY = 'pcapViewer.any';       // "Open With" for .cap, .dmp and any other file
const EXT_ID = 'zovo.pcap-viewer';
let rating = { success() {}, failure() {} };

function settings() {
  const c = vscode.workspace.getConfiguration('pcapViewer');
  return {
    timeFormat: c.get('timeFormat', 'relative'),
    resolveNames: c.get('resolveNames', true),
    maxGzipMB: c.get('maxGzipMB', 512),
    maxRemoteMB: c.get('maxRemoteMB', 256),
    savedFilters: (c.get('savedFilters', []) || []).filter(f => f && typeof f.filter === 'string').slice(0, 200),
    showHex: c.get('showHex', true),
  };
}

function fmtSize(n) {
  if (n < 1024) return `${n} B`;
  const u = ['KB', 'MB', 'GB', 'TB']; let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return `${n.toFixed(n < 10 ? 2 : 1)} ${u[i]}`;
}

/** Talks to the worker thread that owns one capture. */
class WorkerClient {
  constructor(script, onProgress) {
    this.w = new Worker(script, { resourceLimits: { maxOldGenerationSizeMb: 2048 } });
    this.seq = 0; this.pending = new Map(); this.dead = null;
    this.w.on('message', m => {
      if (m.progress) { onProgress(m); return; }
      const p = this.pending.get(m.id); if (!p) return;
      this.pending.delete(m.id);
      if (m.error) p.reject(new Error(m.error)); else p.resolve(m.result);
    });
    const fail = e => { this.dead = e || new Error('The capture reader stopped.'); for (const p of this.pending.values()) p.reject(this.dead); this.pending.clear(); };
    this.w.on('error', e => fail(e));
    this.w.on('exit', code => { if (code !== 0) fail(new Error(`The capture reader stopped (code ${code}). The file may be too large for the memory limit.`)); });
  }
  call(op, args) {
    if (this.dead) return Promise.reject(this.dead);
    const id = ++this.seq;
    return new Promise((resolve, reject) => { this.pending.set(id, { resolve, reject }); this.w.postMessage({ id, op, args }); });
  }
  dispose() { try { this.w.terminate(); } catch {} }
}

class CaptureDoc {
  constructor(uri) { this.uri = uri; this.panels = new Set(); this.client = null; this.info = null; this.opening = null; this.lastProgress = null; this.filterSeq = 0; this.filterText = ''; this.viewCount = 0; }
  post(m) { for (const p of this.panels) p.webview.postMessage(m).then(undefined, () => {}); }
  dispose() { if (this.client) { this.client.call('close', {}).catch(() => {}); setTimeout(() => this.client.dispose(), 200); } }
}

class CaptureProvider {
  constructor(context, shared) { this.context = context; this.shared = shared; }

  openCustomDocument(uri) { return new CaptureDoc(uri); }

  /** Start the worker and index the file once per document. */
  ensureOpen(doc) {
    if (doc.opening) return doc.opening;
    doc.opening = (async () => {
      doc.client = new WorkerClient(path.join(this.context.extensionPath, 'dist', 'worker.js'), m => { doc.lastProgress = m; doc.post({ type: 'progress', ...m }); });
      const s = settings();
      const lower = doc.uri.path.toLowerCase();
      let gz = /\.gz$/.test(lower);
      let fsPath = doc.uri.scheme === 'file' ? doc.uri.fsPath : null;
      if (!fsPath) {
        // Remote and virtual file systems: read the bytes through VS Code (with a size cap) into a temp file.
        const stat = await vscode.workspace.fs.stat(doc.uri);
        if (stat.size > s.maxRemoteMB * 1048576) return { error: `This file is ${fmtSize(stat.size)}. Files on remote or virtual file systems open up to ${s.maxRemoteMB} MB (setting pcapViewer.maxRemoteMB). Local files of any size open.` };
        const bytes = await vscode.workspace.fs.readFile(doc.uri);
        const os = require('os'), fs = require('fs');
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pcapv-'));
        fsPath = path.join(dir, path.basename(doc.uri.path) || 'capture');
        fs.writeFileSync(fsPath, bytes);
        doc.tempDir = dir;
      }
      if (!gz) {
        // A .pcap that is really gzip data (some tools do that) opens too.
        try { const fs = require('fs'); const fd = fs.openSync(fsPath, 'r'); const b = Buffer.alloc(2); fs.readSync(fd, b, 0, 2, 0); fs.closeSync(fd); gz = b[0] === 0x1f && b[1] === 0x8b; } catch {}
      }
      const info = await doc.client.call('open', { path: fsPath, opts: { gz, maxGzipMB: s.maxGzipMB } });
      doc.info = info; doc.viewCount = info.count || 0;
      return info;
    })().catch(e => ({ error: errorText(e) }));
    return doc.opening;
  }

  async resolveCustomEditor(doc, panel) {
    const ctx = this.context;
    const dist = vscode.Uri.joinPath(ctx.extensionUri, 'dist'), media = vscode.Uri.joinPath(ctx.extensionUri, 'media');
    panel.webview.options = { enableScripts: true, localResourceRoots: [dist, media], enableCommandUris: [...commandUris('pcapViewer'), 'workbench.action.openSettings'] };
    const name = path.posix.basename(doc.uri.path);
    panel.webview.html = buildHtml({
      cspSource: panel.webview.cspSource,
      scriptUri: panel.webview.asWebviewUri(vscode.Uri.joinPath(dist, 'webview.js')).toString(),
      styleUri: panel.webview.asWebviewUri(vscode.Uri.joinPath(media, 'webview.css')).toString(),
      title: name, showSupportLinks: showLinks(vscode, 'pcapViewer'),
    });
    doc.panels.add(panel);
    const me = { doc, panel, selected: 0 };
    let disposed = false, counted = false;
    const post = m => (disposed ? Promise.resolve(false) : panel.webview.postMessage(m));
    const setActive = () => { if (panel.active) { this.shared.active = me; } else if (this.shared.active === me) this.shared.active = null; this.shared.showStatus(); };
    panel.onDidChangeViewState(setActive); setActive();
    const cfgSub = vscode.workspace.onDidChangeConfiguration(e => { if (e.affectsConfiguration('pcapViewer')) post({ type: 'config', settings: settings() }); });

    panel.webview.onDidReceiveMessage(async raw => {
      const msg = validate(raw);
      if (!msg) return;
      try {
        if (msg.type === 'ready') {
          if (doc.lastProgress && !doc.info) post({ type: 'progress', ...doc.lastProgress });
          const info = await this.ensureOpen(doc);
          if (info.error && !info.count) rating.failure();
          await post({ type: 'init', name, info, settings: settings(), filter: doc.filterText, viewCount: doc.viewCount });
          this.shared.showStatus();
          return;
        }
        if (!doc.client || !doc.info) return;
        const c = doc.client;
        switch (msg.type) {
          case 'rendered': if (!counted && !doc.info.error) { counted = true; rating.success(); } return;
          case 'rows': { const r = await c.call('rows', { start: msg.start, count: msg.count, opts: { names: msg.names, time: msg.time } }); await post({ type: 'rows', seq: msg.seq, ...r }); return; }
          case 'packet': { me.selected = msg.no; const r = await c.call('packet', { no: msg.no }); await post({ type: 'packet', ...r }); this.shared.showStatus(); return; }
          case 'find': { const r = await c.call('find', { no: msg.no }); await post({ type: 'found', no: msg.no, pos: r.pos }); return; }
          case 'filter': {
            doc.filterSeq = msg.seq;
            const r = await c.call('filter', { expr: msg.expr });
            if (r.cancelled) return;
            if (r.ok) { doc.filterText = msg.expr; doc.viewCount = r.count; }
            await post({ type: 'filtered', seq: msg.seq, expr: msg.expr, ...r });
            this.shared.showStatus();
            return;
          }
          case 'stats': { const r = await c.call('stats', {}); await post({ type: 'stats', ...r }); return; }
          case 'follow': { const r = await c.call('follow', { no: msg.no }); await post({ type: 'follow', no: msg.no, ...r }); return; }
          case 'export': await this.exportPackets(doc, msg.which, post); return;
          case 'saveFilter': await saveFilter(msg.expr); return;
          case 'manageFilters': await vscode.commands.executeCommand('workbench.action.openSettings', 'pcapViewer.savedFilters'); return;
          case 'openSettings': await vscode.commands.executeCommand('workbench.action.openSettings', 'pcapViewer'); return;
          case 'copy': await vscode.env.clipboard.writeText(msg.text); await post({ type: 'notice', level: 'info', message: `Copied ${msg.what}.` }); return;
          case 'saveStream': {
            const dest = await vscode.window.showSaveDialog({ defaultUri: vscode.Uri.joinPath(doc.uri, '..', msg.name), filters: { Text: ['txt'], 'All files': ['*'] } });
            if (dest) { await vscode.workspace.fs.writeFile(dest, Buffer.from(msg.text, 'utf8')); await post({ type: 'notice', level: 'info', message: `Saved ${path.posix.basename(dest.path)}.` }); }
            return;
          }
          case 'error': console.error('[pcap-viewer webview]', msg.message); return;
        }
      } catch (e) {
        await post({ type: 'notice', level: 'error', message: errorText(e) });
      }
    });
    panel.onDidDispose(() => {
      disposed = true; cfgSub.dispose(); doc.panels.delete(panel);
      if (this.shared.active === me) { this.shared.active = null; this.shared.showStatus(); }
    });
  }

  async exportPackets(doc, which, post) {
    const base = path.posix.basename(doc.uri.path).replace(/\.(pcapng|pcap|cap)(\.gz)?$/i, '');
    const label = which === 'view' ? (doc.filterText ? 'filtered' : 'all') : 'selected';
    const defaultUri = doc.uri.scheme === 'file' ? vscode.Uri.file(path.join(path.dirname(doc.uri.fsPath), `${base}-${label}.pcap`)) : undefined;
    const dest = await vscode.window.showSaveDialog({ defaultUri, saveLabel: 'Export packets', filters: { 'Packet capture': ['pcap', 'pcapng'] } });
    if (!dest) return;
    if (dest.scheme !== 'file') { await post({ type: 'notice', level: 'warn', message: 'Export writes to a local file only. Pick a folder on this computer.' }); return; }
    const r = await doc.client.call('export', { path: dest.fsPath, which });
    const msg = `Exported ${r.count.toLocaleString('en-US')} packet${r.count === 1 ? '' : 's'} (${fmtSize(r.bytes)}) to ${path.basename(dest.fsPath)}${r.format === 'pcapng' ? ' as pcapng, because the packets have more than one link type' : ''}.`;
    await post({ type: 'notice', level: 'info', message: msg });
  }

  dispose() {}
}

async function saveFilter(expr) {
  const name = await vscode.window.showInputBox({ title: 'Save display filter', prompt: `Name for the filter: ${expr}`, value: expr.length < 40 ? expr : '', validateInput: s => (s.trim() ? null : 'Type a name.') });
  if (!name) return;
  const c = vscode.workspace.getConfiguration('pcapViewer');
  const list = (c.get('savedFilters', []) || []).filter(f => f && f.name !== name.trim());
  list.push({ name: name.trim(), filter: expr });
  await c.update('savedFilters', list, vscode.ConfigurationTarget.Global);
}

function errorText(e) {
  const code = e && e.code;
  const m = { EACCES: 'You do not have permission to read this file.', EPERM: 'The system does not allow this file to be read.', ENOENT: 'The file does not exist (it was moved or deleted).', EISDIR: 'This is a folder, not a file.', FileNotFound: 'The file does not exist (it was moved or deleted).', NoPermissions: 'You do not have permission to read this file.' }[code];
  if (m) return `${m} (${code})`;
  const msg = (e && e.message) || String(e);
  if (/EACCES/.test(msg)) return 'You do not have permission to read this file. (' + msg + ')';
  return msg;
}

function activeUri() {
  try { const t = vscode.window.tabGroups.activeTabGroup.activeTab; if (t && t.input && t.input.uri) return t.input.uri; } catch {}
  return vscode.window.activeTextEditor ? vscode.window.activeTextEditor.document.uri : undefined;
}

function activate(context) {
  rating = createRatingPrompt({ vscode, context, extensionId: EXT_ID, section: 'pcapViewer', name: 'PCAP Viewer' });
  registerSupport({ vscode, context, prefix: 'pcapViewer', selfId: EXT_ID });
  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  status.tooltip = 'PCAP Viewer: packets shown / packets in the file';
  context.subscriptions.push(status);
  const shared = {
    active: null,
    showStatus() {
      const a = this.active;
      if (!a || !a.doc.info || a.doc.info.error && !a.doc.info.count) { status.hide(); return; }
      const total = a.doc.info.count, shown = a.doc.viewCount;
      status.text = `$(pulse) ${shown === total ? total.toLocaleString('en-US') + ' packets' : `${shown.toLocaleString('en-US')} of ${total.toLocaleString('en-US')} packets`}${a.selected ? ` · #${a.selected}` : ''}`;
      status.show();
    },
  };
  for (const vt of [VIEW_CAP, VIEW_ANY]) {
    context.subscriptions.push(vscode.window.registerCustomEditorProvider(vt, new CaptureProvider(context, shared), {
      supportsMultipleEditorsPerDocument: true, webviewOptions: { retainContextWhenHidden: true },
    }));
  }
  const post = m => { if (shared.active) shared.active.panel.webview.postMessage(m); else vscode.window.showInformationMessage('Open a capture in PCAP Viewer first.'); };
  context.subscriptions.push(
    vscode.commands.registerCommand('pcapViewer.openWalkthrough', () => vscode.commands.executeCommand('workbench.action.openWalkthrough', `${EXT_ID}#pcapViewer.start`, false)),
    vscode.commands.registerCommand('pcapViewer.openWith', async (uri, uris) => {
      const list = Array.isArray(uris) && uris.length ? uris : [uri && uri.scheme ? uri : activeUri()];
      if (!list[0]) {
        const picked = await vscode.window.showOpenDialog({ canSelectMany: true, openLabel: 'Open in PCAP Viewer', filters: { 'Packet capture': ['pcap', 'pcapng', 'cap', 'gz', 'dmp'], 'All files': ['*'] } });
        if (picked) list.splice(0, 1, ...picked); else return;
      }
      for (const u of list.filter(Boolean)) await vscode.commands.executeCommand('vscode.openWith', u, VIEW_ANY);
    }),
    vscode.commands.registerCommand('pcapViewer.focusFilter', () => post({ type: 'focusFilter' })),
    vscode.commands.registerCommand('pcapViewer.followStream', () => post({ type: 'followSelected' })),
    vscode.commands.registerCommand('pcapViewer.statistics', () => post({ type: 'showStats' })),
    vscode.commands.registerCommand('pcapViewer.exportSelected', () => post({ type: 'exportSelected' })),
    vscode.commands.registerCommand('pcapViewer.goToPacket', async () => {
      if (!shared.active) { post({}); return; }
      const total = shared.active.doc.info ? shared.active.doc.info.count : 0;
      const v = await vscode.window.showInputBox({ title: 'Go to packet', prompt: `Packet number, 1 to ${total.toLocaleString('en-US')}`, validateInput: s => (/^\d+$/.test(s.trim()) && +s >= 1 && +s <= total ? null : `Type a number from 1 to ${total}.`) });
      if (v) post({ type: 'goto', no: Number(v) });
    }),
  );
}

function deactivate() {}

module.exports = { activate, deactivate, settings, errorText, VIEW_CAP, VIEW_ANY };
