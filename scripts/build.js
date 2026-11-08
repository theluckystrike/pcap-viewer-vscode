'use strict';
// Bundles the extension host and the webview with esbuild. No runtime dependencies.
const esbuild = require('esbuild');
const path = require('path');
const root = path.join(__dirname, '..');
const prod = process.argv.includes('--production');
const common = { bundle: true, minify: prod, sourcemap: false, legalComments: 'none', logLevel: 'warning', absWorkingDir: root };
(async () => {
  await Promise.all([
    esbuild.build({ ...common, entryPoints: ['src/extension.js'], outfile: 'dist/extension.js', platform: 'node', format: 'cjs', target: 'node18', external: ['vscode'] }),
    esbuild.build({ ...common, entryPoints: ['src/core/worker.js'], outfile: 'dist/worker.js', platform: 'node', format: 'cjs', target: 'node18' }),
    esbuild.build({ ...common, entryPoints: ['src/webview/main.js'], outfile: 'dist/webview.js', platform: 'browser', format: 'iife', target: 'chrome110' }),
  ]);
  const fs = require('fs');
  console.log(`built: extension ${(fs.statSync(path.join(root, 'dist/extension.js')).size / 1024).toFixed(0)} KB, worker ${(fs.statSync(path.join(root, 'dist/worker.js')).size / 1024).toFixed(0)} KB, webview ${(fs.statSync(path.join(root, 'dist/webview.js')).size / 1024).toFixed(0)} KB`);
})().catch(e => { console.error(e); process.exit(1); });
