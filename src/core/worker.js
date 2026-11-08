'use strict';
// Worker thread entry: owns one capture and answers requests from the extension host.
const { parentPort, workerData } = require('worker_threads');
const { Engine } = require('./engine');

const engine = new Engine(m => parentPort.postMessage({ ...m, progress: true }));

parentPort.on('message', async req => {
  const { id, op, args } = req;
  try {
    let result;
    switch (op) {
      case 'open': result = await engine.open(args.path, args.opts); break;
      case 'rows': result = engine.rows(args.start, args.count, args.opts); break;
      case 'packet': result = engine.packet(args.no); break;
      case 'filter': result = await engine.filter(args.expr, id); break;
      case 'find': result = { pos: engine.find(args.no) }; break;
      case 'stats': result = await engine.stats(); break;
      case 'follow': result = await engine.follow(args.no); break;
      case 'export': result = engine.exportTo(args.path, args.which); break;
      case 'close': engine.close(); result = { ok: true }; break;
      default: throw new Error('unknown op ' + op);
    }
    parentPort.postMessage({ id, result });
  } catch (e) {
    parentPort.postMessage({ id, error: (e && e.message) || String(e) });
  }
});
void workerData;
