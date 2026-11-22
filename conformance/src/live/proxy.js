// A loopback forwarding proxy that records every exchange and can inject faults.
// A fault applies to the first later request it matches (match(entry) on the parsed request), so background
// traffic such as a late rejection record cannot consume a fault meant for another case.
//   { kind: 'drop-response' }        forward, then cut the connection before answering
//   { kind: 'respond', status, headers, body }           answer without forwarding
//   { kind: 'replace-response', status, headers, body }  forward, then answer with this instead
//   { kind: 'hold', until: Promise } wait for `until` before forwarding normally
import { createServer } from 'node:http';
import { rawRequest, readAll } from '../http.js';

const HOP = new Set(['host', 'connection', 'keep-alive', 'transfer-encoding', 'proxy-connection', 'upgrade']);

export async function faultProxy(target, { parse = () => null } = {}) {
  const log = [];
  const faults = [];
  const server = createServer(async (req, res) => {
    const body = await readAll(req, 1 << 20);
    const entry = { at: Date.now(), method: req.method, url: req.url, headers: req.headers, rawHeaders: req.rawHeaders,
      body, record: parse(body), response: null, respondedAt: null, fault: 'pass', done: false };
    const index = faults.findIndex(f => !f.match || f.match(entry));
    const fault = index >= 0 ? faults.splice(index, 1)[0] : { kind: 'pass' };
    entry.fault = fault.kind;
    log.push(entry);
    const answer = (status, headers, payload) => {
      res.writeHead(status, headers);
      res.end(payload);
      entry.respondedAt = Date.now();
    };
    try {
      if (fault.kind === 'respond') {
        entry.response = { status: fault.status, headers: fault.headers ?? {}, body: Buffer.from(fault.body ?? '') };
        answer(fault.status, fault.headers ?? {}, fault.body ?? '');
        return;
      }
      if (fault.kind === 'hold') await fault.until;
      const headers = req.rawHeaders.filter((_, i) => !HOP.has(req.rawHeaders[i - (i % 2)].toLowerCase()));
      let upstream;
      try {
        upstream = await rawRequest(proxy.target, { method: req.method, headers, body: body.length || req.method === 'POST' ? body : null });
      } catch (error) {
        entry.response = { error: error.message };
        req.socket.destroy();
        entry.respondedAt = Date.now();
        return;
      }
      entry.response = { status: upstream.status, headers: upstream.headers, body: upstream.body };
      if (fault.kind === 'drop-response') { req.socket.destroy(); entry.respondedAt = Date.now(); return; }
      if (fault.kind === 'replace-response') { answer(fault.status, fault.headers ?? {}, fault.body ?? ''); return; }
      answer(upstream.status, Object.fromEntries(Object.entries(upstream.headers).filter(([k]) => !HOP.has(k))), upstream.body);
    } finally {
      entry.done = true;
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const proxy = {
    target,
    log,
    url: `http://127.0.0.1:${server.address().port}${new URL(target).pathname}${new URL(target).search}`,
    inject(...list) { faults.push(...list); },
    close: () => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }),
  };
  return proxy;
}
