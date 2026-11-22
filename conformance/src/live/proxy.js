// A loopback forwarding proxy that records every exchange and can inject faults into the next request(s).
// Faults: { kind: 'pass' } | { kind: 'drop-response' } (forward, then cut the connection before answering)
//       | { kind: 'respond', status, headers, body } (answer without forwarding)
//       | { kind: 'replace-response', status, headers, body } (forward, then answer with this instead)
import { createServer } from 'node:http';
import { rawRequest, readAll } from '../http.js';

const HOP = new Set(['host', 'connection', 'keep-alive', 'transfer-encoding', 'proxy-connection', 'upgrade']);

export async function faultProxy(target) {
  const log = [];
  const faults = [];
  const waiters = new Set();
  const settle = () => { for (const w of [...waiters]) { const hit = log.find(w.match); if (hit) { waiters.delete(w); w.resolve(hit); } } };
  const server = createServer(async (req, res) => {
    const body = await readAll(req, 1 << 20);
    const entry = { at: Date.now(), method: req.method, url: req.url, headers: req.headers, rawHeaders: req.rawHeaders,
      body, response: null, fault: null, done: false };
    const fault = faults.shift() ?? { kind: 'pass' };
    entry.fault = fault.kind;
    log.push(entry);
    try {
      if (fault.kind === 'respond') {
        res.writeHead(fault.status, fault.headers ?? {});
        res.end(fault.body ?? '');
        entry.response = { status: fault.status, headers: fault.headers ?? {}, body: Buffer.from(fault.body ?? '') };
        return;
      }
      const headers = req.rawHeaders.filter((_, i) => i % 2 === 0 ? !HOP.has(req.rawHeaders[i].toLowerCase()) : !HOP.has(req.rawHeaders[i - 1].toLowerCase()));
      let upstream;
      try {
        upstream = await rawRequest(proxy.target, { method: req.method, headers, body: body.length || req.method === 'POST' ? body : null });
      } catch (error) {
        entry.response = { error: error.message };
        req.socket.destroy();
        return;
      }
      entry.response = { status: upstream.status, headers: upstream.headers, body: upstream.body };
      if (fault.kind === 'drop-response') { req.socket.destroy(); return; }
      if (fault.kind === 'replace-response') {
        res.writeHead(fault.status, fault.headers ?? {});
        res.end(fault.body ?? '');
        return;
      }
      const out = Object.fromEntries(Object.entries(upstream.headers).filter(([k]) => !HOP.has(k)));
      res.writeHead(upstream.status, out);
      res.end(upstream.body);
    } finally {
      entry.done = true;
      settle();
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const proxy = {
    target,
    log,
    url: `http://127.0.0.1:${server.address().port}${new URL(target).pathname}`,
    inject(...list) { faults.push(...list); },
    clearFaults() { faults.length = 0; },
    // Resolves with the first completed exchange that matches, or null after timeoutMs.
    waitFor(match, timeoutMs) {
      const m = e => e.done && match(e);
      const hit = log.find(m);
      if (hit) return Promise.resolve(hit);
      return new Promise(resolve => {
        const w = { match: m, resolve };
        waiters.add(w);
        setTimeout(() => { if (waiters.delete(w)) resolve(null); }, timeoutMs);
      });
    },
    close: () => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }),
  };
  return proxy;
}
