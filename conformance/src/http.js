// Raw HTTP helpers. The kit sends exact bytes and exact headers, so it does not use fetch().
import { request, createServer } from 'node:http';

// POST (or any method) with exact body bytes. headers may be an object or a flat raw-header array.
export function rawRequest(url, { method = 'POST', headers = {}, body = null, timeoutMs = 15_000 } = {}) {
  const target = new URL(url);
  const flat = Array.isArray(headers) ? [...headers] : Object.entries(headers).flat();
  if (!flat.some((v, i) => i % 2 === 0 && v.toLowerCase() === 'host')) flat.unshift('host', target.host);
  const bytes = body === null ? null : Buffer.isBuffer(body) ? body : Buffer.from(body, 'utf8');
  if (bytes && !flat.some((v, i) => i % 2 === 0 && v.toLowerCase() === 'content-length')) {
    flat.push('content-length', String(bytes.length));
  }
  return new Promise((resolve, reject) => {
    const req = request({ host: target.hostname, port: target.port, path: target.pathname + target.search, method,
      headers: flat, setHost: false }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, rawHeaders: res.rawHeaders,
        body: Buffer.concat(chunks) }));
      res.on('error', reject);
    });
    req.setTimeout(timeoutMs, () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    req.end(bytes ?? undefined);
  });
}

export function readAll(stream, limit = 1 << 20) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    stream.on('data', c => { size += c.length; if (size <= limit) chunks.push(c); });
    stream.on('end', () => resolve(Buffer.concat(chunks)));
    stream.on('error', reject);
  });
}

export const headerCount = (rawHeaders, name) =>
  rawHeaders.filter((v, i) => i % 2 === 0 && v.toLowerCase() === name).length;

// A loopback endpoint that answers each request from a script and records what it received.
export async function scriptedServer() {
  const received = [];
  let script = [];
  const server = createServer(async (req, res) => {
    const body = await readAll(req);
    received.push({ method: req.method, url: req.url, headers: req.headers, rawHeaders: req.rawHeaders, body });
    const answer = script.shift() ?? { status: 503, headers: { 'retry-after': '1' }, body: '' };
    if (answer.connection) { req.socket.destroy(); return; }
    res.writeHead(answer.status, answer.headers ?? {});
    res.end(answer.body ?? '');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  return {
    url: `http://127.0.0.1:${port}/darep/v2/inbox`, received,
    answer(...answers) { script = answers; received.length = 0; },
    close: () => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }),
  };
}
