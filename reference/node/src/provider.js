import { createServer } from 'node:http';
import { createServer as createTlsServer } from 'node:https';
import { Store } from './store.js';
import { handleMcp } from './mcp.js';
import { loadConfig } from './config.js';
import { hash, Problem, requireThat, maxBody, eventMedia, receiptMedia,
  understoodExtensions } from './protocol.js';
import { isAddress, RecordRejection, typs, statusFor, skew, verifyRecord } from './records.js';

// Read at most limit+1 request bytes without destroying the socket before the problem response.
function readRequest(stream) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    function cleanup() { stream.off('readable', readable); stream.off('end', end); stream.off('error', fail); }
    function fail(error) { cleanup(); reject(error); }
    function end() { cleanup(); resolve(Buffer.concat(chunks).toString('utf8')); }
    function readable() {
      while (stream.readableLength) {
        const chunk = stream.read(Math.min(stream.readableLength, maxBody + 1 - size));
        if (!chunk) break;
        size += chunk.length;
        if (size > maxBody) { fail(new RecordRejection('too-large')); return; }
        chunks.push(chunk);
      }
      stream.read(0);
    }
    stream.on('readable', readable); stream.on('end', end); stream.on('error', fail);
    readable();
  });
}
async function readBody(stream, headers) {
  if (!stream) return Buffer.alloc(0);
  // Fetch byte streams support BYOB: each read consumes only the remaining budget,
  // even when the peer supplies one chunk larger than that budget.
  const reader = stream.getReader({ mode: 'byob' });
  const chunks = [];
  let size = 0;
  try {
    while (size < maxBody) {
      const { value, done } = await reader.read(new Uint8Array(maxBody - size));
      if (value?.length) { chunks.push(Buffer.from(value)); size += value.length; }
      if (done) return Buffer.concat(chunks);
    }
    // Do not read another octet just to test EOF. HTTP framing can establish an
    // exact-size body; absent that evidence, a full budget is an incomplete answer.
    if (headers['content-length'] === String(size) &&
        (!headers['content-encoding'] || headers['content-encoding'] === 'identity')) return Buffer.concat(chunks);
    throw new RecordRejection('receipt-mismatch', 'Response exceeds the read budget');
  } catch (error) {
    error.evidence = Buffer.concat(chunks);
    throw error;
  } finally {
    try { await reader.cancel(); } catch { /* Preserve the read failure and its raw evidence. */ }
    finally { reader.releaseLock(); }
  }
}
function parseJson(body) {
  try { return JSON.parse(body); } catch { throw new Problem(400, 'Invalid JSON'); }
}
function reply(res, status, value, media = 'application/json') {
  res.writeHead(status, { 'content-type': media, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
  res.end(typeof value === 'string' ? value : JSON.stringify(value));
}
// C1 is shared by the HTTP adapter and vector runner; single-tenant hosting is checked at R12.
export function checkCarrier(method, headers) {
  if (method !== 'POST') throw new RecordRejection('method-not-allowed');
  if (headers['content-type']?.split(';')[0].trim().toLowerCase() !== 'application/jose' ||
      (headers['content-encoding'] && headers['content-encoding'].trim().toLowerCase() !== 'identity')) {
    throw new RecordRejection('unsupported-media-type');
  }
  if (!isAddress(headers['darep-recipient'])) throw new RecordRejection('wrong-recipient');
}
export function receive(token, recipient, runtime) {
  if (Buffer.byteLength(token) > maxBody) throw new RecordRejection('too-large');
  const { config, store } = runtime ?? {};
  const verified = verifyRecord(token, {
    typ: [eventMedia, typs.rejection], mode: 'admission', now: store?.now() ?? Date.now(), receiver: recipient,
    hosted: recipient === config?.card.id, understood: runtime?.extensions ?? understoodExtensions,
    dedupe: (record, payload) => store.prior(record, hash(payload)),
  }, id => store?.document(id) ?? null);
  if (verified.duplicate) return verified.duplicate.receipt;
  try { return store.receive(verified.record, verified.body, token, verified.header.typ).receipt; }
  catch (error) {
    if (error instanceof RecordRejection) throw error;
    throw new RecordRejection('unavailable');
  }
}
export function problemResponse(code) {
  const status = statusFor[code];
  return { status, headers: { 'content-type': 'application/problem+json', 'cache-control': 'no-store',
    ...(code === 'method-not-allowed' ? { allow: 'POST' } : {}),
    ...(['rate-limited', 'unavailable'].includes(code) ? { 'retry-after': '5' } : {}) },
  body: { type: 'https://darep.org/problems/' + code, title: code.replaceAll('-', ' '), status, code } };
}
export function classify(status, headers, body) {
  let code;
  if (headers['content-type']?.split(';')[0].trim().toLowerCase() === 'application/problem+json') {
    try {
      const candidate = JSON.parse(body).code;
      if (Object.hasOwn(statusFor, candidate) && candidate !== 'receipt-mismatch') code = candidate;
    } catch { /* A non-problem answer falls back to the HTTP status. */ }
  }
  const transient = code ? ['not-yet-valid', 'rate-limited', 'unavailable'].includes(code) :
    [408, 425, 429].includes(status) || (status >= 300 && status < 400) || status >= 500;
  return { result: transient ? 'transient' : 'permanent', code: code ?? 'Peer returned HTTP ' + status };
}
export async function send(selected, config, store, transport = fetch) {
  const row = store.claim(selected);
  if (!row) return;
  try { await sendClaimed(row, config, store, transport); }
  finally { store.release(row); }
}
async function sendClaimed(row, config, store, transport) {
  if (store.now() >= Date.parse(JSON.parse(row.body).expires) + skew) {
    store.transaction(() => store.fail(row, 'expired'));
    return;
  }
  let token;
  try { token = store.signed(row); }
  catch (error) {
    // PV-4 and other explicit permanent refusals close delivery. Local storage or
    // commit errors can recover, and must not cascade failure to dependent records.
    const result = error instanceof RecordRejection
      ? classify(error.status, { 'content-type': 'application/problem+json' }, JSON.stringify({ code: error.code })).result
      : error instanceof Problem ? classify(error.status, {}, '').result : 'transient';
    store.attempt(row, result, { code: error.message });
    return;
  }
  const evidence = {};
  let result = 'transient';
  try {
    const peer = store.contact(row.recipient);
    requireThat(peer, 404, 'Peer is not paired');
    const response = store.transmit(row, () => transport(peer.inbox ?? new URL('/darep/v2/inbox', peer.origin), {
      method: 'POST', headers: { 'content-type': 'application/jose', 'darep-recipient': row.recipient }, body: token,
      redirect: 'manual', signal: AbortSignal.timeout(10_000),
    }));
    if (!response) return;
    const res = await response;
    evidence.status = res.status;
    evidence.headers = Object.fromEntries(res.headers);
    result = res.status >= 200 && res.status < 300 ? 'receipt-mismatch' : classify(res.status, {}, '').result;
    const delay = evidence.headers['retry-after'];
    evidence.retryAfter = /^\d{1,10}$/.test(delay ?? '') ? Number(delay) : 0;
    evidence.bodyBytes = await readBody(res.body, evidence.headers);
    evidence.body = evidence.bodyBytes.toString('utf8');
    if (res.status >= 200 && res.status < 300) {
      result = 'receipt-mismatch';
      if (res.status !== 200 || evidence.headers['content-type']?.split(';')[0].trim().toLowerCase() !== 'application/jose') {
        throw new RecordRejection('receipt-mismatch');
      }
      const receipt = verifyRecord(evidence.body, { typ: receiptMedia, mode: 'admission', now: store.now(),
        receiver: config.card.id, understood: understoodExtensions, answered: token }, id => store.document(id)).record;
      if (receipt.source !== row.recipient) throw new RecordRejection('receipt-mismatch');
      result = 'delivered';
    } else {
      const classification = classify(res.status, evidence.headers, evidence.body);
      result = classification.result;
      evidence.code = classification.code;
    }
  } catch (error) {
    if (error.evidence !== undefined) {
      evidence.bodyBytes = error.evidence;
      evidence.body = error.evidence.toString('utf8');
    }
    evidence.code = error instanceof RecordRejection ? error.code : error instanceof Problem ? error.message :
      'Peer unreachable or connection interrupted before a verified receipt';
  }
  store.attempt(row, result, evidence);
}
// Every provider runtime shares storage, transport and signature checks.
export function openProviderRuntime(dir, config = loadConfig(dir)) {
  const store = new Store(dir, config.card.id, { config });
  let running;
  function tick() {
    if (running) return running;
    running = Promise.resolve().then(() => { store.applyReady(); return Promise.all(store.due().map(row => send(row, config, store))); })
      .catch(error => console.error('Delivery worker failed:', error.name))
      .finally(() => { running = null; });
    return running;
  }
  async function observeDelivery() {
    // A nearby peer can usually sign before we answer. A slow peer stays in the durable outbox.
    let timer;
    try {
      await Promise.race([tick(), new Promise(resolve => { timer = setTimeout(resolve, 500); })]);
    } finally {
      clearTimeout(timer);
    }
  }
  const timer = setInterval(tick, 200);
  tick();
  return { config, store, observeDelivery, async close() {
    clearInterval(timer);
    await running;
    store.close();
  } };
}

function replyFailure(req, res, error) {
  if (res.headersSent || res.destroyed) return;
  if (!(error instanceof Problem) && !(error instanceof RecordRejection)) console.error('Provider request failed:', error.name);
  if (error.status === 401 && req.url === '/mcp') res.setHeader('www-authenticate', 'Bearer realm="darep"');
  if (req.url === '/darep/v2/inbox') {
    const code = error instanceof RecordRejection ? error.code : error.status === 413 ? 'too-large' : 'unavailable';
    const problem = problemResponse(code);
    if (code === 'too-large') {
      res.setHeader('connection', 'close');
      res.once('finish', () => req.destroy());
    }
    res.writeHead(problem.status, problem.headers);
    res.end(JSON.stringify(problem.body));
    return;
  }
  const known = error instanceof Problem || error instanceof RecordRejection;
  reply(res, known ? error.status : 500, { error: known ? error.message : 'Internal error', ...(error.code && known ? { code: error.code } : {}) });
}

export async function handleProviderEndpoint(req, res, forAgent, forEvent) {
  if (req.url !== '/mcp' && req.url !== '/darep/v2/inbox') return false;
  let runtime;
  try {
    if (req.url === '/darep/v2/inbox') {
      const headers = { ...req.headers };
      for (const name of ['content-type', 'darep-recipient']) {
        if (req.rawHeaders.filter((v, i) => i % 2 === 0 && v.toLowerCase() === name).length > 1) delete headers[name];
      }
      checkCarrier(req.method, headers);
      // Multi-tenant routing may refuse an unhosted address at C1 before any pin lookup or signature check.
      runtime = forEvent(headers['darep-recipient']);
      if (!runtime) throw new RecordRejection('wrong-recipient');
    }
    else requireThat(req.method === 'POST', 405, 'POST required');
    const media = req.headers['content-type']?.split(';')[0]?.trim();
    // delivery.md §3.1: for a delivery, carrier check C1 (method, media type) comes before C2 (size).
    requireThat(Number(req.headers['content-length'] || 0) <= maxBody, 413, 'Body too large');
    if (req.url === '/mcp') {
      const { store, observeDelivery } = forAgent(req.headers.authorization);
      store.authorize(req.headers.authorization);
      requireThat(media === 'application/json', 415, 'application/json required');
      await handleMcp(req, res, parseJson(await readRequest(req)), store, observeDelivery);
    } else {
      // HTTPS binding §2.1: exactly one recipient address names this delivery (check C1).
      const recipient = req.headers['darep-recipient'];
      if (!isAddress(recipient)) throw new RecordRejection('wrong-recipient', 'Darep-Recipient must name one address');
      const token = await readRequest(req);
      const receipt = receive(token, recipient, runtime);
      reply(res, 200, receipt, 'application/jose');
      // The receipt is committed and handed to the response before any workflow check.
      try { runtime.store.applyReady(); } catch { /* The durable worker resumes after failure. */ }
    }
  } catch (error) { replyFailure(req, res, error); }
  return true;
}

export async function startProvider({ dir, port, host = '127.0.0.1', tls }) {
  const config = loadConfig(dir);
  const origin = new URL(config.card.origin);
  if (tls) requireThat(origin.protocol === 'https:' && tls.key && tls.cert, 400, 'HTTPS origin, key and certificate required');
  const runtime = openProviderRuntime(dir, config);
  const singleton = () => runtime;
  const listen = tls ? createTlsServer : createServer;
  const server = listen({ ...tls, requestTimeout: 15_000, headersTimeout: 10_000 }, async (req, res) => {
    try {
      requireThat(req.headers.host === origin.host, 400, 'Unknown host');
      requireThat(req.url === '/darep/v2/inbox' || !req.headers.origin || req.headers.origin === origin.origin, 403, 'Unknown origin');
      if (['GET', 'HEAD'].includes(req.method) && req.url === new URL(config.card.document.id).pathname) {
        res.setHeader('access-control-allow-origin', '*');
        res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'max-age=300' });
        res.end(req.method === 'HEAD' ? undefined : JSON.stringify(config.card.document));
        return;
      }
      if (req.url === '/health' && req.method === 'GET') return reply(res, 200, { status: 'ok' });
      if (!await handleProviderEndpoint(req, res, singleton, singleton)) {
        res.writeHead(404);
        res.end();
      }
    } catch (error) { replyFailure(req, res, error); }
  });
  try {
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, resolve); });
  } catch (error) { await runtime.close(); throw error; }
  return { port: server.address().port, async close() {
    const stopped = new Promise(resolve => server.close(resolve));
    server.closeIdleConnections();
    await stopped;
    await runtime.close();
  } };
}
