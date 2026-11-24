// Runs every Wire v2 delivery vector against the Node reference provider. Receiver vectors go over real HTTP to the
// provider's own inbox handler on loopback, with the vector's request octets; sender vectors drive send() with a
// scripted transport, and responses given as raw octets (respond.raw) come from a loopback TCP responder through the
// real fetch(). Stored records are addressed by (source, id): ids are unique per source only (delivery.md §6).
import assert from 'node:assert/strict';
import test from 'node:test';
import { createPrivateKey } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { createServer, request } from 'node:http';
import { createServer as createTcpServer, connect } from 'node:net';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { Store } from '../src/store.js';
import { advance, parseAction, Problem } from '../src/protocol.js';
import { typs, verifyRecord } from '../src/records.js';
import { handleProviderEndpoint, send } from '../src/provider.js';

const root = new URL('../../../vectors/v2/delivery/', import.meta.url);
const load = path => JSON.parse(readFileSync(new URL(path, root), 'utf8'));
const { documents, inboxes } = load('identities.json');
const keys = load('test-keys.json').keys;
const resolve = id => documents.find(d => d.id === id);
const payload = token => JSON.parse(Buffer.from(token.split('.')[1], 'base64url'));

// (source, id) for a vector reference: { source, id }, or an id plus an optional source. A bare id must name exactly
// one source among the vector's records; a vector holding two records with one id must say which it means.
function recordKey(v, ref, source) {
  if (ref && typeof ref === 'object') return { source: ref.source, id: ref.id };
  if (source) return { source, id: ref };
  const sources = new Set(Object.values(v.records ?? {}).filter(r => r.envelope?.id === ref).map(r => r.envelope.source));
  assert.equal(sources.size, 1, `vector reference ${ref} matches ${sources.size} sources; name the source`);
  return { source: [...sources][0], id: ref };
}
const incoming = (store, key) => store.db.prepare("SELECT * FROM events WHERE direction='in' AND actor=? AND event_id=?").get(key.source, key.id);

// Strict base64 (RFC 4648 §4, padded): Buffer.from(…, 'base64') would silently drop invalid characters.
function base64(text) {
  assert.ok(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text), 'invalid base64 in vector');
  return Buffer.from(text, 'base64');
}

// The exact request octets: bodyFill, bodyBase64 (any octets) or body (text, sent as UTF-8).
function requestBody(req, v) {
  if (req.bodyFill) return Buffer.alloc(req.bodyFill.length, req.bodyFill.octet);
  if (req.bodyBase64 !== undefined) return base64(req.bodyBase64);
  if (req.body !== undefined && req.body !== null) return Buffer.from(req.body, 'utf8');
  if (req.bodyEqualsRecord) return Buffer.from(v.records[req.bodyEqualsRecord].recordBytes, 'utf8');
  return null;
}

// The exact response octets of a respond.raw script: text (UTF-8), base64 or fill segments, in order.
function rawOctets(raw) {
  assert.ok(['close', 'reset', undefined].includes(raw.end), 'raw.end must be close or reset');
  return Buffer.concat(raw.segments.map(s => {
    if (s.text !== undefined) return Buffer.from(s.text, 'utf8');
    if (s.base64 !== undefined) return base64(s.base64);
    assert.equal(Buffer.byteLength(s.fill.octet), 1, 'fill.octet must be one octet');
    return Buffer.alloc(s.fill.length, s.fill.octet);
  }));
}
// (status, lowercase headers) the sender should see; status null for a raw response with no complete head.
function respondHead(respond) {
  if (!respond.raw) return { status: respond.status, headers: respond.headers ?? {} };
  const octets = rawOctets(respond.raw);
  const end = octets.indexOf('\r\n\r\n');
  if (end < 0) return { status: null, headers: {} };
  const lines = octets.subarray(0, end).toString('latin1').split('\r\n');
  return { status: Number(lines[0].split(' ')[1]),
    headers: Object.fromEntries(lines.slice(1).map(l => [l.slice(0, l.indexOf(':')).trim().toLowerCase(), l.slice(l.indexOf(':') + 1).trim()])) };
}

// A loopback TCP endpoint that reads one HTTP request per connection and writes the scripted octets exactly, then
// closes ("close") or resets ("reset") the connection. The vector controls status line, headers, framing and size.
async function rawResponder() {
  const received = [];
  let script = null;
  const sockets = new Set();
  const server = createTcpServer(socket => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    let data = Buffer.alloc(0);
    socket.on('error', () => {});
    socket.on('data', chunk => {
      data = Buffer.concat([data, chunk]);
      const end = data.indexOf('\r\n\r\n');
      if (end < 0) return;
      const head = data.subarray(0, end).toString('latin1').split('\r\n');
      const length = Number(head.find(l => /^content-length:/i.test(l))?.split(':')[1] ?? 0);
      if (data.length < end + 4 + length) return;
      socket.removeAllListeners('data');
      received.push({ requestLine: head[0], headers: head.slice(1), body: data.subarray(end + 4, end + 4 + length) });
      socket.write(rawOctets(script), () => {
        if (!socket.destroyed) (script.end === 'reset' ? socket.resetAndDestroy() : socket.end());
      });
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { url: `http://127.0.0.1:${server.address().port}/darep/v2/inbox`, received,
    answer(raw) { script = raw; received.length = 0; },
    close: () => new Promise(resolve => { for (const s of sockets) s.destroy(); server.close(resolve); }) };
}

// One HTTP request with exact octets; resolves to { status, headers, body: Buffer }.
function exchange(url, method, headers, body) {
  const target = new URL(url);
  const flat = ['host', target.host, ...Object.entries(headers ?? {}).flat()];
  if (body) flat.push('content-length', String(body.length));
  return new Promise((resolve, reject) => {
    const req = request({ host: target.hostname, port: target.port, path: target.pathname, method, headers: flat }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.end(body ?? undefined);
  });
}

// The provider's own inbox handler on loopback. front(req) may stand in for the request (self-test mutants only).
async function inboxServer(f, front = req => req) {
  const server = createServer(async (req, res) => {
    f.inFlight = res; // lets the runner see whether an outcome is set before the response is handed over
    const handled = await handleProviderEndpoint(await front(req), res,
      () => { throw new Problem(404, 'Not found'); }, () => ({ config: f.config, store: f.store, extensions: f.extensions }));
    if (!handled) { res.writeHead(404); res.end(); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { url: `http://127.0.0.1:${server.address().port}/darep/v2/inbox`,
    close: () => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }) };
}
function fixture(v, t) {
  const party = v.receiver ?? v.sender;
  const document = documents.find(d => d.addresses.includes(party.address));
  const signer = purpose => {
    const kid = document.keys.find(k => k.purpose.includes(purpose)).id;
    return { kid, key: createPrivateKey({ key: keys[kid], format: 'jwk' }) };
  };
  const config = { card: { id: party.address, document }, signer: signer('record'), providerSigner: signer('provider') };
  const dir = mkdtempSync(join(import.meta.dirname, '.delivery-'));
  let now = Date.parse(v.steps?.[0]?.at ?? '2026-11-20T10:00:30Z');
  const store = new Store(dir, party.address, { config, now: () => now });
  t.after(() => { store.close(); rmSync(dir, { recursive: true }); });
  for (const address of party.pinned) store.trust({ identity: documents.find(d => d.addresses.includes(address)), inbox: inboxes[address] });
  return { store, config, extensions: party.extensions, clock: at => { now = Date.parse(at); } };
}
function fields(actual, expected) {
  for (const [key, value] of Object.entries(expected)) {
    const got = key.split('.').reduce((o, k) => o?.[k], actual);
    if (key === 'data' && value.storedAt) {
      assert.equal(got.sha256, value.sha256);
      assert.equal(Date.parse(got.storedAt), Date.parse(value.storedAt));
    } else assert.deepEqual(got, value, key);
  }
}
function seed(f, record) {
  f.store.transaction(() => {
    const row = f.store.queueSigned(record.recordBytes);
    const state = advance(f.store.state(record.envelope.thread), record.envelope, parseAction(record.envelope));
    f.store.db.prepare('INSERT OR REPLACE INTO threads VALUES (?,?,?)').run(state.threadId, JSON.stringify(state), row.row_id);
  });
}
// Sender vector. transport stands in for fetch() on raw responses (self-test mutants only).
async function runSender(v, t, { transport = fetch } = {}) {
  if (v.retryProfile?.jitterPercent === 0) t.mock.method(Math, 'random', () => 0);
  const raw = [...(v.steps ?? []), ...(v.cases ?? [])].some(s => s.respond?.raw) ? await rawResponder() : null;
  if (raw) t.after(() => raw.close());
  const respondBody = respond => {
    if (!respond.raw) return respond.body ?? '';
    assert.ok(respond.raw.decodedBody !== undefined, 'vector compares a raw response body but declares no decodedBody');
    return respond.raw.decodedBody;
  };
  // Cases are independent attempts; steps share durable state and exponential backoff.
  const scenarios = v.cases ? v.cases.map(c => [c]) : [v.steps];
  for (const steps of scenarios) {
    const f = fixture(v, t), { store, config } = f;
    for (const r of Object.values(v.records)) store.transaction(() => store.queueSigned(r.recordBytes));
    const recipient = steps[0].request?.headers['darep-recipient'] ?? v.records.out.envelope.to[0];
    const out = store.db.prepare("SELECT * FROM events WHERE direction='out' AND actor=? AND event_id=? AND recipient=?")
      .get(v.sender.address, v.records.out.envelope.id, recipient);
    if (!v.steps) f.clock(new Date(Date.parse(v.records.out.envelope.time) + 30_000).toISOString());
    let previousBackoff = 0;
    for (const step of steps) {
      if (step.at) f.clock(step.at);
      if (step.expect.recordsVerdict === 'accept') {
        const pins = id => documents.find(d => d.id === id && d.addresses.some(a => v.sender.pinned.includes(a)));
        assert.doesNotThrow(() => verifyRecord(respondBody(step.respond), { typ: typs.receipt, mode: 'admission',
          now: Date.parse(step.at), receiver: v.sender.address, answered: v.records.out.recordBytes }, pins));
      }
      let calls = 0;
      if (step.respond) await send(out, config, store, async (url, options) => {
        calls++;
        assert.equal(options.body, v.records.out.recordBytes);
        assert.equal(options.redirect, 'manual');
        assert.equal(String(url), inboxes[out.recipient]);
        assert.equal(options.method, 'POST');
        assert.equal(options.headers['darep-recipient'], out.recipient);
        assert.equal(options.headers['content-type'], 'application/jose');
        if (step.respond.raw) { raw.answer(step.respond.raw); return transport(raw.url, options); }
        if (step.respond.connection) throw new Error('Injected connection reset');
        return new Response(step.respond.body ?? '', { status: step.respond.status, headers: step.respond.headers });
      });
      else store.applyReady();
      const delivery = store.db.prepare('SELECT * FROM outbox WHERE event_row=?').get(out.row_id);
      const attempt = store.db.prepare('SELECT * FROM attempts WHERE event_row=? ORDER BY id DESC LIMIT 1').get(out.row_id);
      const expected = step.expect;
      const at = `step ${steps.indexOf(step)}`;
      if (expected.delivery) assert.equal(delivery.status, expected.delivery, `${at}: delivery`);
      if (expected.attemptResult) assert.equal(attempt.result, expected.attemptResult, `${at}: attempt result`);
      if (expected.verifyCode) assert.equal(attempt.code, expected.verifyCode);
      if (expected.nextAttemptNotBefore) assert.ok(delivery.next_at >= Date.parse(expected.nextAttemptNotBefore));
      if (expected.backoff) {
        assert.ok(delivery.backoff_ms >= expected.backoff.minimumSeconds * 1000, 'initial minimum backoff');
        if (expected.backoff.nonDecreasing) assert.ok(delivery.backoff_ms >= previousBackoff, 'backoff must not decrease');
        assert.ok(delivery.next_at >= Date.parse(step.at) + delivery.backoff_ms, 'schedule honors backoff');
        previousBackoff = delivery.backoff_ms;
      }
      if (expected.should?.backoffSeconds !== undefined) {
        const met = delivery.backoff_ms === expected.should.backoffSeconds * 1000 && delivery.next_at === Date.parse(expected.should.nextAttemptAt);
        t.diagnostic(`SHOULD ${met ? 'met' : 'not met'}: zero-jitter profile backoff ${expected.should.backoffSeconds}s`);
      }
      if (step.respond) {
        assert.equal(calls, 1);
        if (step.respond.raw) {
          assert.equal(raw.received.length, 1, `${at}: the sender made ${raw.received.length} requests to the raw responder`);
          assert.equal(raw.received[0].body.toString('latin1'), v.records.out.recordBytes);
          const head = respondHead(step.respond);
          if (head.status !== null) assert.equal(attempt.status, head.status, `${at}: evidence status`);
          if (step.respond.raw.decodedBody !== undefined) assert.equal(attempt.body, step.respond.raw.decodedBody, `${at}: evidence body`);
        } else if (!step.respond.connection) {
          assert.equal(attempt.status, step.respond.status);
          assert.equal(attempt.body, step.respond.body ?? '');
          fields(JSON.parse(attempt.headers), step.respond.headers ?? {});
        }
      }
      if (expected.delivery === 'delivered') assert.equal(delivery.receipt, respondBody(step.respond), `${at}: stored receipt`);
      if (expected.furtherAttempts === 0) assert.equal(store.due().length, 0);
      for (const id of Object.keys(expected.dependentRecords ?? {})) {
        const dep = store.db.prepare("SELECT o.* FROM outbox o JOIN events e ON e.row_id=o.event_row WHERE e.direction='out' AND e.actor=? AND e.event_id=?")
          .get(v.sender.address, id);
        assert.equal(dep.status, 'failed'); assert.equal(dep.attempts, 0);
      }
    }
  }
}

// Receiver vector, over real HTTP to the provider's inbox handler. front and mutate are for self-test mutants only.
async function runReceiver(v, file, t, { front, mutate } = {}) {
  const f = fixture(v, t), { store } = f;
  for (const prior of v.priorState ?? []) seed(f, v.records[prior.record]);
  if (file === 'reject-rate-limited.json') store.capacity = () => 'rate-limited';
  if (file === 'reject-unavailable.json') {
    store.db.exec("CREATE TRIGGER fail_store BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT, 'Injected storage failure'); END");
  }
  const applied = (v.priorState ?? []).map(prior => ({ source: v.records[prior.record].envelope.source, id: v.records[prior.record].envelope.id }));
  const setOutcome = store.outcome.bind(store);
  const early = []; // records given an outcome before their receipt was handed to the response (delivery.md §3)
  store.outcome = (row, outcome, code) => {
    if (row.direction === 'in' && f.inFlight && !f.inFlight.writableEnded) early.push(row.event_id);
    const result = setOutcome(row, outcome, code);
    if (outcome === 'applied' && row.typ === typs.event) applied.push({ source: row.actor, id: row.event_id });
    return result;
  };
  mutate?.(store);
  const inbox = await inboxServer(f, front);
  t.after(() => inbox.close());
  const answers = [];
  let key = null; // (source, id) of the record the current step is about
  let row;
  for (const [i, step] of v.steps.entries()) {
    const at = `step ${i}`;
    f.clock(step.at);
    const expected = step.expect;
    const countBefore = store.db.prepare('SELECT count(*) AS n FROM events').get().n;
    if (step.request) {
      const req = step.request;
      const body = requestBody(req, v);
      const response = await exchange(inbox.url, req.method, req.headers, body);
      const text = response.body.toString('utf8');
      answers.push(response.status === 200 ? text : null);
      assert.equal(response.status, expected.status, `${at}: status ${response.status} ${text.slice(0, 160)}`);
      assert.equal(response.headers['content-type'], expected.contentType, `${at}: content-type`);
      if (expected.problem) fields(JSON.parse(text), expected.problem);
      for (const [name, value] of Object.entries(expected.headers ?? {})) {
        if (!value.startsWith('<')) assert.equal(response.headers[name], value);
      }
      if (expected.stored === false || expected.stored === 'unchanged') {
        assert.equal(store.db.prepare('SELECT count(*) AS n FROM events').get().n, countBefore, `${at}: something was stored`);
      }
      if (response.status === 200) {
        const receipt = verifyRecord(text, { typ: typs.receipt, mode: 'evidence' }, resolve).record;
        const sent = payload(body.toString('utf8'));
        key = { source: sent.source, id: sent.id };
        assert.equal(receipt.inReplyTo, key.id);
        assert.deepEqual(receipt.to, [key.source]);
        row = incoming(store, key);
        assert.ok(row, `${at}: the record is not stored`);
        assert.equal(row.digest, receipt.data.sha256);
        assert.equal(row.receipt, text);
        if (expected.stored === true) assert.equal(row.jws, body.toString('utf8'));
        assert.deepEqual(early, [], 'Application must not precede acknowledgement');
        if (expected.receipt?.equals) fields(receipt, expected.receipt.equals);
        if (expected.receipt?.members) assert.deepEqual(Object.keys(receipt).sort(), expected.receipt.members.toSorted());
        if (expected.receipt?.timeAtOrAfter) assert.ok(Date.parse(receipt.time) >= Date.parse(expected.receipt.timeAtOrAfter));
        if (expected.receipt?.retainedAtLeastUntil) assert.ok(Date.parse(row.retain_until) >= Date.parse(expected.receipt.retainedAtLeastUntil));
        if (expected.receiptBytesEqualStep !== undefined) assert.equal(text, answers[expected.receiptBytesEqualStep]);
      }
    }
    store.applyReady();
    if (key) row = incoming(store, key);
    if (expected.applyOutcome) assert.equal(row.outcome, expected.applyOutcome, `${at}: apply outcome`);
    if (expected.applyCount !== undefined) assert.equal(row.apply_count, expected.applyCount);
    for (const after of expected.afterApply ?? []) {
      const dependent = incoming(store, recordKey(v, after.record, after.source));
      assert.ok(dependent, `${at}: afterApply record ${after.record} is not stored`);
      assert.equal(dependent.outcome, after.applyOutcome, `${at}: afterApply ${after.source ?? ''} ${after.record}`);
      if (after.rejectionRecord) {
        const rejection = store.db.prepare('SELECT * FROM events WHERE row_id=?').get(dependent.rejection_row);
        const verified = verifyRecord(rejection.jws, { typ: typs.rejection, mode: 'evidence', answered: dependent.jws }, resolve);
        fields(verified.record, after.rejectionRecord.equals);
      }
    }
    if (expected.rejectionRecord && (!expected.rejectionRecord.optional || row.rejection_row)) {
      const rejectionRow = store.db.prepare('SELECT * FROM events WHERE row_id=?').get(row.rejection_row);
      const rejection = verifyRecord(rejectionRow.jws, { typ: typs.rejection, mode: 'evidence', answered: row.jws }, resolve).record;
      fields(rejection, expected.rejectionRecord.equals);
      for (const k of expected.rejectionRecord.absent ?? []) assert.ok(!(k in rejection));
      for (const k of expected.rejectionRecord.present ?? []) assert.ok(k in rejection);
      assert.equal(store.db.prepare('SELECT status FROM outbox WHERE event_row=?').get(rejectionRow.row_id).status, 'queued');
    }
  }
  if (v.finalState?.applyOrder) assert.deepEqual(applied, v.finalState.applyOrder.map(e => recordKey(v, e)), 'apply order');
  for (const e of v.finalState?.stored ?? []) {
    const k = recordKey(v, e);
    assert.ok(store.db.prepare('SELECT 1 FROM events WHERE actor=? AND event_id=?').get(k.source, k.id), `final: ${k.source} ${k.id} not stored`);
  }
  if (v.finalState?.rejectionRecords !== undefined) {
    assert.equal(store.db.prepare("SELECT count(*) AS n FROM events WHERE direction='out' AND typ=?").get(typs.rejection).n,
      v.finalState.rejectionRecords);
  }
  if (v.finalState?.threadHead) assert.equal(store.state(row.topic).head, v.finalState.threadHead);
}

for (const role of ['receiver', 'sender']) {
  for (const file of readdirSync(new URL(role + '/', root)).filter(f => f.endsWith('.json')).sort()) {
    test(`delivery vector ${role}/${file}`, async t => {
      const v = load(role + '/' + file);
      if (role === 'sender') await runSender(v, t);
      else await runReceiver(v, file, t);
    });
  }
}

test('Retry-After delays one attempt without advancing the backoff sequence', t => {
  const v = load('sender/retry-same-bytes.json');
  const f = fixture(v, t), { store } = f;
  const out = store.transaction(() => store.queueSigned(v.records.out.recordBytes));
  t.mock.method(Math, 'random', () => 0);
  store.attempt(out, 'transient', { retryAfter: 600 });
  const first = store.db.prepare('SELECT * FROM outbox WHERE event_row=?').get(out.row_id);
  assert.equal(first.backoff_ms, 1000);
  assert.equal(first.next_at, store.now() + 600_000);
  f.clock(new Date(first.next_at).toISOString());
  store.attempt(out, 'transient');
  const second = store.db.prepare('SELECT * FROM outbox WHERE event_row=?').get(out.row_id);
  assert.equal(second.backoff_ms, 2000);
  assert.equal(second.next_at, store.now() + 2000);
});

// ---------- harness self-tests: each runner capability catches a deliberately wrong implementation ----------

const selftest = (role, name) => load(`selftest/${role}/${name}.json`);
for (const role of ['receiver', 'sender']) {
  for (const file of readdirSync(new URL(`selftest/${role}/`, root)).filter(f => f.endsWith('.json')).sort()) {
    test(`harness: self-test fixture ${role}/${file} passes on the provider`, async t => {
      const v = load(`selftest/${role}/${file}`);
      if (role === 'sender') await runSender(v, t);
      else await runReceiver(v, file, t);
    });
  }
}

test('harness: records are keyed by (source, id), so an outcome written by id alone is caught', async t => {
  const v = selftest('receiver', 'same-id-two-sources');
  const shared = v.records.fromBob.envelope.id;
  assert.throws(() => recordKey(v, shared), /name the source/);
  assert.deepEqual(recordKey(v, shared, 'acct:dave@vectors.test'), { source: 'acct:dave@vectors.test', id: shared });
  await assert.rejects(runReceiver(v, 'same-id-two-sources.json', t, { mutate: store => {
    const real = store.outcome;
    // Wrong: writes the outcome to every stored record with this id, whatever its source.
    store.outcome = (row, outcome, code) => {
      const result = real(row, outcome, code);
      store.db.prepare('UPDATE events SET outcome=? WHERE event_id=? AND direction=?').run(outcome, row.event_id, row.direction);
      return result;
    };
  } }), /afterApply acct:bob@vectors.test/);
});

test('harness: bodyBase64 is sent octet for octet, so a receiver that drops undecodable octets is caught', async t => {
  const v = selftest('receiver', 'binary-body');
  assert.deepEqual([...requestBody(v.steps[1].request, v).subarray(0, 2)], [0xff, 0xfe]);
  // Wrong: drops octets it cannot decode instead of refusing the body.
  const lenient = async req => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const kept = Buffer.from([...Buffer.concat(chunks)].filter(b => b < 0x80));
    return Object.assign(Readable.from([kept]), { method: req.method, url: req.url, rawHeaders: req.rawHeaders,
      headers: { ...req.headers, 'content-length': String(kept.length) } });
  };
  await assert.rejects(runReceiver(v, 'binary-body.json', t, { front: lenient }), /step 1: status 200/);
});

test('harness: the raw responder writes exact octets and resets on request', async () => {
  const raw = await rawResponder();
  try {
    const read = script => new Promise((resolve, reject) => {
      raw.answer(script);
      const chunks = [];
      const socket = connect(new URL(raw.url).port, '127.0.0.1', () => socket.write('POST /darep/v2/inbox HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi'));
      socket.on('data', c => chunks.push(c));
      socket.on('end', () => resolve({ data: Buffer.concat(chunks) }));
      socket.on('error', error => resolve({ data: Buffer.concat(chunks), error: error.code }));
      socket.setTimeout(5000, () => reject(new Error('timeout')));
    });
    const closed = await read({ segments: [{ text: 'HTTP/1.1 204 No Content\r\n' }, { base64: 'WC1CaW46IP8NCg==' }, { fill: { octet: 'a', length: 3 } }, { text: '\r\n\r\n' }], end: 'close' });
    assert.deepEqual(closed.data, Buffer.concat([Buffer.from('HTTP/1.1 204 No Content\r\nX-Bin: '), Buffer.from([0xff]), Buffer.from('\r\naaa\r\n\r\n')]));
    assert.equal(raw.received[0].body.toString(), 'hi');
    const reset = await read({ segments: [{ text: 'HTTP/1.1 200 OK\r\n' }], end: 'reset' });
    assert.equal(reset.error, 'ECONNRESET');
  } finally { await raw.close(); }
});

test('harness: raw response framing catches a sender HTTP client that keeps the chunk framing', async t => {
  // Wrong: reads the response to EOF and takes everything after the head as the body, without decoding chunks.
  const naive = (url, options) => new Promise((resolve, reject) => {
    const target = new URL(url);
    const chunks = [];
    const socket = connect(target.port, target.hostname, () => {
      const head = [`POST ${target.pathname} HTTP/1.1`, `host: ${target.host}`, `content-length: ${Buffer.byteLength(options.body)}`, 'connection: close',
        ...Object.entries(options.headers).map(([k, value]) => `${k}: ${value}`)].join('\r\n');
      socket.write(head + '\r\n\r\n' + options.body);
    });
    socket.on('data', c => chunks.push(c));
    socket.on('error', reject);
    socket.on('end', () => {
      const data = Buffer.concat(chunks);
      const split = data.indexOf('\r\n\r\n');
      const lines = data.subarray(0, split).toString('latin1').split('\r\n');
      const headers = new Headers(lines.slice(1).map(l => [l.slice(0, l.indexOf(':')), l.slice(l.indexOf(':') + 1).trim()])
        .filter(([k]) => k.toLowerCase() !== 'transfer-encoding'));
      resolve(new Response(data.subarray(split + 4), { status: Number(lines[0].split(' ')[1]), headers }));
    });
  });
  await assert.rejects(runSender(selftest('sender', 'raw-framing'), t, { transport: naive }), /step 1: delivery/);
});
