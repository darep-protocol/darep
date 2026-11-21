import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { request } from 'node:http';
import { initialize, loadConfig } from '../src/config.js';
import { Store } from '../src/store.js';
import { handoffType } from '../src/protocol.js';
import { makeEventRecord, signRecord, typs, rejectionType, verifyRecord } from '../src/records.js';
import { receive, send, problemResponse } from '../src/provider.js';
import { localPair } from '../examples/local-pair.js';

function setup(t) {
  const root = mkdtempSync(join(import.meta.dirname, '.evidence-'));
  const people = ['alice', 'bob'].map(name => {
    const dir = join(root, name), card = initialize(dir, `acct:${name}@evidence.test`, 'http://127.0.0.1:1');
    const config = loadConfig(dir), store = new Store(dir, card.id);
    return { dir, card, config, store };
  });
  const [alice, bob] = people;
  alice.store.trust(bob.card); bob.store.trust(alice.card);
  t.after(() => { people.forEach(p => p.store.close()); rmSync(root, { recursive: true }); });
  return { alice, bob };
}
const workData = { summary: 'A sample', nextStep: 'Review it', expectedResult: 'A result' };
function event(from, to, overrides = {}) {
  return makeEventRecord({ source: from.card.id, to: to.card.id, type: handoffType + '#handoff', data: workData,
    grant: { id: 'fixture-owner', actor: 'owner' }, ...overrides });
}
const sign = (person, value, typ = typs.event) => signRecord(JSON.stringify(value), person.config.signer, typ);
const byId = (store, id) => store.db.prepare('SELECT * FROM events WHERE event_id=?').get(id);
function queue(person, peer, grant) {
  person.store.allowHandoff({ peer: peer.card.id, action: { kind: 'handoff', ...workData } });
  const state = person.store.start({ requestKey: randomUUID(), peer: peer.card.id, ...workData }, handoffType, grant);
  return byId(person.store, state.head);
}

test('durable acknowledgement precedes application, survives restart, and retains exact evidence', t => {
  const { alice, bob } = setup(t);
  const r = event(alice, bob), token = sign(alice, r);
  const receipt = receive(token, bob.card.id, bob);
  assert.equal(byId(bob.store, r.id).outcome, null);
  assert.equal(bob.store.state(r.thread), null);
  bob.store.close(); bob.store = new Store(bob.dir, bob.card.id);
  assert.equal(receive(token, bob.card.id, bob), receipt);
  bob.store.applyReady(); bob.store.applyReady();
  const stored = byId(bob.store, r.id);
  assert.equal(stored.jws, token); assert.equal(stored.receipt, receipt);
  assert.equal(stored.outcome, 'applied'); assert.equal(stored.apply_count, 1);
  assert.equal(stored.grant_id, r.grant.id); assert.equal(stored.grant_actor, 'owner');
  assert.equal(stored.stored_at, JSON.parse(Buffer.from(receipt.split('.')[1], 'base64url')).data.storedAt);
  assert.equal(bob.store.db.prepare('PRAGMA user_version').get().user_version, 2);
  assert.equal(bob.store.db.prepare('PRAGMA synchronous').get().synchronous, 2);
});

test('unknown types and messages are stored, acknowledged and readable; invalid known data is refused afterward', t => {
  const { alice, bob } = setup(t);
  for (const type of ['https://else.test/ext/new/v1#unknown', 'https://darep.org/ext/core/v2#message']) {
    const r = event(alice, bob, { type, required: [], data: { text: 'Opaque content' } });
    const token = sign(alice, r);
    assert.ok(receive(token, bob.card.id, bob));
    bob.store.applyReady();
    assert.equal(byId(bob.store, r.id).outcome, type.endsWith('#message') ? 'applied' : 'unsupported');
    assert.ok(bob.store.records().records.some(x => x.signedBytes === token && x.grantClaimVerified === false));
  }
  const bad = event(alice, bob, { data: { unexpected: true } });
  const receipt = receive(sign(alice, bad), bob.card.id, bob);
  bob.store.applyReady();
  const row = byId(bob.store, bad.id);
  assert.equal(row.outcome_code, 'invalid-data'); assert.equal(row.receipt, receipt);
  const rejection = bob.store.db.prepare('SELECT * FROM events WHERE row_id=?').get(row.rejection_row);
  verifyRecord(rejection.jws, { typ: typs.rejection, mode: 'evidence', answered: row.jws }, id => id === bob.card.document.id ? bob.card.document : null);
  bob.store.applyReady();
  assert.equal(bob.store.db.prepare('SELECT count(*) AS n FROM events WHERE typ=?').get(typs.rejection).n, 1);
});

test('invalid message data is acknowledged before refusal and applied only once', t => {
  const { alice, bob } = setup(t);
  for (const data of [{}, { text: '' }, { text: 42 }, { text: 'hello', extra: true }]) {
    const r = event(alice, bob, { type: 'https://darep.org/ext/core/v2#message', required: [], data });
    const receipt = receive(sign(alice, r), bob.card.id, bob);
    assert.equal(byId(bob.store, r.id).outcome, null);
    bob.store.applyReady(); bob.store.applyReady();
    const row = byId(bob.store, r.id);
    assert.equal(row.outcome, 'refused');
    assert.equal(row.outcome_code, 'invalid-data');
    assert.equal(row.apply_count, 1);
    assert.equal(row.receipt, receipt);
  }
});

test('received rejections preserve delivery receipts, correlate before effects, and never generate rejection loops', t => {
  const { alice, bob } = setup(t);
  const original = event(alice, bob), token = sign(alice, original);
  let outgoing;
  alice.store.transaction(() => { outgoing = alice.store.queueSigned(token); });
  const receipt = receive(token, bob.card.id, bob);
  alice.store.delivered(outgoing, receipt);
  const reject = overrides => event(bob, alice, { type: rejectionType, grant: undefined, required: [],
    thread: original.thread, inReplyTo: original.id, data: { code: 'policy-denied' }, ...overrides });
  const unrelated = reject({ thread: randomUUID() });
  receive(sign(bob, unrelated, typs.rejection), alice.card.id, alice); alice.store.applyReady();
  assert.equal(alice.store.db.prepare('SELECT refused_code FROM outbox').get().refused_code, null);
  const refusal = reject();
  receive(sign(bob, refusal, typs.rejection), alice.card.id, alice); alice.store.applyReady();
  const delivery = alice.store.db.prepare('SELECT * FROM outbox').get();
  assert.equal(delivery.status, 'delivered'); assert.equal(delivery.receipt, receipt);
  assert.equal(delivery.refused_code, 'policy-denied');
  assert.equal(byId(alice.store, refusal.id).outcome, 'applied');
  assert.equal(alice.store.db.prepare("SELECT count(*) AS n FROM events WHERE direction='out'").get().n, 1);
});

test('PV-4 rechecks grant closure, expiry, verbs, types and peers before first signature', async t => {
  const { alice, bob } = setup(t);
  const grants = [
    { change: g => alice.store.revoke(g.id) },
    { change: g => alice.store.db.prepare('UPDATE grants SET expires=0 WHERE id=?').run(g.id) },
    { authority: { verbs: ['read'] } },
    { authority: { types: ['https://else.test/ext/other/v1'] } },
    { authority: { peers: ['acct:else@evidence.test'] } },
  ];
  for (const condition of grants) {
    const grant = alice.store.issue(['read', 'handoff'], 1, undefined, condition.authority);
    const row = queue(alice, bob, { id: grant.id, actor: 'agent' });
    condition.change?.(grant);
    let attempts = 0;
    await send(row, alice.config, alice.store, async () => { attempts++; throw new Error('Must not send'); });
    assert.equal(attempts, 0); assert.equal(byId(alice.store, row.event_id).jws, null);
    assert.equal(alice.store.db.prepare('SELECT status FROM outbox WHERE event_row=?').get(row.row_id).status, 'failed');
  }
  assert.equal(alice.store.db.prepare('SELECT count(*) AS n FROM grants').get().n, 5);
  assert.equal(alice.store.db.prepare("SELECT count(*) AS n FROM grants WHERE close_reason='revoked' AND closed_at IS NOT NULL").get().n, 1);
});

test('signed retries and operator redelivery keep identical bytes after grant closure and restart', async t => {
  const { alice, bob } = setup(t);
  const grant = alice.store.issue(['read','handoff'], 1);
  const row = queue(alice, bob, { id: grant.id, actor: 'agent' });
  const seen = [];
  const transport = async (_url, request) => { seen.push(request.body); return new Response('', { status: 404 }); };
  await send(row, alice.config, alice.store, transport);
  alice.store.revoke(grant.id);
  alice.store.close(); alice.store = new Store(alice.dir, alice.card.id);
  alice.store.retryDelivery(row.topic, row.event_id);
  await send(row, alice.config, alice.store, transport);
  assert.equal(seen.length, 2); assert.equal(seen[0], seen[1]);
  assert.equal(byId(alice.store, row.event_id).jws, seen[0]);
  assert.equal(alice.store.db.prepare('SELECT count(*) AS n FROM attempts').get().n, 2);
});

test('approvals and sharing rules close with evidence and can be reissued without overwriting history', t => {
  const { alice, bob } = setup(t);
  const approval = { peer: bob.card.id, action: { kind: 'handoff', ...workData } };
  alice.store.allowHandoff(approval); alice.store.allowHandoff(approval, { withdraw: true });
  const row = queue(alice, bob, { id: 'owner-fixture', actor: 'owner' });
  const approvals = alice.store.db.prepare('SELECT * FROM handoff_approvals ORDER BY rowid').all();
  assert.deepEqual(approvals.map(a => a.close_reason), ['withdrawn', 'used']);
  assert.ok(approvals.every(a => a.closed_at)); assert.equal(approvals[1].used_by, row.event_id);
  const rule = { peer: bob.card.id, activity: 'Review', originalStart: '2030-01-01T12:00:00Z', durationMinutes: 60, slots: ['2030-01-02T12:00:00Z'] };
  alice.store.allowTimes(rule); alice.store.allowTimes({ ...rule, slots: [] });
  assert.equal(alice.store.db.prepare('SELECT count(*) AS n FROM sharing_rules').get().n, 2);
  assert.equal(alice.store.db.prepare('SELECT close_reason FROM sharing_rules WHERE closed_at IS NOT NULL').get().close_reason, 'withdrawn');
});

test('HTTP binding returns problems, accepts signed rejections, and bounds chunked requests', async t => {
  const pair = await localPair();
  t.after(() => pair.close()); await pair.bob.start();
  const url = pair.bob.card.origin + '/darep/v2/inbox';
  for (const [options, status, code] of [
    [{ method: 'GET' }, 405, 'method-not-allowed'],
    [{ method: 'POST', headers: { 'content-type': 'text/plain' } }, 415, 'unsupported-media-type'],
    [{ method: 'POST', headers: { 'content-type': 'application/jose', 'content-encoding': 'gzip' } }, 415, 'unsupported-media-type'],
    [{ method: 'POST', headers: { 'content-type': 'application/jose' } }, 403, 'wrong-recipient'],
  ]) {
    const res = await fetch(url, options);
    assert.equal(res.status, status); assert.equal(res.headers.get('content-type'), 'application/problem+json');
    assert.equal((await res.json()).code, code);
    if (status === 405) assert.equal(res.headers.get('allow'), 'POST');
  }
  assert.equal((await fetch(pair.bob.card.origin + '/federation/events')).status, 404);
  const alice = { card: pair.alice.card, config: loadConfig(pair.alice.dir) };
  const r = event(alice, pair.bob, { type: rejectionType, grant: undefined, required: [], thread: randomUUID(), inReplyTo: randomUUID(), data: { code: 'invalid-data' } });
  const headers = { 'content-type': 'application/jose', 'darep-recipient': pair.bob.card.id };
  const token = sign(alice, r, typs.rejection);
  assert.equal((await fetch(url, { method: 'POST', headers, body: token })).status, 200);
  assert.equal((await fetch(url, { method: 'POST', headers, body: token + '\n' })).status, 400);
  const oversized = await new Promise((resolve, reject) => {
    const req = request(url, { method: 'POST', headers }, res => {
      let body = ''; res.on('data', c => { body += c; }); res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject); req.write('A'.repeat(32768)); req.end('A'.repeat(32769));
  });
  assert.equal(oversized.status, 413); assert.equal(JSON.parse(oversized.body).code, 'too-large');
});

test('restart backlog releases waiting siblings in storage order, and expiry wins over the hold window', t => {
  const { alice, bob } = setup(t);
  const opening = queue(alice, bob, { id: 'owner-fixture', actor: 'owner' });
  const accept = event(bob, alice, { type: handoffType + '#accept', thread: opening.topic, inReplyTo: opening.event_id, data: {} });
  const complete = event(bob, alice, { type: handoffType + '#complete', thread: opening.topic, inReplyTo: accept.id, data: { result: 'Done' } });
  const decline = event(bob, alice, { type: handoffType + '#decline', thread: opening.topic, inReplyTo: accept.id, data: {} });
  for (const r of [complete, accept, decline]) receive(sign(bob, r), alice.card.id, alice);
  alice.store.applyReady();
  assert.equal(byId(alice.store, complete.id).outcome, 'applied');
  assert.equal(byId(alice.store, decline.id).outcome_code, 'stale-head');
  assert.equal(alice.store.state(opening.topic).status, 'completed');
  const early = event(bob, alice, { type: handoffType + '#accept', thread: randomUUID(), inReplyTo: randomUUID(), data: {}, lifetime: 60_000 });
  receive(sign(bob, early), alice.card.id, alice); alice.store.applyReady();
  assert.equal(byId(alice.store, early.id).outcome, 'pending');
  alice.store.now = () => Date.parse(early.expires);
  alice.store.applyReady();
  assert.equal(byId(alice.store, early.id).outcome_code, 'expired-before-apply');
});

test('a receipt racing a correlated refusal remains delivery evidence without permitting a resend', t => {
  const { alice, bob } = setup(t);
  const original = event(alice, bob), token = sign(alice, original);
  let row;
  alice.store.transaction(() => { row = alice.store.queueSigned(token); });
  const receipt = receive(token, bob.card.id, bob);
  const refusal = event(bob, alice, { type: rejectionType, grant: undefined, required: [], thread: original.thread,
    inReplyTo: original.id, data: { code: 'policy-denied' } });
  receive(sign(bob, refusal, typs.rejection), alice.card.id, alice); alice.store.applyReady();
  assert.equal(alice.store.db.prepare('SELECT status FROM outbox').get().status, 'refused');
  alice.store.delivered(row, receipt);
  const delivery = alice.store.db.prepare('SELECT * FROM outbox').get();
  assert.equal(delivery.status, 'delivered'); assert.equal(delivery.refused_code, 'policy-denied');
  assert.equal(delivery.receipt, receipt); assert.equal(alice.store.due().length, 0);
});


test('provider receipts and rejections require a currently valid provider signing key', t => {
  const { alice, bob } = setup(t);
  const config = bob.store.config;
  const key = config.card.document.keys[0];
  const original = structuredClone(key);
  const invalid = [
    { validUntil: new Date(Date.now() - 1000).toISOString() },
    { revoked: new Date().toISOString() },
    { purpose: ['record'] },
    { validFrom: new Date(Date.now() + 60_000).toISOString() },
  ];
  const unavailable = error => {
    assert.equal(error.code, 'unavailable');
    const response = problemResponse(error.code);
    assert.equal(response.status, 503);
    assert.equal(response.headers['content-type'], 'application/problem+json');
    return true;
  };
  for (const change of invalid) {
    const count = bob.store.db.prepare("SELECT count(*) AS n FROM events WHERE direction='out'").get().n;
    Object.assign(key, change);
    const record = event(alice, bob, { data: { invalid: true } });
    const token = sign(alice, record);
    assert.throws(() => receive(token, bob.card.id, bob), unavailable);
    assert.equal(byId(bob.store, record.id), undefined);
    for (const name of Object.keys(key)) delete key[name];
    Object.assign(key, structuredClone(original));
    const receipt = receive(token, bob.card.id, bob);
    Object.assign(key, change);
    assert.throws(() => bob.store.applyReady(), unavailable);
    const stored = byId(bob.store, record.id);
    assert.equal(stored.receipt, receipt);
    assert.equal(stored.outcome, null);
    assert.equal(stored.rejection_row, null);
    assert.equal(bob.store.db.prepare("SELECT count(*) AS n FROM events WHERE direction='out'").get().n, count);
    assert.equal(receive(token, bob.card.id, bob), receipt, 'Duplicates replay the committed receipt');
    for (const name of Object.keys(key)) delete key[name];
    Object.assign(key, structuredClone(original));
    bob.store.applyReady();
    const rejection = bob.store.db.prepare('SELECT * FROM events WHERE row_id=?').get(byId(bob.store, record.id).rejection_row);
    verifyRecord(rejection.jws, { typ: typs.rejection, mode: 'evidence', answered: token }, () => config.card.document);
  }
  // An unusable preferred signer must not hide an available valid provider signer.
  config.providerSigner = { ...config.signer, kid: config.card.document.id + '#missing' };
  const record = event(alice, bob);
  const receipt = receive(sign(alice, record), bob.card.id, bob);
  verifyRecord(receipt, { typ: typs.receipt, mode: 'evidence' }, () => config.card.document);
});

test('local signing storage failures stay transient without failing dependent deliveries', async t => {
  const { alice, bob } = setup(t);
  const row = queue(alice, bob);
  const child = event(alice, bob, { thread: row.topic, inReplyTo: row.event_id });
  alice.store.transaction(() => alice.store.queueSigned(sign(alice, child)));
  alice.store.db.exec("CREATE TRIGGER fail_signature BEFORE UPDATE OF jws ON events BEGIN SELECT RAISE(ABORT, 'Injected storage failure'); END");
  let calls = 0;
  const transport = async (_url, request) => {
    calls++;
    return new Response(receive(request.body, bob.card.id, bob), { headers: { 'content-type': 'application/jose' } });
  };
  const before = alice.store.now();
  await send(row, alice.config, alice.store, transport);
  assert.equal(calls, 0);
  const delivery = alice.store.db.prepare('SELECT * FROM outbox WHERE event_row=?').get(row.row_id);
  assert.equal(delivery.status, 'queued');
  assert.ok(delivery.next_at >= before + 1000);
  assert.equal(alice.store.db.prepare('SELECT result FROM attempts').get().result, 'transient');
  assert.equal(byId(alice.store, row.event_id).jws, null);
  assert.equal(alice.store.db.prepare("SELECT count(*) AS n FROM outbox WHERE status='queued'").get().n, 2);
  alice.store.db.exec('DROP TRIGGER fail_signature');
  alice.store.now = () => delivery.next_at;
  await send(row, alice.config, alice.store, transport);
  assert.equal(calls, 1);
  assert.equal(alice.store.db.prepare('SELECT status FROM outbox WHERE event_row=?').get(row.row_id).status, 'delivered');
});

test('stale selections never transmit finalized records and concurrent workers share one claim', async t => {
  const { alice, bob } = setup(t);
  const row = queue(alice, bob);
  const other = new Store(alice.dir, alice.card.id);
  t.after(() => other.close());
  let calls = 0;
  const transport = async () => { calls++; return new Response('', { status: 503 }); };
  for (const status of ['refused', 'delivered', 'failed']) {
    other.db.prepare('UPDATE outbox SET status=? WHERE event_row=?').run(status, row.row_id);
    await send(row, alice.config, alice.store, transport);
    assert.equal(calls, 0, status);
  }
  other.db.prepare("UPDATE outbox SET status='queued' WHERE event_row=?").run(row.row_id);
  let resolveResponse;
  const pending = new Promise(resolve => { resolveResponse = resolve; });
  const first = send(row, alice.config, alice.store, async () => { calls++; return pending; });
  await send(row, alice.config, other, transport);
  resolveResponse(new Response('', { status: 503 }));
  await first;
  assert.equal(calls, 1, 'Only the worker owning the durable claim transmits');
  // A refusal that arrives during signing must be checked again at transmission.
  other.db.prepare('UPDATE outbox SET next_at=0 WHERE event_row=?').run(row.row_id);
  const signed = alice.store.signed.bind(alice.store);
  alice.store.signed = selected => {
    const token = signed(selected);
    other.db.prepare("UPDATE outbox SET status='refused',refused_code='policy-denied' WHERE event_row=?").run(row.row_id);
    return token;
  };
  await send(row, alice.config, alice.store, transport);
  assert.equal(calls, 1);
});

test('late correlated rejection preserves failed delivery and keeps thread reads usable', t => {
  const { alice, bob } = setup(t);
  const row = queue(alice, bob);
  alice.store.signed(row);
  alice.store.unsuccessful(row, 'Permanent carrier failure', true);
  const refusal = event(bob, alice, { type: rejectionType, grant: undefined, required: [], thread: row.topic,
    inReplyTo: row.event_id, data: { code: 'policy-denied' } });
  receive(sign(bob, refusal, typs.rejection), alice.card.id, alice);
  alice.store.applyReady();
  const view = alice.store.view(row.topic, undefined, handoffType);
  assert.equal(view.transport.failed, 1);
  assert.equal(view.transport.firstFailed, null);
  assert.equal(view.transport.retryableFailed, 0);
  const history = view.history.find(item => item.event.id === row.event_id);
  assert.equal(history.delivery, 'failed');
  assert.equal(history.refusal, 'policy-denied');
  assert.equal(history.deliveryError, 'Permanent carrier failure');
  assert.equal(alice.store.list(undefined, handoffType).threads[0].transport.firstFailed, null);
  assert.throws(() => alice.store.retryDelivery(row.topic, row.event_id), /first failed/);
});

test('response evidence preserves invalid UTF-8 bytes across migration and restart', async t => {
  const { alice, bob } = setup(t);
  const row = queue(alice, bob);
  const bytes = Buffer.from([0xff, 0xc3, 0x28, 0x00, 0x80]);
  await send(row, alice.config, alice.store, async () => new Response(bytes, { headers: { 'content-type': 'application/jose' } }));
  const attempt = alice.store.db.prepare('SELECT * FROM attempts').get();
  assert.ok(attempt.body_bytes, 'Raw bytes must be stored separately from decoded text');
  assert.deepEqual(Buffer.from(attempt.body_bytes), bytes);
  assert.equal(attempt.result, 'receipt-mismatch');
  alice.store.close(); alice.store = new Store(alice.dir, alice.card.id);
  assert.deepEqual(Buffer.from(alice.store.db.prepare('SELECT body_bytes FROM attempts').get().body_bytes), bytes);
  // Recreate the pre-upgrade column set and confirm migration preserves old evidence.
  alice.store.db.exec('ALTER TABLE attempts DROP COLUMN body_bytes; ALTER TABLE outbox DROP COLUMN claim_token; ALTER TABLE outbox DROP COLUMN claim_until; PRAGMA user_version=1');
  alice.store.close(); alice.store = new Store(alice.dir, alice.card.id);
  const migrated = alice.store.db.prepare('SELECT * FROM attempts').get();
  assert.equal(migrated.body, attempt.body);
  assert.equal(migrated.body_bytes, null, 'Do not invent original bytes for legacy decoded evidence');
  assert.equal(alice.store.db.prepare('PRAGMA user_version').get().user_version, 2);
});

test('response reads stop at 65536 octets and cancel without an extra read', async t => {
  const { alice, bob } = setup(t);
  for (const chunks of [[65537], [65536, 1], [32768, 32769]]) {
    const row = queue(alice, bob);
    let consumed = 0, reads = 0, cancelled = false, overBudgetRead = false;
    const stream = new ReadableStream({
      type: 'bytes',
      start(controller) { for (const size of chunks) controller.enqueue(new Uint8Array(size).fill(65)); },
      cancel() { cancelled = true; },
    });
    const body = { getReader(options) {
      const reader = stream.getReader(options);
      return {
        async read(view) {
          reads++;
          // The old unbounded reader would otherwise hang after a full-size chunk.
          if (consumed >= 65536) { overBudgetRead = true; return { done: true }; }
          const result = await reader.read(view);
          consumed += result.value?.length ?? 0;
          return result;
        },
        cancel: () => reader.cancel(), releaseLock: () => reader.releaseLock(),
      };
    } };
    await send(row, alice.config, alice.store, async () => ({ status: 200, headers: new Headers({ 'content-type': 'application/jose' }), body }));
    assert.equal(consumed, 65536, 'Never consume an oversized chunk past the budget');
    assert.equal(overBudgetRead, false, 'Never probe for EOF beyond the budget');
    assert.ok(reads <= (chunks[0] === 32768 ? 2 : 1));
    assert.equal(cancelled, true);
    const attempt = alice.store.db.prepare('SELECT * FROM attempts WHERE event_row=?').get(row.row_id);
    assert.equal(attempt.result, 'receipt-mismatch');
    assert.equal(Buffer.from(attempt.body_bytes).length, 65536);
    assert.equal(alice.store.db.prepare('SELECT status FROM outbox WHERE event_row=?').get(row.row_id).status, 'queued');
  }
});
