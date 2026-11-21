import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { localPair, call, sample, until } from '../examples/local-pair.js';
import { loadConfig } from '../src/config.js';
import { connectClient } from '../src/mcp.js';
import { Store } from '../src/store.js';
import { eventMedia, receiptMedia, makeEvent, hash } from '../src/protocol.js';
import { signCompact, verifyRecord } from '../src/records.js';

// Evidence-mode verification (records.md §7.3) of a receipt signed by a pinned contact.
const receiptFrom = (card, token) =>
  verifyRecord(token, { typ: receiptMedia, mode: 'evidence' }, id => id === card.document.id ? card.document : null).record;

async function fixture(t) {
  const pair = await localPair();
  const clients = [];
  t.after(async () => {
    await Promise.all(clients.map(client => client.close()));
    await pair.close();
  });
  return { ...pair, async client(person, grant = person.grant) {
    const client = await connectClient({ ...grant, url: person.grant.url });
    clients.push(client);
    return client;
  } };
}
const read = (client, threadId) => call(client, 'get_reschedule', { threadId });
const act = (client, state, action) => call(client, 'respond_reschedule', {
  threadId: state.threadId, expectedHead: state.head, action,
});
const waitFor = (client, id, predicate) => until(async () => {
  const state = await read(client, id);
  return predicate(state) && state;
});

test('two owners resume asynchronously; countering invalidates old confirmations; restarts preserve agreement', async t => {
  const f = await fixture(t);
  await f.alice.start();
  const a = await f.client(f.alice);
  const input = sample(f.bob.card.id);
  const [first, repeated] = await Promise.all([call(a, 'request_reschedule', input), call(a, 'request_reschedule', input)]);
  const id = first.threadId;
  assert.equal(repeated.threadId, id);
  assert.equal(first.transport.headDelivery, 'queued');
  assert.equal(first.transport.deliveredAt, null);
  assert.match(first.followUp, /ask again or refresh/);
  await assert.rejects(call(a, 'request_reschedule', { ...input, durationMinutes: 30 }), /409/);
  await waitFor(a, id, s => s.history[0].attempts > 0 && s.history[0].delivery === 'queued');
  await a.close();
  await f.bob.start();
  const a2 = await f.client(f.alice);
  assert.equal((await waitFor(a2, id, s => s.history[0].delivery === 'delivered')).status, 'requested');
  const b = await f.client(f.bob);
  const opening = (await call(b, 'list_reschedules')).threads[0];
  assert.equal(opening.threadId, id);
  await assert.rejects(act(b, opening, { kind: 'confirm', slot: opening.slots[0] }), /Accept coordination first/);
  const accepted = await act(b, opening, { kind: 'accept' });
  assert.equal((await act(b, opening, { kind: 'accept' })).head, accepted.head);
  const selected = await act(b, accepted, { kind: 'confirm', slot: accepted.slots[0] });
  assert.deepEqual(selected.confirmedBy, [f.bob.card.id]);
  const received = await waitFor(a2, id, s => s.head === selected.head);
  await assert.rejects(act(a2, first, { kind: 'decline' }), /409/);
  await assert.rejects(act(a2, received, { kind: 'confirm', slot: received.slots[1] }), /Counter before/);
  const alternative = await act(a2, received, { kind: 'counter', slots: ['2030-04-07T20:00:00+02:00'] });
  assert.deepEqual(alternative.confirmedBy, []);
  assert.equal(alternative.selectedSlot, null);
  assert.deepEqual(alternative.slots, ['2030-04-07T18:00:00Z']);
  const atBob = await waitFor(b, id, s => s.head === alternative.head);
  await assert.rejects(act(b, atBob, { kind: 'confirm', slot: selected.selectedSlot }), /current candidate/);
  const oneYes = await act(b, atBob, { kind: 'confirm', slot: atBob.slots[0] });
  await waitFor(a2, id, s => s.head === oneYes.head);
  const both = await act(a2, oneYes, { kind: 'confirm', slot: oneYes.selectedSlot });
  assert.deepEqual(both.confirmedBy, [f.bob.card.id, f.alice.card.id]);
  await waitFor(a2, id, s => s.history.at(-1).delivery === 'delivered');
  await Promise.all([f.alice.stop(), f.bob.stop()]);
  await Promise.all([f.alice.start(), f.bob.start()]);
  const newA = await f.client(f.alice), newB = await f.client(f.bob);
  const [left, right] = await Promise.all([read(newA, id), read(newB, id)]);
  assert.equal(left.head, right.head);
  assert.equal(left.status, 'confirmed');
  assert.equal(right.selectedSlot, '2030-04-07T18:00:00Z');
  assert.equal(left.history.length, 6);
  assert.equal(right.history.length, 6);
  await assert.rejects(act(newB, right, { kind: 'counter', slots: right.slots }), /409/);
});

test('a dropped committed receipt survives process restarts; HTTP success alone never marks it delivered', async t => {
  const f = await fixture(t);
  let mode = 'drop';
  const savedReceipts = [];
  const relay = createServer(async (req, res) => {
    try {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const remote = await fetch(f.bob.card.origin + '/darep/v2/inbox', {
        method: 'POST', headers: { 'content-type': 'application/jose', 'darep-recipient': req.headers['darep-recipient'] },
        body: Buffer.concat(chunks),
      });
      const token = await remote.text();
      assert.equal(remote.status, 200);
      savedReceipts.push({ ...receiptFrom(f.bob.card, token), token });
      if (mode === 'drop') return res.destroy();
      res.writeHead(200, { 'content-type': 'application/jose' }).end(mode === 'bad' ? 'unverified receipt' : token);
    } catch { res.destroy(); }
  });
  relay.listen(0, '127.0.0.1');
  await once(relay, 'listening');
  t.after(() => new Promise(resolve => relay.close(resolve)));
  f.alice.trust({ ...f.bob.card, origin: 'http://127.0.0.1:' + relay.address().port });
  await Promise.all([f.alice.start(), f.bob.start()]);
  const a = await f.client(f.alice);
  const { threadId } = await call(a, 'request_reschedule', sample(f.bob.card.id));
  await waitFor(a, threadId, s => s.history[0].attempts >= 1 && s.history[0].delivery === 'queued');
  assert.ok(savedReceipts.length);
  await Promise.all([f.alice.stop(), f.bob.stop()]);
  mode = 'bad';
  await Promise.all([f.alice.start(), f.bob.start()]);
  const newA = await f.client(f.alice);
  await waitFor(newA, threadId, s => s.history[0].attempts >= 2 && s.history[0].delivery === 'queued');
  mode = 'deliver';
  const acknowledged = await waitFor(newA, threadId, s => s.history[0].delivery === 'delivered');
  assert.equal(acknowledged.history[0].deliveredAt, savedReceipts[0].data.storedAt);
  assert.ok(savedReceipts.length >= 3);
  // Every retry returns the same receipt, including its id and signature.
  for (const receipt of savedReceipts) {
    assert.equal(receipt.token, savedReceipts[0].token);
  }
  const b = await f.client(f.bob);
  assert.equal((await read(b, threadId)).history.length, 1);
  assert.equal((await call(b, 'list_reschedules')).threads.length, 1);
});

test('a slow signed receipt can arrive after the MCP write returns', async t => {
  const pair = await fixture(t);
  const release = Promise.withResolvers();
  const received = Promise.withResolvers();
  const relay = createServer(async (req, res) => {
    try {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const peerReply = await fetch(pair.bob.card.origin + '/darep/v2/inbox', {
        method: 'POST', headers: { 'content-type': 'application/jose', 'darep-recipient': req.headers['darep-recipient'] },
        body: Buffer.concat(chunks),
      });
      const receipt = await peerReply.text();
      received.resolve();
      await release.promise;
      res.writeHead(peerReply.status, { 'content-type': 'application/jose' }).end(receipt);
    } catch { res.destroy(); }
  });
  relay.listen(0, '127.0.0.1');
  await once(relay, 'listening');
  t.after(() => new Promise(resolve => relay.close(resolve)));
  pair.alice.trust({ ...pair.bob.card, origin: 'http://127.0.0.1:' + relay.address().port });
  await Promise.all([pair.alice.start(), pair.bob.start()]);
  const a = await pair.client(pair.alice), b = await pair.client(pair.bob);
  const request = call(a, 'request_reschedule', sample(pair.bob.card.id));
  try {
    await received.promise;
    const pending = await request;
    assert.equal(pending.transport.headDelivery, 'queued');
    assert.equal(pending.history[0].deliveredAt, null);
    assert.equal(pending.history[0].attempts, 0, 'The call finished while the first delivery was still in flight');
    release.resolve();
    const delivered = await waitFor(a, pending.threadId, view => view.transport.headDelivery === 'delivered');
    const local = await read(b, pending.threadId);
    assert.equal(local.history.length, 1);
    assert.equal(delivered.transport.deliveredAt, local.history[0].storedAt);
  } finally { release.resolve(); }
});

test('read, coordination and confirmation are separately authorized; expiry and revocation apply to live sessions', async t => {
  const f = await fixture(t);
  await Promise.all([f.alice.start(), f.bob.start()]);
  const store = new Store(f.bob.dir, f.bob.card.id);
  t.after(() => store.close());
  const reader = store.issue(['read'], 1), coordinator = store.issue(['read', 'coordinate'], 1);
  const ro = await f.client(f.bob, reader), coord = await f.client(f.bob, coordinator);
  const a = await f.client(f.alice);
  await assert.rejects(f.client(f.bob, f.alice.grant), { code: 401 });
  await assert.rejects(call(ro, 'request_reschedule', sample(f.alice.card.id)), /403/);
  await assert.rejects(call(a, 'request_reschedule', { ...sample(f.bob.card.id), privateReason: 'unshared' }));
  await assert.rejects(call(a, 'request_reschedule', { ...sample(f.bob.card.id), activity: 'Different event' }), /403/);
  await assert.rejects(call(a, 'request_reschedule', { ...sample(f.bob.card.id), slots: ['2030-05-01T09:00:00Z'] }), /403/);
  assert.equal((await call(a, 'list_reschedules')).threads.length, 0);
  const { threadId } = await call(a, 'request_reschedule', sample(f.bob.card.id));
  await waitFor(a, threadId, s => s.history[0].delivery === 'delivered');
  const received = await read(ro, threadId);
  const accepted = await act(coord, received, { kind: 'accept' });
  await assert.rejects(act(coord, accepted, { kind: 'counter', slots: ['2030-05-01T09:00:00Z'] }), /403/);
  await assert.rejects(act(coord, accepted, { kind: 'confirm', slot: accepted.slots[0] }), /403/);
  const { requestKey, ...rule } = sample(f.alice.card.id);
  f.bob.allow({ ...rule, slots: [] });
  const delegated = await f.client(f.bob);
  await assert.rejects(act(delegated, accepted, { kind: 'confirm', slot: accepted.slots[0] }), /403/);
  assert.equal((await read(ro, threadId)).head, accepted.head);
  const declined = await act(coord, accepted, { kind: 'decline' });
  assert.equal(declined.status, 'declined');
  assert.equal((await waitFor(a, threadId, s => s.head === declined.head)).turn, null);
  assert.ok(store.revoke(reader.id));
  await assert.rejects(read(ro, threadId), { code: 401 });
  store.db.prepare('UPDATE grants SET expires=? WHERE id=?').run(Date.now() - 1, coordinator.id);
  await assert.rejects(read(coord, threadId), { code: 401 });
});

test('federation verifies v2 records against the pinned document, checks version, detects conflicts and late dependencies', async t => {
  const f = await fixture(t);
  await f.bob.start();
  const alice = loadConfig(f.alice.dir);
  const { requestKey, peer, ...occurrence } = sample(f.bob.card.id);
  const event = makeEvent(f.alice.card.id, peer, { kind: 'request', ...occurrence });
  async function post(value, { signer = alice.signer, typ = eventMedia, recipient = f.bob.card.id } = {}) {
    const token = signCompact(typeof value === 'string' ? value : JSON.stringify(value), signer, typ);
    const res = await fetch(f.bob.card.origin + '/darep/v2/inbox', { method: 'POST',
      headers: { 'content-type': 'application/jose', ...(recipient ? { 'darep-recipient': recipient } : {}) }, body: token });
    const text = await res.text();
    return { status: res.status, text, code: res.headers.get('content-type')?.includes('json') ? JSON.parse(text).code : undefined };
  }
  const check = async (value, options, status, code) => assert.deepEqual(
    (({ status, code }) => ({ status, code }))(await post(value, options)), { status, code });
  await check({ ...event, darep: '9' }, {}, 400, 'unsupported-version');
  const { darep, ...v1 } = event;
  await check({ ...v1, specversion: '1.0' }, {}, 400, 'unsupported-version');
  // The old envelope member is not an alias; it is also forbidden alongside darep.
  await check({ ...v1, ack: '2' }, {}, 400, 'unsupported-version');
  await check({ ...event, ack: '2' }, {}, 400, 'malformed');
  await check(event, { typ: 'agent-network-event+jws' }, 400, 'bad-header');
  await check(event, { signer: { key: alice.key, kid: f.alice.card.id } }, 400, 'bad-header');
  await check({ ...event, source: 'acct:charlie@else.test' }, {}, 403, 'signer-mismatch');
  await check(event, { signer: { key: alice.key, kid: 'https://else.test/.well-known/darep/charlie#k' } }, 403, 'unknown-key');
  await check(event, { signer: { key: loadConfig(f.bob.dir).key, kid: alice.kid } }, 400, 'bad-signature');
  await check({ ...event, to: ['acct:charlie@else.test'] }, {}, 403, 'wrong-recipient');
  await check(event, { recipient: null }, 403, 'wrong-recipient');
  // An unhosted recipient is refused only after signature verification (delivery.md §3.1 R12).
  await check(event, { recipient: 'acct:charlie@else.test' }, 403, 'wrong-recipient');
  for (const recipient of [f.bob.card.id, 'acct:charlie@else.test']) {
    const res = await fetch(f.bob.card.origin + '/darep/v2/inbox', { method: 'POST',
      headers: { 'content-type': 'application/jose', 'darep-recipient': recipient }, body: 'not-a-jws' });
    assert.deepEqual([res.status, (await res.json()).code], [400, 'malformed']);
  }
  // Back-dated before the signing key's validFrom: key validity (step 11) fails before the clock (step 13).
  await check({ ...event, time: '2020-01-01T00:00:00Z', expires: '2020-01-08T00:00:00Z' }, {}, 403, 'key-not-valid');
  const later = Date.parse(event.time) + 31 * 24 * 3600_000;
  await check({ ...event, expires: new Date(later).toISOString() }, {}, 400, 'malformed');
  await check({ ...event, time: new Date(Date.now() + 3600_000).toISOString() }, {}, 425, 'not-yet-valid');
  await check({ ...event, required: ['https://example.test/ext/unknown/v1'] }, {}, 422, 'unsupported-extension');
  await check({ ...event, grant: { id: 'g', actor: 'robot' } }, {}, 400, 'malformed');
  const early = { ...event, id: randomUUID(), inReplyTo: event.id, type: 'https://darep.org/ext/reschedule/v2#accept', data: {} };
  assert.equal((await post(early)).status, 200);
  const ok = await post(event);
  assert.equal(ok.status, 200);
  const receipt = receiptFrom(f.bob.card, ok.text);
  assert.equal(receipt.data.sha256, hash(JSON.stringify(event)));
  assert.deepEqual([receipt.source, receipt.to, receipt.inReplyTo, receipt.thread], [f.bob.card.id, [f.alice.card.id], event.id, event.thread]);
  assert.equal((await post(event)).status, 200);
  const changed = { ...event, data: { ...event.data, activity: 'Other activity' } };
  await check(changed, {}, 409, 'id-conflict');
  const b = await f.client(f.bob);
  const state = await read(b, event.thread);
  assert.equal(state.history.length, 3);
  assert.equal(state.history[0].outcome, 'refused');
  assert.equal(state.history[0].outcomeCode, 'wrong-turn');
  assert.equal(state.activity, occurrence.activity);
});


test('HTTP identity GET and HEAD share headers; unknown identity paths return empty 404', async t => {
  const f = await fixture(t);
  await f.alice.start();
  const path = new URL(f.alice.card.document.id).pathname;
  const url = f.alice.card.origin + path;
  const get = await fetch(url);
  assert.equal(get.status, 200);
  assert.deepEqual(await get.json(), f.alice.card.document);
  const head = await fetch(url, { method: 'HEAD' });
  assert.equal(head.status, 200);
  for (const name of ['content-type', 'cache-control', 'access-control-allow-origin']) {
    assert.equal(head.headers.get(name), get.headers.get(name), name);
  }
  assert.equal(await head.text(), '');
  for (const method of ['GET', 'HEAD']) {
    const missing = await fetch(url + '-unknown', { method });
    assert.equal(missing.status, 404);
    assert.equal(await missing.text(), '');
  }
});
