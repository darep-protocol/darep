import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, rm, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { initialize, loadConfig } from '../src/config.js';
import { Store } from '../src/store.js';
import { localPair, call, sample, until } from '../examples/local-pair.js';
import { connectClient } from '../src/mcp.js';

// Wire v2 (A1) is a breaking wire change with a data wipe. Wire v1 state must be refused loudly,
// never reinterpreted, because a v1 contact card cannot verify a v2 record.
test('a Wire v1 provider directory and Wire v1 contacts are refused, not reused', async () => {
  const root = await mkdtemp(join(tmpdir(), 'darep-v1-'));
  try {
    const v1 = join(root, 'v1');
    await mkdir(v1);
    const keys = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    await writeFile(join(v1, 'provider.json'), JSON.stringify({
      card: { version: 1, id: 'acct:alice@old.test', origin: 'http://127.0.0.1:1',
        publicKey: keys.publicKey.export({ type: 'spki', format: 'pem' }) },
      privateKey: keys.privateKey.export({ type: 'pkcs8', format: 'pem' }),
    }));
    assert.throws(() => loadConfig(v1), { status: 409, message: /Wire v1/ });

    const dir = join(root, 'v2');
    const card = initialize(dir, 'acct:bob@new.test', 'http://127.0.0.1:2');
    assert.equal(loadConfig(dir).kid, card.document.keys[0].id);
    const store = new Store(dir, card.id);
    try {
      store.db.prepare('INSERT INTO contacts VALUES (?, ?)').run('acct:alice@old.test', JSON.stringify({
        version: 1, id: 'acct:alice@old.test', origin: 'http://127.0.0.1:1', publicKey: 'x' }));
      assert.throws(() => store.contact('acct:alice@old.test'), { status: 409, message: /Wire v1/ });
      assert.throws(() => store.trust({ version: 1, id: 'acct:carol@old.test', origin: 'http://127.0.0.1:3', publicKey: 'x' }),
        { status: 400 });
    } finally { store.close(); }
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('a long v2 thread chains inReplyTo and supports paged resume on both sides', async t => {
  const pair = await localPair();
  const clients = [];
  t.after(async () => { await Promise.all(clients.map(c => c.close())); await pair.close(); });
  const { alice: a, bob: b } = pair;
  await Promise.all([a.start(), b.start()]);
  for (const p of [a, b]) {
    p.client = await connectClient(p.grant);
    clients.push(p.client);
  }
  const occurrence = sample(b.card.id);
  const { threadId: id } = await call(a.client, 'request_reschedule', occurrence);
  const get = (p, extra = {}) => call(p.client, 'get_reschedule', { threadId: id, ...extra });
  let head = id;
  async function step(actor, other, action) {
    await until(async () => (await get(actor)).head === head);
    const value = await call(actor.client, 'respond_reschedule', { threadId: id, expectedHead: head, action });
    head = value.head;
    await until(async () => (await get(other)).head === head);
    return value;
  }
  const slot = (await get(a)).slots[0];
  await step(b, a, { kind: 'accept' });
  for (let n = 0; n < 28; n++) await step(n % 2 ? a : b, n % 2 ? b : a, { kind: 'counter', slots: (await get(a)).slots });
  await step(b, a, { kind: 'confirm', slot });
  await step(a, b, { kind: 'confirm', slot });
  for (const person of [a, b]) {
    const page1 = await get(person), page2 = await get(person, { before: page1.nextBefore });
    assert.equal(page1.status, 'confirmed');
    assert.equal(page1.history.length, 25);
    assert.equal(page2.history.length, 7);
    assert.equal(page2.nextBefore, null);
    const chronological = [...page2.history, ...page1.history].map(row => row.event);
    assert.equal(chronological[0].id, id);
    assert.equal(new Set(chronological.map(e => e.id)).size, 32);
    chronological.forEach(e => { assert.equal(e.darep, '2'); assert.equal(e.thread, id); assert.equal(e.grant.actor, 'agent'); });
    chronological.slice(1).forEach((e, i) => assert.equal(e.inReplyTo, chronological[i].id));
  }
});
