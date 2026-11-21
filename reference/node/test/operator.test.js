import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { get } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { initialize } from '../src/config.js';
import { connectClient } from '../src/mcp.js';
import { startOperator } from '../src/operator.js';
import { Store } from '../src/store.js';
import { handoffType, parse, startInput } from '../src/protocol.js';
import { localPair, sample } from '../examples/local-pair.js';

const cli = fileURLToPath(new URL('../src/cli.js', import.meta.url));
async function wait(check) {
  const end = Date.now() + 10_000;
  while (Date.now() < end) {
    const value = await check();
    if (value) return value;
    await delay(40);
  }
  throw new Error('Timed out waiting for local test');
}
function panel(link) {
  const { origin, hash } = new URL(link);
  const key = new URLSearchParams(hash.slice(1)).get('key');
  const headers = { origin, authorization: 'Bearer ' + key, 'content-type': 'application/json' };
  function post(op, data = {}, customHeaders = {}) {
    return fetch(origin + '/api/' + op, { method: 'POST', headers: { ...headers, ...customHeaders }, body: JSON.stringify(data) });
  }
  async function action(op, data = {}) {
    const res = await post(op, data);
    const value = await res.json();
    assert.equal(res.status, 200, value.error);
    return value;
  }
  async function approve(code) {
    const inspected = await action('inspect', { code });
    return action('approve', { code, fingerprint: inspected.fingerprint });
  }
  return { origin, action, approve, post };
}
async function launch(t, root, name) {
  const reservation = createServer();
  reservation.listen(0, '127.0.0.1');
  await once(reservation, 'listening');
  const port = reservation.address().port;
  await new Promise(resolve => reservation.close(resolve));
  const args = [cli, 'operator', '--dir', join(root, name), '--port', String(port), '--id', 'acct:' + name + '@' + name + '.test'];
  const proc = spawn(process.execPath, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  let log = '';
  proc.stdout.on('data', data => { log += data; });
  let stderr = '';
  proc.stderr.on('data', data => { stderr = (stderr + data).slice(-2000); });
  t.after(async () => {
    if (proc.exitCode !== null || proc.signalCode) return;
    const done = once(proc, 'exit');
    proc.kill('SIGTERM');
    await done;
  });
  return panel(await wait(() => {
    assert.equal(proc.exitCode, null, 'Operator exited before startup: ' + stderr.replace(/#key=[\w-]+/g, '#key=[omitted]'));
    return log.match(/http:\/\/127\.0\.0\.1:\d+\/#key=[\w-]+/)?.[0];
  }));
}
const rule = peer => ({ peer, activity: 'Weekend tennis', originalStart: '2030-03-09T10:00:00Z',
  durationMinutes: 60, slots: ['2030-03-10T14:00:00Z'] });

async function tool(client, name, input) {
  const reply = await client.callTool({ name, arguments: input });
  if (reply.isError) throw new Error(reply.content[0].text);
  return JSON.parse(reply.content[0].text);
}

test('two fresh CLI owner consoles pair once and approve a real MCP reschedule without copying credentials', async t => {
  const root = await mkdtemp(join(tmpdir(), "owner's pilot "));
  try {
    await t.test('first setup through confirmed time', async t => {
      const started = Date.now();
      const [a, b, c] = await Promise.all(['alice', 'bob', 'charlie'].map(n => launch(t, root, n)));
      const [alice, bob] = await Promise.all([a.action('state'), b.action('state')]);
      const invite = await a.action('invite');
      assert.equal((await b.action('inspect', { code: invite.code })).fingerprint, alice.fingerprint);
      assert.equal((await b.post('approve', { code: invite.code, fingerprint: bob.fingerprint })).status, 400);
      const answer = await b.approve(invite.code);
      assert.equal((await b.approve(invite.code)).code, answer.code);
      assert.deepEqual((await b.action('state')).contacts, []);
      const finish = await a.approve(answer.code);
      assert.equal((await a.approve(answer.code)).code, finish.code);
      const extra = await c.approve(invite.code);
      assert.equal((await a.post('approve', { code: extra.code, fingerprint: (await c.action('state')).fingerprint })).status, 409);
      assert.deepEqual((await b.action('state')).contacts, []);
      assert.equal((await b.approve(finish.code)).phase, 'paired');
      assert.equal((await b.approve(finish.code)).phase, 'paired');
      assert.equal((await c.post('inspect', { code: finish.code })).status, 403);
      assert.deepEqual((await a.action('state')).contacts.map(v => v.id), [bob.owner]);
      assert.deepEqual((await b.action('state')).contacts.map(v => v.id), [alice.owner]);
      await a.action('allow', rule(bob.owner));
      await b.action('allow', rule(alice.owner));
      const aGrant = await a.action('grant', { confirmation: true });
      const bGrant = await b.action('grant', { confirmation: false });
      const aFile = JSON.parse(await readFile(aGrant.file, 'utf8'));
      const bFile = JSON.parse(await readFile(bGrant.file, 'utf8'));
      assert.ok(!JSON.stringify(aGrant).includes(aFile.token));
      assert.ok(!JSON.stringify(await a.action('state')).includes(aFile.token));
      assert.deepEqual(bGrant.scopes, ['read', 'coordinate']);
      const aClient = await connectClient(aFile);
      const bClient = await connectClient(bFile);
      t.after(async () => { await aClient.close(); await bClient.close(); });
      const request = await tool(aClient, 'request_reschedule', { requestKey: 'practice', ...rule(bob.owner) });
      const threadId = request.threadId;
      const [incoming] = await wait(async () => {
        const threads = (await b.action('state')).threads;
        return threads.length && threads;
      });
      const accepted = await tool(bClient, 'respond_reschedule', { threadId, expectedHead: incoming.head, action: { kind: 'accept' } });
      const slot = accepted.slots[0];
      const decision = { threadId, expectedHead: accepted.head, action: { kind: 'confirm', slot } };
      await assert.rejects(tool(bClient, 'respond_reschedule', decision), /403/);
      assert.equal((await b.action('confirm', { threadId, expectedHead: accepted.head, slot })).status, 'awaiting_confirmation');
      const ready = await wait(async () => (await a.action('state')).threads.find(s => s.status === 'awaiting_confirmation'));
      await tool(aClient, 'respond_reschedule', { threadId, expectedHead: ready.head, action: { kind: 'confirm', slot } });
      await wait(async () => (await b.action('state')).threads.find(s => s.status === 'confirmed'));
      assert.equal((await a.action('revoke', { id: aGrant.id })).revoked, true);
      await assert.rejects(tool(aClient, 'list_reschedules', {}));
      t.diagnostic('Automated setup from fresh private directories through bilateral confirmation: ' + (Date.now() - started) + ' ms');
    });
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('operator requires localhost origin, exact host, owner capability and unexpired invites', async t => {
  const root = await mkdtemp(join(tmpdir(), 'operator-expiry-'));
  try {
    let now = Date.now();
    const local = [];
    try {
      for (const name of ['alice', 'bob']) {
        const dir = join(root, name);
        initialize(dir, 'acct:' + name + '@test.test', 'http://127.0.0.1:3100');
        local.push(await startOperator({ dir, now: () => now }));
      }
      const [a, b] = local.map(p => panel(p.url));
      assert.equal((await a.post('state', {}, { origin: b.origin })).status, 403);
      const mismatchedHostStatus = await new Promise((resolve, reject) => {
        get(a.origin + '/', { headers: { host: 'another.test' } }, res => {
          res.resume(); resolve(res.statusCode);
        }).on('error', reject);
      });
      assert.equal(mismatchedHostStatus, 403);
      assert.equal((await a.post('state', {}, { authorization: 'Bearer invalid' })).status, 401);
      const invite = await a.action('invite');
      await b.action('inspect', { code: invite.code });
      now += 16 * 60_000;
      assert.equal((await b.post('inspect', { code: invite.code })).status, 410);
      assert.deepEqual((await b.action('state')).contacts, []);
      for (const path of ['/', '/app.js', '/app.css']) {
        const asset = await fetch(a.origin + path);
        assert.equal(asset.status, 200, path);
        assert.ok(asset.headers.get('content-security-policy').includes("frame-ancestors 'none'"));
        assert.ok(!(await asset.text()).includes(local[0].url.split('#key=')[1]));
      }
    } finally { await Promise.all(local.map(o => o.close())); }
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('a cold owner console can cancel an invitation after its guest answered, or finish a different pending pair', async () => {
  const root = await mkdtemp(join(tmpdir(), 'operator-resume-'));
  let panels = [];
  const dirs = ['alice', 'bob'].map(n => join(root, n));
  async function open() {
    panels = await Promise.all(dirs.map(dir => startOperator({ dir })));
    return panels.map(p => panel(p.url));
  }
  async function close() {
    await Promise.all(panels.map(p => p.close()));
    panels = [];
  }
  try {
    initialize(dirs[0], 'acct:alice@pilot.test', 'http://127.0.0.1:4311');
    initialize(dirs[1], 'acct:bob@pilot.test', 'http://127.0.0.1:4312');
    let [a, b] = await open();
    assert.equal((await a.action('state')).timeZone, 'UTC');
    assert.deepEqual(await a.action('set-zone', { zone: 'Europe/London' }), { timeZone: 'Europe/London' });
    assert.equal((await a.post('set-zone', { zone: 'Unknown/Zone' })).status, 400);
    const withdrawn = await a.action('invite');
    const reply = await b.approve(withdrawn.code);
    const valid = await a.action('invite');
    const validReply = await b.approve(valid.code);
    const bOwner = await b.action('state');
    await close();
    [a, b] = await open();
    const ownerState = await a.action('state');
    assert.equal(ownerState.timeZone, 'Europe/London');
    assert.equal((await b.action('state')).timeZone, 'UTC');
    const pending = ownerState.pendingInvites;
    assert.deepEqual(pending.map(v => v.nonce).sort(), [withdrawn.nonce, valid.nonce].sort());
    assert.deepEqual(await a.action('cancel-invite', { nonce: withdrawn.nonce }), { cancelled: true });
    assert.deepEqual(await a.action('cancel-invite', { nonce: withdrawn.nonce }), { cancelled: false });
    assert.equal((await a.post('approve', { code: reply.code, fingerprint: bOwner.fingerprint })).status, 409);
    assert.deepEqual((await a.action('state')).contacts, []);
    const finish = await a.approve(validReply.code);
    assert.equal((await b.approve(finish.code)).phase, 'paired');
    assert.deepEqual(await a.action('cancel-invite', { nonce: valid.nonce }), { cancelled: false });
    assert.deepEqual((await a.action('state')).contacts.map(v => v.id), [bOwner.owner]);
    assert.deepEqual((await a.action('state')).pendingInvites, []);
  } finally { await close(); await rm(root, { recursive: true, force: true }); }
});

test('owner can reach older threads by workflow and see or revoke grants issued outside the console', async () => {
  const root = await mkdtemp(join(tmpdir(), 'operator-history-'));
  let owner, store;
  try {
    const dir = join(root, 'alice');
    const alice = initialize(dir, 'acct:alice@pilot.test', 'http://127.0.0.1:4311');
    const bob = initialize(join(root, 'bob'), 'acct:bob@pilot.test', 'http://127.0.0.1:4312');
    store = new Store(dir, alice.id);
    store.trust(bob);
    const permissions = store.issue(['read', 'confirm'], 1);
    const times = rule(bob.id), generated = { reschedule: [], handoff: [] };
    for (let i = 0; i < 53; i++) {
      const occurrence = { ...times, activity: 'Weekend tennis ' + i };
      store.allowTimes(occurrence);
      generated.reschedule.push(store.start({ requestKey: 'schedule-' + i, ...occurrence }).threadId);
      const fields = { summary: 'Progress ' + i, nextStep: 'Read and reply', expectedResult: 'A short summary' };
      store.allowHandoff({ peer: bob.id, action: { kind: 'handoff', ...fields } });
      generated.handoff.push(store.start({ peer: bob.id, requestKey: 'work-' + i, ...fields }, handoffType).threadId);
    }
    owner = await startOperator({ dir });
    const p = panel(owner.url);
    const first = await p.action('state');
    const old = first.grants.find(x => x.id === permissions.id);
    assert.deepEqual(old.scopes, ['read', 'confirm']);
    assert.equal(old.file, null);
    assert.equal(old.instructions, null);
    assert.deepEqual(await p.action('revoke', { id: old.id }), { revoked: true });
    assert.throws(() => store.authorize('Bearer ' + permissions.token), /valid provider grant/);
    for (const workflow of ['reschedule', 'handoff']) {
      const found = first.threads.filter(v => (v.workflow === handoffType) === (workflow === 'handoff'));
      let cursor = first.nextPages[workflow];
      assert.equal(found.length, 25);
      const pages = [];
      while (cursor) {
        const next = await p.action('threads', { workflow, before: cursor });
        pages.push(next.threads.length); found.push(...next.threads); cursor = next.nextBefore;
      }
      assert.deepEqual(pages, [25, 3]);
      assert.deepEqual(found.map(v => v.threadId), generated[workflow].reverse());
      assert.ok(found.every(v => v.transport?.headDelivery === 'queued' && v.transport?.pending === 1));
    }
  } finally { await owner?.close(); store?.close(); await rm(root, { recursive: true, force: true }); }
});

test('two independently opened requests show a collision; owner can decline one by its current head', async () => {
  const pair = await localPair();
  const { alice, bob } = pair;
  let aliceStore, bobStore, owner, clients = [];
  try {
    // Both owners create the request before either provider worker has seen its peer's opening.
    aliceStore = new Store(alice.dir, alice.card.id);
    bobStore = new Store(bob.dir, bob.card.id);
    const openedByAlice = aliceStore.start(parse(startInput, sample(bob.card.id)));
    const openedByBob = bobStore.start(parse(startInput, sample(alice.card.id)));
    assert.notEqual(openedByAlice.threadId, openedByBob.threadId);
    await Promise.all([alice.start(), bob.start()]);
    owner = await startOperator({ dir: bob.dir });
    const b = panel(owner.url);
    const atBob = await wait(async () => {
      const state = await b.action('state');
      return state.threads.find(th => th.threadId === openedByAlice.threadId && th.occurrenceConflict);
    });
    assert.equal(atBob.occurrenceConflict.needsOwnerDecision, true);
    assert.deepEqual(atBob.occurrenceConflict.threadIds.toSorted(), [openedByAlice.threadId,openedByBob.threadId].sort());
    const who = atBob.occurrenceConflict.threads.find(item => item.threadId === atBob.threadId);
    assert.equal(who.turn, bob.card.id);
    assert.equal(who.status, 'requested');
    assert.equal((await b.post('decline', { threadId: atBob.threadId, expectedHead: openedByBob.head })).status, 409);
    assert.equal((await b.action('decline', { threadId: atBob.threadId, expectedHead: atBob.head })).status, 'declined');
    const aClient = await connectClient(alice.grant);
    const bClient = await connectClient(bob.grant);
    clients = [aClient,bClient];
    await wait(async () => {
      const { threads } = await tool(aClient, 'list_reschedules', {});
      return threads.some(item => item.threadId === atBob.threadId && item.status === 'declined') &&
        threads.some(item => item.threadId === openedByBob.threadId);
    });
    const surviving = await tool(aClient, 'get_reschedule', { threadId: openedByBob.threadId });
    assert.ok(!surviving.occurrenceConflict);
    const accepted = await tool(aClient, 'respond_reschedule', {
      threadId: surviving.threadId, expectedHead: surviving.head, action: { kind: 'accept' },
    });
    const chosen = await tool(aClient, 'respond_reschedule', {
      threadId: surviving.threadId, expectedHead: accepted.head, action: { kind: 'confirm', slot: accepted.slots[0] },
    });
    await wait(async () => (await tool(bClient, 'get_reschedule', { threadId: surviving.threadId })).head === chosen.head);
    assert.equal((await b.action('confirm', { threadId: surviving.threadId, expectedHead: chosen.head, slot: chosen.selectedSlot })).status, 'confirmed');
  } finally {
    await Promise.all(clients.map(c => c.close()));
    await owner?.close(); aliceStore?.close(); bobStore?.close(); await pair.close();
  }
});

test('withdrawing one pending handoff via console or CLI leaves independent approved work usable', async () => {
  const pair = await localPair();
  const { alice, bob } = pair;
  let owner, client;
  try {
    await Promise.all([alice.start(), bob.start()]);
    owner = await startOperator({ dir: alice.dir });
    const p = panel(owner.url);
    const approval = title => ({ peer: bob.card.id, action: {
      kind: 'handoff', summary: title, nextStep: 'Review it', expectedResult: 'Send an answer',
    } });
    const rules = ['First review', 'Second review', 'Third review'].map(approval);
    for (const rule of rules) await p.action('allow-handoff', rule);
    const issued = await p.action('grant', { confirmation: false, handoff: true });
    client = await connectClient(JSON.parse(await readFile(issued.file, 'utf8')));
    const pending = (await p.action('state')).handoffApprovals;
    assert.deepEqual(pending.map(x => x.action.summary).sort(), rules.map(x => x.action.summary));
    assert.deepEqual(Object.keys(pending[0]).sort(), ['action', 'peer', 'threadId']);
    assert.deepEqual(await p.action('withdraw-handoff', rules[0]), { approved: false, removed: true });
    assert.deepEqual(await p.action('withdraw-handoff', rules[0]), { approved: false, removed: false });
    const file = join(alice.dir, 'withdraw-rule.json');
    await writeFile(file, JSON.stringify(rules[2]), { mode: 0o600 });
    const { stdout } = await promisify(execFile)(process.execPath, [cli, 'withdraw-handoff', '--dir', alice.dir, '--file', file]);
    assert.deepEqual(JSON.parse(stdout), { approved: false, removed: true });
    const send = async (rule, requestKey) => {
      const { kind, ...brief } = rule.action;
      return tool(client, 'request_handoff', { peer: rule.peer, requestKey, ...brief });
    };
    for (const i of [0, 2]) await assert.rejects(send(rules[i], 'review-' + i), /403/);
    assert.deepEqual((await p.action('state')).handoffApprovals.map(x => x.action), [rules[1].action]);
    const sent = await send(rules[1], 'review-1');
    assert.equal(sent.summary, rules[1].action.summary);
    assert.deepEqual((await p.action('state')).handoffApprovals, []);
  } finally {
    await client?.close(); await owner?.close(); await pair.close();
  }
});
