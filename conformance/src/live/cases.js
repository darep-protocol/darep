// Live mode: real HTTP deliveries on loopback, in both directions, between the kit peer and the implementation,
// through fault-injecting proxies. Only core/v2#message (and one unknown type) is used; never work/v2.
//
//   kit peer ──► implProxy ──► implementation inbox      (implementation as receiver)
//   implementation ──► kitProxy ──► kit peer inbox       (implementation as sender)
//
// Pinning is explicit local configuration: the kit gives the implementation its card (identity document plus the
// kitProxy inbox URL) in liveStart, and pins the card the implementation returns. Nothing is discovered.
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { check } from '../report.js';
import { Unsupported } from '../adapter.js';
import { CORE, MESSAGE, REJECTION, TYP, deepEqual, headerOf, payloadOf, referenceVerify } from '../check.js';
import { headerCount, rawRequest } from '../http.js';
import { faultProxy } from './proxy.js';
import { KIT_ADDRESS, startKitPeer } from './peer.js';

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const PROBLEM_MEMBERS = new Set(['type', 'title', 'status', 'code', 'detail', 'record']);
const DAY = 86400_000;
const envelopeOf = bytes => { try { return JSON.parse(payloadOf(bytes.toString('latin1')).toString('utf8')); } catch { return null; } };

async function poll(fn, timeoutMs, everyMs = 200) {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const value = await fn();
    if (value || Date.now() >= end) return value;
    await sleep(everyMs);
  }
}

export async function liveCases(adapter, report, { roles, outDir }) {
  const asReceiver = roles.includes('receiver');
  const asSender = roles.includes('sender');
  if (!asReceiver && !asSender) return;
  const skipAll = reason => {
    for (const role of ['receiver', 'sender'].filter(r => roles.includes(r))) {
      report.add({ id: `live/${role}`, mode: 'live', role, status: 'skip', refs: ['delivery.md', 'https-binding.md'], detail: reason });
    }
  };
  let kit;
  try { kit = await startKitPeer(); } catch (error) { skipAll(error.message); return; }
  const kitProxy = await faultProxy(kit.inbox);
  let implProxy = null;
  try {
    const kitCard = { identity: kit.document, inbox: kitProxy.url };
    let started;
    try { started = await adapter.call('liveStart', { addressHint: 'acct:impl@impl.conformance.test', kitCard }, { timeoutMs: 60_000 }); }
    catch (error) { skipAll(error instanceof Unsupported ? 'the adapter does not support live mode (liveStart)' : error.message); return; }
    const card = started.card;
    const implDoc = card?.identity;
    const implAddress = implDoc?.addresses?.[0];
    const setup = { id: 'live/setup', mode: 'live', role: asReceiver ? 'receiver' : 'sender', refs: ['https-binding.md §1.1, §1.3', 'records.md TA-2'] };
    let ok = false;
    await report.run(setup, async () => {
      check(implDoc && typeof card.inbox === 'string', 'liveStart returned no card {identity, inbox}');
      check(/^http:\/\/(127\.0\.0\.1|localhost|\[::1\])(:\d+)?\//.test(card.inbox), `inbox ${card.inbox} is not a loopback URL`);
      implProxy = await faultProxy(card.inbox);
      try { kit.pin({ identity: implDoc, inbox: implProxy.url }); }
      catch (error) { check(false, `the kit cannot pin the implementation's identity document: ${error.message}`); }
      writeFileSync(join(outDir, 'live-pins.json'), JSON.stringify({
        note: 'Explicit local pins written by the kit for this run (records.md TA-2). Test-only identities.',
        kit: { card: kitCard, forwardsTo: kit.inbox }, implementation: { card: { identity: implDoc, inbox: implProxy.url }, forwardsTo: card.inbox },
      }, null, 2) + '\n');
      ok = true;
      return `implementation ${implAddress}, inbox ${card.inbox} (via proxy ${implProxy.url})`;
    });
    if (!ok) return;
    const ctx = { adapter, report, kit, kitProxy, implProxy, implDoc, implAddress };
    if (asReceiver) await receiverCases(ctx);
    if (asSender) await senderCases(ctx);
    report.notes.push('Live mode pins: see live-pins.json next to this report.');
  } finally {
    await implProxy?.close();
    await kitProxy.close();
    await kit.close();
  }
}

// ---------- the implementation as receiver ----------

async function receiverCases({ adapter, report, kit, kitProxy, implProxy, implDoc, implAddress }) {
  const meta = (id, refs) => ({ id: 'live/receiver/' + id, mode: 'live', role: 'receiver', refs });
  const R = kit.R;
  const message = ({ text = 'Conformance kit message', data = { text }, now = Date.now(), lifetime = 7 * DAY, ...rest } = {}) =>
    R.makeEventRecord({ source: kit.address, to: implAddress, type: MESSAGE, data, now, lifetime,
      grant: { id: 'kit-owner-act', actor: 'owner' }, required: [CORE], ...rest });
  const post = (body, { headers = {}, method = 'POST' } = {}) => rawRequest(implProxy.url, { method, body,
    headers: { 'content-type': 'application/jose', 'darep-recipient': implAddress, ...headers } });
  const verifyReceipt = (text, answered) => {
    const got = referenceVerify(text, { typ: TYP.receipt, mode: 'admission', now: new Date().toISOString(), receiver: kit.address,
      understood: [CORE], answered }, [implDoc]);
    check(got.ok, `receipt fails records.md §8 at the sender: ${got.code} (${got.why})`);
    check(got.record.source === implAddress, `receipt source ${got.record.source} is not the delivery's recipient (delivery.md §7.4)`);
    return got.record;
  };
  const inspect = id => adapter.optional('inspectIncoming', { source: kit.address, id });
  let first = null;

  await report.run(meta('happy-path', ['delivery.md §3, §4', 'https-binding.md §2.2']), async () => {
    const record = message();
    const jws = kit.sign(record);
    const row = kit.queue(jws);
    const { outbox, last } = await kit.deliver(row);
    const exchange = implProxy.log.at(-1);
    check(exchange?.response?.status === 200, `HTTP ${exchange?.response?.status ?? exchange?.response?.error}: ${exchange?.response?.body?.toString().slice(0, 200)}`);
    check((exchange.response.headers['content-type'] ?? '').split(';')[0].trim() === 'application/jose', `content-type ${exchange.response.headers['content-type']}`);
    check(outbox.status === 'delivered', `the reference sender did not accept the receipt: ${last?.result} ${last?.code ?? ''}`);
    const receipt = verifyReceipt(outbox.receipt, jws);
    check(receipt.data.sha256 === R.sha256(payloadOf(jws)), 'receipt digest');
    first = { record, jws, receipt: outbox.receipt };
    const stored = await inspect(record.id);
    if (!stored) return 'stored state not inspected (inspectIncoming unsupported)';
    check(stored.found && stored.recordBytes === jws, 'the record bytes are not stored exactly as received');
    check(stored.receipt === outbox.receipt, 'the issued receipt is not stored byte for byte');
    const applied = await poll(async () => ((await inspect(record.id))?.outcome === 'applied' ? true : null), 5000);
    check(applied, `apply outcome is ${(await inspect(record.id))?.outcome}; expected applied for a valid core/v2#message`);
  });

  await report.run(meta('duplicate-same-bytes', ['delivery.md §6', 'https-binding.md §2.2']), async () => {
    check(first, 'needs the happy-path record');
    const res = await post(first.jws);
    check(res.status === 200, `HTTP ${res.status}`);
    check(res.body.toString('latin1') === first.receipt, 'the duplicate did not get the byte-identical stored receipt');
  });

  await report.run(meta('duplicate-resigned', ['delivery.md §6']), async () => {
    check(first, 'needs the happy-path record');
    const resigned = kit.resign(first.jws);
    check(resigned !== first.jws, 'internal: re-signing produced the same bytes');
    const res = await post(resigned);
    check(res.status === 200, `HTTP ${res.status}`);
    check(res.body.toString('latin1') === first.receipt, 'same payload with a new signature did not get the stored receipt');
    const stored = await inspect(first.record.id);
    if (stored) check(stored.recordBytes === first.jws, 'the first record bytes were replaced by the re-signed copy');
  });

  await report.run(meta('dropped-ack-restart', ['delivery.md §4.1, §6, §7.2', 'https-binding.md §3']), async () => {
    const jws = kit.sign(message({ text: 'Receipt lost on the way back' }));
    const row = kit.queue(jws);
    implProxy.inject({ kind: 'drop-response' });
    const firstTry = await kit.deliver(row);
    const dropped = implProxy.log.at(-1);
    check(dropped.fault === 'drop-response' && dropped.response?.status === 200, `the implementation answered ${dropped.response?.status ?? dropped.response?.error}`);
    check(firstTry.outbox.status === 'queued' && firstTry.last.result === 'transient', 'internal: the kit peer saw the dropped answer');
    const restarted = await adapter.optional('restart', {});
    const res = await kit.deliver(row);
    check(res.outbox.status === 'delivered', `retry after ${restarted ? 'restart' : 'no restart'}: ${res.last?.result} ${res.last?.code ?? ''}`);
    check(res.outbox.receipt === dropped.response.body.toString('latin1'), 'the retry did not get the byte-identical receipt issued before');
    return restarted ? 'implementation restarted between the attempts' : 'restart unsupported: retried without a restart';
  });

  await report.run(meta('id-conflict', ['delivery.md §6', 'https-binding.md §3']), async () => {
    check(first, 'needs the happy-path record');
    const conflicting = kit.sign({ ...first.record, data: { text: 'Same id, different payload' } });
    await expectProblem(await post(conflicting), 'id-conflict', 409);
    const again = await post(first.jws);
    check(again.status === 200 && again.body.toString('latin1') === first.receipt, 'the original delivery changed after the conflict');
  });

  const preStore = [
    ['wrong-recipient-not-in-to', 'wrong-recipient', 403, ['delivery.md §3.1 R12'],
      () => post(kit.sign(message({ to: 'acct:someone-else@kit.conformance.test' })))],
    ['wrong-recipient-header-missing', 'wrong-recipient', 403, ['https-binding.md §2.1', 'delivery.md §3.1 C1'],
      () => rawRequest(implProxy.url, { body: kit.sign(message()), headers: { 'content-type': 'application/jose' } })],
    ['bad-signature', 'bad-signature', 400, ['records.md §8 step 6'], () => {
      const [h, p, s] = kit.sign(message()).split('.');
      const sig = Buffer.from(s, 'base64url');
      sig[0] ^= 0x01;
      return post(`${h}.${p}.${sig.toString('base64url')}`);
    }],
    ['unknown-key', 'unknown-key', 403, ['records.md TA-2, §8 step 5'],
      () => post(kit.sign(message({ source: kit.stranger.address }), R.typs.event, kit.stranger))],
    ['too-large', 'too-large', 413, ['delivery.md §3.4', 'https-binding.md §2.1'], () => post(Buffer.alloc(65_537, 0x61))],
    ['unsupported-media-type', 'unsupported-media-type', 415, ['https-binding.md §2.1'],
      () => post(kit.sign(message()), { headers: { 'content-type': 'text/plain' } })],
    ['method-not-allowed', 'method-not-allowed', 405, ['https-binding.md §3'], () => post(null, { method: 'GET' })],
    ['malformed', 'malformed', 400, ['records.md §8 step 1'], () => post('not-a-compact-jws')],
    ['expired', 'expired', 422, ['records.md §7.2', 'delivery.md §3.1 R13'],
      () => post(kit.sign(message({ now: Date.now() - 10 * DAY, lifetime: 7 * DAY })))],
    ['not-yet-valid', 'not-yet-valid', 425, ['records.md §7.2', 'delivery.md §3.1 R13'],
      () => post(kit.sign(message({ now: Date.now() + 3600_000 })))],
    ['unsupported-extension', 'unsupported-extension', 422, ['records.md §6.2', 'delivery.md §3.1 R14'],
      () => post(kit.sign(message({ required: [CORE, 'https://kit.conformance.test/ext/unimplemented/v1'] })))],
  ];
  for (const [id, code, status, refs, send] of preStore) {
    await report.run(meta('pre-store/' + id, [...refs, 'https-binding.md §2.3']), async () => {
      const before = (await adapter.optional('stats', {}))?.incoming;
      const res = await send();
      await expectProblem(res, code, status);
      const after = (await adapter.optional('stats', {}))?.incoming;
      if (before !== undefined) check(after === before, `a rejected delivery was stored (${before} → ${after})`);
    });
  }

  await report.run(meta('post-store-signed-rejection', ['delivery.md §3, §5.3', 'records.md §4.5, §6.1 core/v2#message']), async () => {
    const record = message({ data: { text: '' } }); // core/v2#message requires non-empty text: stored, acked, then refused
    const jws = kit.sign(record);
    const res = await post(jws);
    check(res.status === 200, `invalid data must not be refused before storage (D6); got HTTP ${res.status} ${res.body.toString().slice(0, 160)}`);
    verifyReceipt(res.body.toString('latin1'), jws);
    const isAnswer = e => { const r = envelopeOf(e.body); return r?.type === REJECTION && r.inReplyTo === record.id; };
    const exchange = await kitProxy.waitFor(isAnswer, 20_000);
    check(exchange, 'no signed rejection record arrived within 20 s (delivery.md §5.3: MUST be emitted for refused)');
    checkCarrier(exchange, kit.address);
    const rejection = exchange.body.toString('latin1');
    const got = referenceVerify(rejection, { typ: TYP.rejection, mode: 'admission', now: new Date().toISOString(), receiver: kit.address,
      understood: [CORE], answered: jws }, [implDoc]);
    check(got.ok, `the rejection record fails records.md §8 (with RC-1): ${got.code} (${got.why})`);
    const r = got.record;
    check(headerOf(rejection).typ === TYP.rejection, 'typ');
    check(r.source === implAddress && deepEqual(r.to, [kit.address]) && r.thread === record.thread, 'source, to or thread');
    check(r.data.code === 'invalid-data', `code ${r.data.code}; expected invalid-data`);
    check(!('grant' in r) && 'expires' in r, 'a rejection has expires and no grant (records.md §4.5)');
    check(exchange.response?.status === 200, `the kit peer did not store it: HTTP ${exchange.response?.status}`);
    await sleep(2000);
    const count = kitProxy.log.filter(e => isAnswer(e)).map(e => envelopeOf(e.body)?.id);
    check(new Set(count).size === 1, `${new Set(count).size} different rejection records for one stored record (at most one allowed)`);
    const stored = await inspect(record.id);
    if (stored) check(stored.outcome === 'refused', `apply outcome ${stored.outcome}; expected refused`);
    return 'invalid-data rejection verified';
  });

  await report.run(meta('unknown-type', ['delivery.md §3.2, §3.3', 'records.md §6.3']), async () => {
    const type = 'https://kit.conformance.test/ext/unimplemented/v1#thing';
    const record = message({ type, data: { anything: true }, required: [] });
    const jws = kit.sign(record);
    const res = await post(jws);
    check(res.status === 200, `an unknown type outside required[] must be stored and acknowledged; got HTTP ${res.status}`);
    verifyReceipt(res.body.toString('latin1'), jws);
    const exchange = await kitProxy.waitFor(e => { const r = envelopeOf(e.body); return r?.type === REJECTION && r.inReplyTo === record.id; }, 3000);
    if (!exchange) return 'no rejection record (MAY): permitted';
    const r = envelopeOf(exchange.body);
    check(r.data?.code === 'unsupported-type', `optional rejection has code ${r.data?.code}; expected unsupported-type`);
    return 'optional unsupported-type rejection emitted';
  });
}

async function expectProblem(res, code, status) {
  const text = res.body.toString('utf8');
  check(res.status === status, `HTTP ${res.status} ${text.slice(0, 200)}; expected ${status} ${code}`);
  check((res.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase() === 'application/problem+json', `content-type ${res.headers['content-type']}`);
  let problem;
  try { problem = JSON.parse(text); } catch { check(false, 'problem body is not JSON'); }
  check(problem.code === code, `problem code ${problem.code}; expected ${code}`);
  check(problem.type === 'https://darep.org/problems/' + code, `problem type ${problem.type}`);
  check(problem.status === status, `problem status ${problem.status}`);
  check(typeof problem.title === 'string', 'problem title');
  check(Object.keys(problem).every(k => PROBLEM_MEMBERS.has(k)), `problem members outside https-binding §2.3: ${Object.keys(problem).join(', ')}`);
  if ('detail' in problem) check(typeof problem.detail === 'string' && [...problem.detail].length <= 1000, 'problem detail');
  if (code === 'method-not-allowed') check(/\bPOST\b/.test(res.headers.allow ?? ''), `Allow header ${res.headers.allow}`);
}

// What a conformant sender's request looks like on the wire (https-binding.md §2.1).
function checkCarrier(e, recipient) {
  check(e.method === 'POST', `method ${e.method}`);
  check((e.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase() === 'application/jose', `content-type ${e.headers['content-type']}`);
  check(headerCount(e.rawHeaders, 'darep-recipient') === 1 && e.headers['darep-recipient'] === recipient, `Darep-Recipient ${e.headers['darep-recipient']}`);
  check(!e.headers.authorization && !e.headers.cookie, 'credentials sent (Authorization or Cookie)');
  check(!e.headers['content-encoding'], `content-encoding ${e.headers['content-encoding']}`);
  check(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(e.body.toString('latin1')), 'body is not exactly a compact JWS');
}

// ---------- the implementation as sender ----------

async function senderCases({ adapter, report, kit, kitProxy, implProxy, implDoc, implAddress }) {
  const meta = (id, refs) => ({ id: 'live/sender/' + id, mode: 'live', role: 'sender', refs });
  const R = kit.R;
  const send = text => adapter.call('send', { to: kit.address, type: MESSAGE, data: { text } });
  // The n-th completed request that carries record `id`.
  const requestFor = (id, n = 1, timeoutMs = 20_000) =>
    poll(() => kitProxy.log.filter(x => x.done && envelopeOf(x.body)?.id === id)[n - 1] ?? null, timeoutMs, 50);
  const outgoing = id => adapter.optional('inspectOutgoing', { id, recipient: kit.address });
  const delivered = async id => poll(async () => { const o = await outgoing(id); return o?.status === 'delivered' ? o : null; }, 10_000);
  let first = null;

  await report.run(meta('happy-path', ['https-binding.md §2.1', 'records.md §4.3, §8', 'delivery.md §7.4']), async () => {
    const { id } = await send('Hello from the implementation');
    const e = await requestFor(id);
    check(e, 'no delivery reached the kit within 20 s');
    checkCarrier(e, kit.address);
    const jws = e.body.toString('latin1');
    const got = referenceVerify(jws, { typ: [TYP.event, TYP.rejection], mode: 'admission', now: new Date().toISOString(),
      receiver: kit.address, understood: [CORE] }, [implDoc]);
    check(got.ok, `the record fails records.md §8: ${got.code} (${got.why})`);
    const r = got.record;
    check(r.type === MESSAGE && deepEqual(r.data, { text: 'Hello from the implementation' }), 'type or data differ from the request');
    check(r.grant && typeof r.grant.id === 'string' && ['owner', 'agent'].includes(r.grant.actor), 'events carry grant {id, actor} (delivery.md §9.3)');
    check(e.response?.status === 200, `the kit peer refused it: HTTP ${e.response?.status} ${e.response?.body?.toString().slice(0, 200)}`);
    first = { id, jws, record: r, receipt: e.response.body.toString('latin1') };
    report.advisory(meta('happy-path#expires-7-days', ['delivery.md §2']), Date.parse(r.expires) - Date.parse(r.time) === 7 * DAY,
      `expires is ${(Date.parse(r.expires) - Date.parse(r.time)) / DAY} days after time (SHOULD be 7)`);
    report.advisory(meta('happy-path#content-length', ['https-binding.md §2.1']), headerCount(e.rawHeaders, 'content-length') === 1,
      'the sender SHOULD send Content-Length');
    const state = await delivered(id);
    if (state === null && !(await outgoing(id))) return 'delivery state not inspected (inspectOutgoing unsupported)';
    check(state, `the implementation did not mark the delivery delivered: ${(await outgoing(id))?.status}`);
    check(state.receipt === first.receipt, 'the stored receipt differs from the bytes received');
  });

  await report.run(meta('dropped-ack-restart', ['delivery.md §6, §7.1, §7.2', 'https-binding.md §3']), async () => {
    kitProxy.inject({ kind: 'drop-response' });
    const { id } = await send('Receipt lost, then a restart');
    const e1 = await requestFor(id);
    check(e1, 'no delivery reached the kit within 20 s');
    check(e1.response?.status === 200, `the kit peer refused it: HTTP ${e1.response?.status}`);
    const restarted = await adapter.optional('restart', {});
    const e2 = await requestFor(id, 2, 45_000);
    check(e2, 'no retry within 45 s after the answer was lost' + (restarted ? ' and the implementation restarted' : ''));
    check(e2.body.equals(e1.body), 'the retry did not send the same record bytes (delivery.md §7.1)');
    check(e2.at - e1.at >= 1000, `retried after ${e2.at - e1.at} ms; the first backoff delay is at least 1 s`);
    check(e2.response?.status === 200 && e2.response.body.equals(e1.response.body), 'internal: the kit peer did not replay its receipt');
    const state = await delivered(id);
    if (state === null && !(await outgoing(id))) return 'delivery state not inspected';
    check(state, `not delivered after the retry: ${(await outgoing(id))?.status}`);
    check(state.receipt === e2.response.body.toString('latin1'), 'stored receipt differs');
    return restarted ? 'restarted between the attempts' : 'restart unsupported: no restart';
  });

  await report.run(meta('transient-retry-after', ['delivery.md §7.2', 'https-binding.md §2.3, §3']), async () => {
    kitProxy.inject({ kind: 'respond', status: 503, headers: { 'content-type': 'application/problem+json', 'retry-after': '2' },
      body: JSON.stringify({ type: 'https://darep.org/problems/unavailable', title: 'Unavailable', status: 503, code: 'unavailable' }) });
    const { id } = await send('Try again later');
    const e1 = await requestFor(id);
    check(e1, 'no delivery reached the kit within 20 s');
    const e2 = await requestFor(id, 2, 30_000);
    check(e2, 'no retry within 30 s after a transient 503');
    check(e2.body.equals(e1.body), 'the retry did not send the same record bytes');
    check(e2.at - e1.at >= 1950, `retried ${e2.at - e1.at} ms after Retry-After: 2`);
    const state = await delivered(id);
    if (state || (await outgoing(id))) check(state, 'not delivered after the retry');
  });

  await report.run(meta('permanent-rejection', ['delivery.md §7.2, §7.3, §9.2']), async () => {
    const body = JSON.stringify({ type: 'https://darep.org/problems/unknown-key', title: 'Unknown key', status: 403, code: 'unknown-key' });
    kitProxy.inject({ kind: 'respond', status: 403, headers: { 'content-type': 'application/problem+json' }, body });
    const { id } = await send('This one is refused');
    const e1 = await requestFor(id);
    check(e1, 'no delivery reached the kit within 20 s');
    await sleep(4000);
    const n = kitProxy.log.filter(x => envelopeOf(x.body)?.id === id).length;
    check(n === 1, `${n} attempts after a permanent rejection; expected none after the first`);
    const state = await outgoing(id);
    if (!state) return 'delivery state not inspected';
    check(state.status === 'failed', `delivery is ${state.status}; expected failed`);
    const kept = state.attempts?.at(-1);
    check(kept?.status === 403 && kept?.body === body, 'the status and problem body were not kept as evidence (delivery.md §9.2)');
  });

  await report.run(meta('receipt-mismatch', ['delivery.md §7.2, §7.4', 'records.md RC-1']), async () => {
    check(first, 'needs the happy-path receipt');
    // A validly signed receipt from the kit, but for another record: never proof of delivery.
    kitProxy.inject({ kind: 'replace-response', status: 200, headers: { 'content-type': 'application/jose' }, body: first.receipt });
    const { id } = await send('Wrong receipt first');
    const e1 = await requestFor(id);
    check(e1, 'no delivery reached the kit within 20 s');
    await sleep(300);
    const mid = await outgoing(id);
    if (mid) check(mid.status !== 'delivered', 'a receipt for another record was accepted as delivery');
    const e2 = await requestFor(id, 2, 30_000);
    check(e2, 'no retry within 30 s after a mismatched receipt');
    check(e2.body.equals(e1.body), 'the retry did not send the same record bytes');
    const state = await delivered(id);
    if (!state && !(await outgoing(id))) return 'delivery state not inspected';
    check(state, 'not delivered after the correct receipt');
    check(state.receipt === e2.response.body.toString('latin1'), 'stored the wrong receipt');
    check(state.attempts?.some(a => a.body === first.receipt), 'the mismatched receipt was not kept as evidence (delivery.md §7.4, §9.2)');
  });

  await report.run(meta('receives-rejection-record', ['delivery.md §3.3, §7.5', 'records.md §4.5']), async () => {
    check(first, 'needs the happy-path record');
    const rejection = R.makeEventRecord({ source: kit.address, to: implAddress, type: REJECTION, thread: first.record.thread,
      inReplyTo: first.record.id, data: { code: 'policy-denied' }, required: [] });
    delete rejection.grant;
    const jws = kit.sign(rejection, R.typs.rejection);
    const res = await rawRequest(implProxy.url, { body: jws, headers: { 'content-type': 'application/jose', 'darep-recipient': implAddress } });
    check(res.status === 200, `a rejection record must be stored and acknowledged; got HTTP ${res.status} ${res.body.toString().slice(0, 160)}`);
    const receipt = referenceVerify(res.body.toString('latin1'), { typ: TYP.receipt, mode: 'admission', now: new Date().toISOString(),
      receiver: kit.address, understood: [CORE], answered: jws }, [implDoc]);
    check(receipt.ok, `receipt for the rejection record fails: ${receipt.code} (${receipt.why})`);
    const echoed = await kitProxy.waitFor(e => envelopeOf(e.body)?.inReplyTo === rejection.id, 3000);
    check(!echoed, 'the implementation answered a rejection record with a rejection record (delivery.md §3.3)');
    const refusal = await poll(async () => (await outgoing(first.id))?.refusal ?? null, 5000);
    if (refusal === null) return 'refusal not exposed by the adapter (inspectOutgoing.refusal)';
    check(refusal.code === 'policy-denied', `recorded refusal ${refusal.code}`);
    check((await outgoing(first.id)).status === 'delivered', 'the delivery must stay delivered (delivery.md §7.5)');
  });
}
