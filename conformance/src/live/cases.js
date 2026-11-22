// Live mode: real HTTP deliveries on loopback, in both directions, between the kit peer and the implementation,
// through fault-injecting proxies. Only core/v2#message (and one unknown type) is used; never work/v2.
//
//   kit peer ──► implProxy ──► implementation inbox      (implementation as receiver)
//   implementation ──► kitProxy ──► kit peer inbox       (implementation as sender)
//
// Pinning is explicit local configuration: the kit gives the implementation its card (identity document plus the
// kitProxy inbox URL) in liveStart, and pins the card the implementation returns. Nothing is discovered.
//
// Waiting: the spec sets minimum delays (first retry at least 1 s, Retry-After) and allows eventual application, but
// no maximum. The kit waits up to `patience` seconds for something to happen; "not observed" means not observed within
// that time, and the failure says so.
import { randomUUID } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { check } from '../report.js';
import { Unsupported } from '../adapter.js';
import { CORE, MESSAGE, REJECTION, TYP, deepEqual, headerOf, payloadOf, referenceVerify } from '../check.js';
import { headerCount, rawRequest } from '../http.js';
import { checkProblem } from '../problem.js';
import { faultProxy } from './proxy.js';
import { startKitPeer } from './peer.js';

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const DAY = 86400_000;
const parseRecord = bytes => { try { return JSON.parse(payloadOf(bytes.toString('latin1')).toString('utf8')); } catch { return null; } };
const nowIso = () => new Date().toISOString();

async function poll(fn, timeoutMs, everyMs = 200) {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const value = await fn();
    if (value || Date.now() >= end) return value;
    await sleep(everyMs);
  }
}

export async function liveCases(adapter, report, { roles, outDir, patience = 120 }) {
  const asReceiver = roles.includes('receiver');
  const asSender = roles.includes('sender');
  if (!asReceiver && !asSender) return;
  const wait = patience * 1000;
  // The kit's own peer must start; if it cannot, the run is a setup error, not a skip.
  const kit = await startKitPeer();
  const kitProxy = await faultProxy(kit.inbox, { parse: parseRecord });
  let implProxy = null;
  try {
    const kitCard = { identity: kit.document, inbox: kitProxy.url };
    const setup = { id: 'live/setup', mode: 'live', role: asReceiver ? 'receiver' : 'sender', refs: ['https-binding.md §1.1, §1.3', 'records.md TA-2'] };
    let started;
    try { started = await adapter.call('liveStart', { addressHint: 'acct:impl@impl.conformance.test', kitCard }, { timeoutMs: 60_000 }); }
    catch (error) {
      if (error instanceof Unsupported) {
        for (const role of ['receiver', 'sender'].filter(r => roles.includes(r))) {
          report.add({ id: `live/${role}`, mode: 'live', role, status: 'skip', refs: ['delivery.md', 'https-binding.md'], detail: 'the adapter does not support live mode (liveStart)' });
        }
      } else report.add({ ...setup, status: 'fail', detail: `liveStart failed: ${error.message}` });
      return;
    }
    const card = started.card;
    const implDoc = card?.identity;
    const implAddress = implDoc?.addresses?.[0];
    let ok = false;
    await report.run(setup, async () => {
      check(implDoc && typeof card.inbox === 'string', 'liveStart returned no card {identity, inbox}');
      check(/^http:\/\/(127\.0\.0\.1|localhost|\[::1\])(:\d+)?\//.test(card.inbox), `inbox ${card.inbox} is not a loopback URL`);
      implProxy = await faultProxy(card.inbox, { parse: parseRecord });
      try { kit.pin({ identity: implDoc, inbox: implProxy.url }); }
      catch (error) { check(false, `the kit peer cannot pin the implementation's identity document: ${error.message}`); }
      writeFileSync(join(outDir, 'live-pins.json'), JSON.stringify({
        note: 'Explicit local pins written by the kit for this run (records.md TA-2). Test-only identities.',
        kit: { card: kitCard, forwardsTo: kit.inbox }, implementation: { card: { identity: implDoc, inbox: implProxy.url }, forwardsTo: card.inbox },
      }, null, 2) + '\n');
      ok = true;
      return `implementation ${implAddress}, inbox ${card.inbox} (via proxy ${implProxy.url})`;
    });
    if (!ok) return;
    // A restarted implementation may come back on another loopback port; the kit's pin points at the proxy, so only
    // the proxy's target moves.
    const restart = async () => {
      const out = await adapter.optional('restart', {});
      if (out?.inbox) implProxy.target = out.inbox;
      return out;
    };
    const ctx = { adapter, report, kit, kitProxy, implProxy, implDoc, implAddress, wait, patience, restart };
    if (asReceiver) await receiverCases(ctx);
    if (asSender) await senderCases(ctx);
    report.notes.push(`Live mode waited up to ${patience} s for each expected event (--patience). Pins: live-pins.json.`);
  } finally {
    await implProxy?.close();
    await kitProxy.close();
    await kit.close();
  }
}

// Verify a signed rejection record the implementation sent to the kit, and the request that carried it.
function checkRejectionExchange(exchange, { answered, implDoc, implAddress, kit, code }) {
  checkCarrier(exchange, kit.address);
  const bytes = exchange.body.toString('latin1');
  const got = referenceVerify(bytes, { typ: TYP.rejection, mode: 'admission', now: nowIso(), receiver: kit.address,
    understood: [CORE], answered }, [implDoc]);
  check(got.ok, `the rejection record fails records.md §8 (with RC-1): ${got.code} (${got.why})`);
  const r = got.record;
  const R = parseRecord(Buffer.from(answered, 'latin1'));
  check(headerOf(bytes).typ === TYP.rejection && r.type === REJECTION, 'typ or type');
  check(r.source === implAddress && deepEqual(r.to, [kit.address]) && r.thread === R.thread && r.inReplyTo === R.id, 'source, to, thread or inReplyTo');
  check(!('grant' in r) && 'expires' in r, 'a rejection has expires and no grant (records.md §4.5)');
  if (code) check(r.data.code === code, `code ${r.data.code}; expected ${code}`);
  check(exchange.response?.status === 200, `the kit peer did not store it: HTTP ${exchange.response?.status} ${exchange.response?.body?.toString().slice(0, 160)}`);
  return r;
}

// What a conformant sender's request looks like on the wire (https-binding.md §2.1).
function checkCarrier(e, recipient) {
  check(e.method === 'POST', `method ${e.method}`);
  check((e.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase() === 'application/jose', `content-type ${e.headers['content-type']}`);
  check(headerCount(e.rawHeaders, 'darep-recipient') === 1 && e.headers['darep-recipient'] === recipient, `Darep-Recipient ${e.headers['darep-recipient']}`);
  check(!e.headers.authorization && !e.headers.cookie, 'credentials sent (Authorization or Cookie)');
  // "MUST NOT apply a Content-Encoding": an explicit `identity` applies none, so it is tolerated (see the report notes).
  check(!e.headers['content-encoding'] || e.headers['content-encoding'].trim().toLowerCase() === 'identity', `content-encoding ${e.headers['content-encoding']}`);
  check(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(e.body.toString('latin1')), 'body is not exactly a compact JWS');
}

// ---------- the implementation as receiver ----------

async function receiverCases({ adapter, report, kit, kitProxy, implProxy, implDoc, implAddress, wait, patience, restart }) {
  const meta = (id, refs) => ({ id: 'live/receiver/' + id, mode: 'live', role: 'receiver', refs });
  const R = kit.R;
  const message = ({ text = 'Conformance kit message', data = { text }, now = Date.now(), lifetime = 7 * DAY, ...rest } = {}) =>
    R.makeEventRecord({ source: kit.address, to: implAddress, type: MESSAGE, data, now, lifetime,
      grant: { id: 'kit-owner-act', actor: 'owner' }, required: [CORE], ...rest });
  const post = (body, { headers = {}, method = 'POST' } = {}) => rawRequest(implProxy.url, { method, body,
    headers: { 'content-type': 'application/jose', 'darep-recipient': implAddress, ...headers } });
  const verifyReceipt = (text, answered) => {
    const got = referenceVerify(text, { typ: TYP.receipt, mode: 'admission', now: nowIso(), receiver: kit.address,
      understood: [CORE], answered }, [implDoc]);
    check(got.ok, `receipt fails records.md §8 at the sender: ${got.code} (${got.why})`);
    check(got.record.source === implAddress, `receipt source ${got.record.source} is not the delivery's recipient (delivery.md §7.4)`);
    check(Date.parse(got.record.time) >= Date.parse(got.record.data.storedAt), 'receipt time precedes data.storedAt (delivery.md §4.1, issuer obligation)');
    return got.record;
  };
  const inspect = id => adapter.optional('inspectIncoming', { source: kit.address, id });
  const answersTo = id => e => e.done && e.record?.type === REJECTION && e.record.inReplyTo === id;
  let first = null;

  await report.run(meta('happy-path', ['delivery.md §3, §3.3, §4', 'https-binding.md §2.2']), async () => {
    const record = message();
    const jws = kit.sign(record);
    const row = kit.queue(jws);
    const { outbox, last } = await kit.deliver(row);
    const exchange = implProxy.log.findLast(e => e.record?.id === record.id);
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
    const applied = await poll(async () => ((await inspect(record.id))?.outcome === 'applied' ? true : null), wait);
    check(applied, `apply outcome is ${(await inspect(record.id))?.outcome} after ${patience} s; expected applied for a valid core/v2#message`);
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
    const res = await post(resigned);
    check(res.status === 200, `HTTP ${res.status}`);
    check(res.body.toString('latin1') === first.receipt, 'same payload with a new signature did not get the stored receipt');
    const stored = await inspect(first.record.id);
    if (stored) check(stored.recordBytes === first.jws, 'the first record bytes were replaced by the re-signed copy');
  });

  await report.run(meta('dropped-ack-restart', ['delivery.md §4.1, §6, §7.2', 'https-binding.md §3']), async () => {
    const record = message({ text: 'Receipt lost on the way back' });
    const jws = kit.sign(record);
    const row = kit.queue(jws);
    implProxy.inject({ kind: 'drop-response', match: e => e.record?.id === record.id });
    const firstTry = await kit.deliver(row);
    const dropped = implProxy.log.findLast(e => e.record?.id === record.id);
    check(dropped.fault === 'drop-response' && dropped.response?.status === 200, `the implementation answered ${dropped.response?.status ?? dropped.response?.error}`);
    check(firstTry.outbox.status === 'queued' && firstTry.last.result === 'transient', 'internal: the kit peer saw the dropped answer');
    const restarted = await restart();
    const res = await kit.deliver(row);
    check(res.outbox.status === 'delivered', `retry after ${restarted ? 'restart' : 'no restart'}: ${res.last?.result} ${res.last?.code ?? ''}`);
    check(res.outbox.receipt === dropped.response.body.toString('latin1'), 'the retry did not get the byte-identical receipt issued before');
    return restarted ? 'implementation restarted between the attempts' : 'restart unsupported: retried without a restart';
  });

  await report.run(meta('id-conflict', ['delivery.md §6', 'https-binding.md §2.3, §3']), async () => {
    check(first, 'needs the happy-path record');
    const conflicting = kit.sign({ ...first.record, data: { text: 'Same id, different payload' } });
    checkProblem(await post(conflicting), { code: 'id-conflict', status: 409, recordId: first.record.id });
    const again = await post(first.jws);
    check(again.status === 200 && again.body.toString('latin1') === first.receipt, 'the original delivery changed after the conflict');
  });

  const preStore = [
    ['wrong-recipient-not-in-to', 'wrong-recipient', 403, ['delivery.md §3.1 R12'],
      () => message({ to: 'acct:someone-else@kit.conformance.test' }), r => post(kit.sign(r))],
    ['wrong-recipient-header-missing', 'wrong-recipient', 403, ['https-binding.md §2.1', 'delivery.md §3.1 C1'],
      () => message(), r => rawRequest(implProxy.url, { body: kit.sign(r), headers: { 'content-type': 'application/jose' } })],
    ['bad-signature', 'bad-signature', 400, ['records.md §8 step 6'], () => message(), r => {
      const [h, p, s] = kit.sign(r).split('.');
      const sig = Buffer.from(s, 'base64url');
      sig[0] ^= 0x01;
      return post(`${h}.${p}.${sig.toString('base64url')}`);
    }],
    ['unknown-key', 'unknown-key', 403, ['records.md TA-2, §8 step 5'],
      () => message({ source: kit.stranger.address }), r => post(kit.sign(r, R.typs.event, kit.stranger))],
    ['too-large', 'too-large', 413, ['delivery.md §3.4', 'https-binding.md §2.1'], () => null, () => post(Buffer.alloc(65_537, 0x61))],
    ['unsupported-media-type', 'unsupported-media-type', 415, ['https-binding.md §2.1'],
      () => message(), r => post(kit.sign(r), { headers: { 'content-type': 'text/plain' } })],
    ['method-not-allowed', 'method-not-allowed', 405, ['https-binding.md §3'], () => null, () => post(null, { method: 'GET' })],
    ['malformed', 'malformed', 400, ['records.md §8 step 1'], () => null, () => post('not-a-compact-jws')],
    ['expired', 'expired', 422, ['records.md §7.2', 'delivery.md §3.1 R13'],
      () => message({ now: Date.now() - 10 * DAY, lifetime: 7 * DAY }), r => post(kit.sign(r))],
    ['not-yet-valid', 'not-yet-valid', 425, ['records.md §7.2', 'delivery.md §3.1 R13'],
      () => message({ now: Date.now() + 3600_000 }), r => post(kit.sign(r))],
    ['unsupported-extension', 'unsupported-extension', 422, ['records.md §6.2', 'delivery.md §3.1 R14'],
      () => message({ required: [CORE, 'https://kit.conformance.test/ext/unimplemented/v1'] }), r => post(kit.sign(r))],
  ];
  for (const [id, code, status, refs, make, send] of preStore) {
    await report.run(meta('pre-store/' + id, [...refs, 'https-binding.md §2.3']), async () => {
      const record = make();
      const before = (await adapter.optional('stats', {}))?.incoming;
      checkProblem(await send(record), { code, status, recordId: record?.id ?? null });
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
    const exchange = await poll(() => kitProxy.log.find(answersTo(record.id)) ?? null, wait, 100);
    check(exchange, `no signed rejection record arrived within ${patience} s (delivery.md §5.3: MUST be emitted for refused)`);
    checkRejectionExchange(exchange, { answered: jws, implDoc, implAddress, kit, code: 'invalid-data' });
    await sleep(2000);
    const ids = new Set(kitProxy.log.filter(answersTo(record.id)).map(e => e.record.id));
    check(ids.size === 1, `${ids.size} different rejection records for one stored record (at most one allowed)`);
    const stored = await inspect(record.id);
    if (stored) check(stored.outcome === 'refused', `apply outcome ${stored.outcome}; expected refused`);
  });

  await report.run(meta('unknown-type', ['delivery.md §3.2, §3.3, §5.3', 'records.md §6.3']), async () => {
    const record = message({ type: 'https://kit.conformance.test/ext/unimplemented/v1#thing', data: { anything: true }, required: [] });
    const jws = kit.sign(record);
    const res = await post(jws);
    check(res.status === 200, `an unknown type outside required[] must be stored and acknowledged; got HTTP ${res.status}`);
    verifyReceipt(res.body.toString('latin1'), jws);
    const stored = await poll(async () => { const s = await inspect(record.id); return s?.outcome ? s : null; }, 5000);
    if (stored) check(['unsupported', 'pending'].includes(stored.outcome), `apply outcome ${stored.outcome}; expected unsupported`);
    const exchange = await poll(() => kitProxy.log.find(answersTo(record.id)) ?? null, 3000, 100);
    if (!exchange) return 'no rejection record (MAY): permitted';
    // Optional, but if it is sent it must be a correct signed rejection record (records.md §4.5, §8).
    checkRejectionExchange(exchange, { answered: jws, implDoc, implAddress, kit, code: 'unsupported-type' });
    return 'optional unsupported-type rejection emitted and verified';
  });
}

// ---------- the implementation as sender ----------

async function senderCases({ adapter, report, kit, kitProxy, implProxy, implDoc, implAddress, wait, patience, restart }) {
  const meta = (id, refs) => ({ id: 'live/sender/' + id, mode: 'live', role: 'sender', refs });
  const R = kit.R;
  // Every case sends a unique text, so faults can target its request before the adapter has returned the id.
  const unique = label => `${label} (${randomUUID().slice(0, 8)})`;
  const isText = text => e => e.record?.type === MESSAGE && e.record?.data?.text === text;
  const send = text => adapter.call('send', { to: kit.address, type: MESSAGE, data: { text } });
  const requestFor = (id, n = 1, timeoutMs = wait) =>
    poll(() => kitProxy.log.filter(x => x.done && x.record?.id === id)[n - 1] ?? null, timeoutMs, 50);
  const outgoing = id => adapter.optional('inspectOutgoing', { id, recipient: kit.address });
  const supportsOutgoing = async id => (await outgoing(id)) !== null;
  const delivered = id => poll(async () => { const o = await outgoing(id); return o?.status === 'delivered' ? o : null; }, wait);
  let first = null;

  await report.run(meta('happy-path', ['https-binding.md §2.1', 'records.md §4.3, §8', 'delivery.md §7.4, §9.3']), async () => {
    const text = unique('Hello from the implementation');
    const { id } = await send(text);
    const e = await requestFor(id);
    check(e, `no delivery reached the kit within ${patience} s`);
    checkCarrier(e, kit.address);
    const jws = e.body.toString('latin1');
    const got = referenceVerify(jws, { typ: TYP.event, mode: 'admission', now: nowIso(), receiver: kit.address, understood: [CORE] }, [implDoc]);
    check(got.ok, `the record fails records.md §8: ${got.code} (${got.why})`);
    const r = got.record;
    check(r.source === implAddress && r.type === MESSAGE && deepEqual(r.data, { text }), 'source, type or data differ from the request');
    check(r.grant && typeof r.grant.id === 'string' && ['owner', 'agent'].includes(r.grant.actor), 'events carry grant {id, actor} (delivery.md §9.3)');
    check(e.response?.status === 200, `the kit peer refused it: HTTP ${e.response?.status} ${e.response?.body?.toString().slice(0, 200)}`);
    first = { id, jws, record: r, receipt: e.response.body.toString('latin1') };
    report.advisory(meta('happy-path#expires-7-days', ['delivery.md §2']), Date.parse(r.expires) - Date.parse(r.time) === 7 * DAY,
      `expires is ${(Date.parse(r.expires) - Date.parse(r.time)) / DAY} days after time (SHOULD be 7)`);
    report.advisory(meta('happy-path#content-length', ['https-binding.md §2.1']), headerCount(e.rawHeaders, 'content-length') === 1,
      'the sender SHOULD send Content-Length');
    if (!(await supportsOutgoing(id))) return 'delivery state not inspected (inspectOutgoing unsupported)';
    const state = await delivered(id);
    check(state, `the implementation did not mark the delivery delivered: ${(await outgoing(id))?.status}`);
    check(state.receipt === first.receipt, 'the stored receipt differs from the bytes received');
  });

  await report.run(meta('dropped-ack-restart', ['delivery.md §6, §7.1, §7.2', 'https-binding.md §3']), async () => {
    const text = unique('Receipt lost, then a restart');
    kitProxy.inject({ kind: 'drop-response', match: isText(text) });
    const { id } = await send(text);
    const e1 = await requestFor(id);
    check(e1, `no delivery reached the kit within ${patience} s`);
    check(e1.fault === 'drop-response' && e1.response?.status === 200, `the kit peer refused it: HTTP ${e1.response?.status}`);
    // Restart only once the implementation has recorded the failed attempt (if the adapter can show it).
    if (await supportsOutgoing(id)) await poll(async () => ((await outgoing(id))?.attempts?.length ? true : null), wait);
    const restarted = await restart();
    const e2 = await requestFor(id, 2);
    check(e2, `no retry within ${patience} s after the answer was lost` + (restarted ? ' and the implementation restarted' : ''));
    check(e2.body.equals(e1.body), 'the retry did not send the same record bytes (delivery.md §7.1)');
    check(e2.at - e1.respondedAt >= 1000, `retried ${e2.at - e1.respondedAt} ms after the failed attempt; the first backoff delay is at least 1 s`);
    check(e2.response?.status === 200 && e2.response.body.equals(e1.response.body), 'internal: the kit peer did not replay its receipt');
    if (!(await supportsOutgoing(id))) return 'delivery state not inspected';
    const state = await delivered(id);
    check(state, `not delivered after the retry: ${(await outgoing(id))?.status}`);
    check(state.receipt === e2.response.body.toString('latin1'), 'stored receipt differs');
    return restarted ? 'restarted between the attempts' : 'restart unsupported: no restart';
  });

  await report.run(meta('transient-retry-after', ['delivery.md §7.2', 'https-binding.md §2.3, §3']), async () => {
    const text = unique('Try again later');
    kitProxy.inject({ kind: 'respond', match: isText(text), status: 503, headers: { 'content-type': 'application/problem+json', 'retry-after': '2' },
      body: JSON.stringify({ type: 'https://darep.org/problems/unavailable', title: 'Unavailable', status: 503, code: 'unavailable' }) });
    const { id } = await send(text);
    const e1 = await requestFor(id);
    check(e1, `no delivery reached the kit within ${patience} s`);
    const e2 = await requestFor(id, 2);
    check(e2, `no retry within ${patience} s after a transient 503`);
    check(e2.body.equals(e1.body), 'the retry did not send the same record bytes');
    // Measured from when the 503 was sent to when the retry arrived, both on the kit's clock.
    check(e2.at - e1.respondedAt >= 2000, `retried ${e2.at - e1.respondedAt} ms after Retry-After: 2 was sent`);
    if (await supportsOutgoing(id)) check(await delivered(id), 'not delivered after the retry');
  });

  await report.run(meta('permanent-rejection', ['delivery.md §7.2, §7.3, §9.2']), async () => {
    const text = unique('This one is refused');
    const body = JSON.stringify({ type: 'https://darep.org/problems/unknown-key', title: 'Unknown key', status: 403, code: 'unknown-key' });
    kitProxy.inject({ kind: 'respond', match: isText(text), status: 403, headers: { 'content-type': 'application/problem+json' }, body });
    const { id } = await send(text);
    const e1 = await requestFor(id);
    check(e1, `no delivery reached the kit within ${patience} s`);
    await sleep(4000);
    const n = kitProxy.log.filter(x => x.record?.id === id).length;
    check(n === 1, `${n} attempts after a permanent rejection; expected none after the first`);
    const state = await outgoing(id);
    if (!state) return 'delivery state not inspected; observed no further attempt for 4 s';
    check(state.status === 'failed', `delivery is ${state.status}; expected failed`);
    const kept = state.attempts?.at(-1);
    check(kept?.status === 403 && kept?.body === body, 'the status and problem body were not kept as evidence (delivery.md §9.2)');
  });

  await report.run(meta('receipt-mismatch', ['delivery.md §7.2, §7.4, §9.2', 'records.md RC-1']), async () => {
    check(first, 'needs the happy-path receipt');
    const text = unique('Wrong receipt first');
    let release;
    // A validly signed receipt from the kit, but for another record: never proof of delivery. The retry is held at
    // the proxy until the kit has looked at the delivery state, so the check cannot race the correct receipt.
    kitProxy.inject({ kind: 'replace-response', match: isText(text), status: 200, headers: { 'content-type': 'application/jose' }, body: first.receipt },
      { kind: 'hold', match: isText(text), until: new Promise(resolve => { release = resolve; }) });
    try {
      const { id } = await send(text);
      const e1 = await requestFor(id);
      check(e1, `no delivery reached the kit within ${patience} s`);
      if (await supportsOutgoing(id)) {
        const recorded = await poll(async () => ((await outgoing(id))?.attempts?.length ? await outgoing(id) : null), wait);
        check(recorded, 'the attempt with the mismatched receipt was not recorded');
        check(recorded.status !== 'delivered', 'a receipt for another record was accepted as delivery');
        check(recorded.attempts.some(a => a.body === first.receipt), 'the mismatched receipt was not kept as evidence (delivery.md §7.4, §9.2)');
      }
      release();
      const e2 = await requestFor(id, 2);
      check(e2, `no retry within ${patience} s after a mismatched receipt`);
      check(e2.body.equals(e1.body), 'the retry did not send the same record bytes');
      if (!(await supportsOutgoing(id))) return 'delivery state not inspected';
      const state = await delivered(id);
      check(state, 'not delivered after the correct receipt');
      check(state.receipt === e2.response.body.toString('latin1'), 'stored the wrong receipt');
    } finally { release?.(); }
  });

  await report.run(meta('receives-rejection-record', ['delivery.md §3.3, §7.5', 'records.md §4.5']), async () => {
    check(first, 'needs the happy-path record');
    const rejection = R.makeEventRecord({ source: kit.address, to: implAddress, type: REJECTION, thread: first.record.thread,
      inReplyTo: first.record.id, data: { code: 'policy-denied' }, required: [] });
    delete rejection.grant;
    const jws = kit.sign(rejection, R.typs.rejection);
    const res = await rawRequest(implProxy.url, { body: jws, headers: { 'content-type': 'application/jose', 'darep-recipient': implAddress } });
    check(res.status === 200, `a rejection record must be stored and acknowledged; got HTTP ${res.status} ${res.body.toString().slice(0, 160)}`);
    const receipt = referenceVerify(res.body.toString('latin1'), { typ: TYP.receipt, mode: 'admission', now: nowIso(),
      receiver: kit.address, understood: [CORE], answered: jws }, [implDoc]);
    check(receipt.ok, `receipt for the rejection record fails: ${receipt.code} (${receipt.why})`);
    await sleep(3000);
    check(!kitProxy.log.some(e => e.record?.inReplyTo === rejection.id), 'the implementation answered a rejection record with a rejection record (delivery.md §3.3)');
    const resent = () => kitProxy.log.filter(e => e.record?.id === first.id).length > 1;
    check(!resent(), 'the refused record was sent again (delivery.md §7.5: MUST NOT resend)');
    if (!(await supportsOutgoing(first.id))) return 'refusal not inspected (inspectOutgoing unsupported); observed no resend for 3 s';
    // delivery.md §7.5: the sender MUST record the refusal against its record; the delivery stays delivered.
    const refusal = await poll(async () => (await outgoing(first.id))?.refusal ?? null, wait);
    check(refusal, `no refusal recorded against the refused record within ${patience} s (inspectOutgoing.refusal)`);
    check(refusal.code === 'policy-denied', `recorded refusal ${refusal.code}`);
    check((await outgoing(first.id)).status === 'delivered', 'the delivery must stay delivered (delivery.md §7.5)');
    check(!resent(), 'the refused record was sent again (delivery.md §7.5: MUST NOT resend)');
  });
}
