// Offline mode, receiver and sender roles: the delivery vectors, driven through the adapter with an injected clock.
// The kit talks to the receiver's loopback inbox over real HTTP, and plays the receiving endpoint for the sender.
import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { loadJson, vectorsRoot } from '../repo.js';
import { check } from '../report.js';
import { TYP, dotted, deepEqual, payloadOf, referenceVerify } from '../check.js';
import { rawRequest, scriptedServer } from '../http.js';
import { checkProblem } from '../problem.js';

const files = role => readdirSync(join(vectorsRoot, 'delivery', role)).filter(f => f.endsWith('.json')).sort();
const instant = t => Date.parse(t);
const envelopeOf = jws => JSON.parse(payloadOf(jws).toString('utf8'));

function setup(v) {
  const ids = loadJson('delivery', 'identities.json');
  const keys = loadJson('delivery', 'test-keys.json').keys;
  const party = v.receiver ?? v.sender;
  const docFor = address => ids.documents.find(d => d.addresses.includes(address));
  return {
    party, document: docFor(party.address),
    params: inboxFor => ({
      address: party.address, document: docFor(party.address),
      privateKeys: Object.fromEntries(party.signingKeys.map(kid => [kid, keys[kid]])),
      pins: party.pinned.map(a => ({ identity: docFor(a), inbox: inboxFor(a, ids.inboxes[a]) })),
      extensions: party.extensions ?? ['https://darep.org/ext/core/v2'],
      jitter: v.retryProfile?.jitterPercent !== 0,
      now: v.steps?.[0]?.at ?? '2026-11-20T10:00:30Z',
    }),
  };
}

export async function deliveryCases(adapter, report, { roles, experimental }) {
  for (const role of ['receiver', 'sender']) {
    if (!roles.includes(role)) continue;
    for (const file of files(role)) {
      const v = loadJson('delivery', role, file);
      const subset = v.conformance ? 'experimental' : 'core';
      const meta = { id: `delivery/${role}/${file.slice(0, -5)}`, mode: 'offline', role, subset, refs: v.spec ?? [],
        // The work/v2 apply rules (head, turn, transitions) are not normatively published (D8 amendment); only these vectors state them.
        ...(subset === 'experimental' ? { basis: 'vector-only', basisNote: `${v.conformance}: the work/v2 lifecycle rules it checks are not published normative text (D8 amendment)` } : {}) };
      if (subset === 'experimental' && !experimental) {
        report.add({ ...meta, status: 'skip', detail: 'experimental work/v2 scenario; run with --experimental to include it' });
        continue;
      }
      const advisories = [];
      await report.run(meta, () => (role === 'receiver' ? receiver(adapter, v, file, advisories) : sender(adapter, v, advisories)));
      for (const a of advisories) report.advisory({ ...meta, id: meta.id + '#' + a.id, refs: a.refs ?? meta.refs }, a.met, a.detail);
    }
  }
}

// ---------- receiver ----------

async function receiver(adapter, v, file, advisories) {
  const { params, document } = setup(v);
  const { inbox } = await adapter.call('reset', { role: 'receiver', ...params((a, url) => url) });
  check(typeof inbox === 'string' && /^http:\/\/(127\.0\.0\.1|localhost|\[::1\]):\d+\//.test(inbox), `reset returned no loopback inbox URL (${inbox})`);
  for (const prior of v.priorState ?? []) await adapter.call('seedOutgoing', { recordBytes: v.records[prior.record].recordBytes });
  if (file === 'reject-rate-limited.json') await adapter.call('fault', { kind: 'rate-limited', source: 'acct:bob@vectors.test' });
  if (file === 'reject-unavailable.json') await adapter.call('fault', { kind: 'unavailable' });
  const sourceOf = id => Object.values(v.records).find(r => r.envelope.id === id)?.envelope.source;
  const answers = [];
  const notes = [];
  let last = null; // { source, id } of the record the current step is about
  let firstBytes = null;
  for (const [i, step] of v.steps.entries()) {
    const at = `step ${i}`;
    await adapter.call('setClock', { now: step.at });
    const exp = step.expect;
    const req = step.request;
    if (req) {
      const body = req.bodyFill ? Buffer.alloc(req.bodyFill.length, req.bodyFill.octet)
        : req.body !== undefined && req.body !== null ? Buffer.from(req.body, 'utf8') : null;
      const before = (await adapter.call('stats')).incoming;
      // The inbox URL is opaque binding configuration (https-binding.md §1.2): use exactly what the adapter returned.
      const res = await rawRequest(inbox, { method: req.method, headers: req.headers ?? {}, body });
      await adapter.call('tick');
      answers.push(res.status === 200 ? res.body.toString('utf8') : null);
      const text = res.body.toString('utf8');
      check(res.status === exp.status, `${at}: HTTP ${res.status} ${text.slice(0, 160)}; expected ${exp.status}`);
      check((res.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase() === exp.contentType, `${at}: content-type ${res.headers['content-type']}`);
      for (const [name, value] of Object.entries(exp.headers ?? {})) {
        const got = res.headers[name];
        if (!value.startsWith('<')) check(got === value, `${at}: header ${name} is ${got}; expected ${value}`);
        else if (/SHOULD/.test(value)) {
          // e.g. Retry-After for rate-limited and unavailable: SHOULD-level (https-binding.md §2.3).
          advisories.push({ id: `${name}-header`, refs: ['https-binding.md §2.3'], met: /^\d+$/.test(got ?? ''), detail: `${name}: ${got ?? 'absent'} (${value})` });
        } else check(/^\d+$/.test(got ?? ''), `${at}: header ${name} is ${got}; expected ${value}`);
      }
      if (exp.problem) {
        const problem = checkProblem(res, { code: exp.problem.code, status: exp.status, at,
          recordId: body && body.length < 65_537 ? (() => { try { return envelopeOf(body.toString('utf8'))?.id ?? null; } catch { return null; } })() : null });
        for (const [k, value] of Object.entries(exp.problem)) check(deepEqual(problem[k], value), `${at}: problem ${k} is ${JSON.stringify(problem[k])}; expected ${JSON.stringify(value)}`);
      }
      const after = (await adapter.call('stats')).incoming;
      if (exp.stored === false || exp.stored === 'unchanged') check(after === before, `${at}: something was stored (${before} → ${after})`);
      if (exp.stored === true) check(after === before + 1, `${at}: expected one new stored record (${before} → ${after})`);
      if (res.status === 200) {
        const r = envelopeOf(body.toString('utf8'));
        last = { source: r.source, id: r.id };
        const stored = await adapter.call('inspectIncoming', last);
        check(stored.found, `${at}: the record is not stored`);
        if (exp.stored === true) { check(stored.recordBytes === body.toString('utf8'), `${at}: stored record bytes differ from the bytes received`); firstBytes ??= stored.recordBytes; }
        if (exp.stored === 'unchanged' && firstBytes) check(stored.recordBytes === firstBytes, `${at}: the first stored record bytes were replaced`);
        check(stored.receipt === text, `${at}: the issued receipt is not stored byte for byte`);
        if (exp.receipt) checkReceipt(text, exp.receipt, body.toString('utf8'), document, at);
      }
      if (exp.receipt === null) check(res.status !== 200, `${at}: a receipt was returned`);
      if (exp.receiptBytesEqualStep !== undefined) {
        check(text === answers[exp.receiptBytesEqualStep], `${at}: receipt bytes differ from step ${exp.receiptBytesEqualStep}`);
      }
    } else {
      await adapter.call('tick');
    }
    if (exp.applyOutcome || exp.applyCount !== undefined || exp.rejectionRecord) {
      check(last, `${at}: no stored record to inspect`);
      const stored = await adapter.call('inspectIncoming', last);
      if (exp.applyOutcome) check(stored.outcome === exp.applyOutcome, `${at}: apply outcome ${stored.outcome}; expected ${exp.applyOutcome}`);
      if (exp.applyCount !== undefined) check(stored.applyCount === exp.applyCount, `${at}: applied ${stored.applyCount} times; expected ${exp.applyCount}`);
      if (exp.rejectionRecord) notes.push(checkRejection(stored, exp.rejectionRecord, document, at));
    }
    for (const item of exp.afterApply ?? []) {
      const dep = await adapter.call('inspectIncoming', { source: sourceOf(item.record), id: item.record });
      check(dep.outcome === item.applyOutcome, `${at}: ${item.record} outcome ${dep.outcome}; expected ${item.applyOutcome}`);
      if (item.rejectionRecord) notes.push(checkRejection(dep, item.rejectionRecord, document, at));
    }
  }
  const final = v.finalState;
  if (final) {
    if (final.rejectionRecords !== undefined) {
      const { rejections } = await adapter.call('stats');
      check(rejections === final.rejectionRecords, `final: ${rejections} rejection records; expected ${final.rejectionRecords}`);
    }
    for (const id of final.stored ?? []) {
      const record = Object.values(v.records).find(r => r.envelope.id === id).envelope;
      const found = (await adapter.call('inspectIncoming', { source: record.source, id })).found ||
        (await adapter.call('inspectOutgoing', { id, recipient: record.to[0] })).found;
      check(found, `final: ${id} not stored`);
    }
    if (final.applyOrder || final.threadHead) {
      const thread = v.records[Object.keys(v.records)[0]].envelope.thread;
      const state = await adapter.optional('inspectThread', { thread });
      if (!state) notes.push('apply order and thread head not checked (inspectThread unsupported)');
      else {
        if (final.applyOrder) check(deepEqual(state.applyOrder, final.applyOrder), `final: apply order ${JSON.stringify(state.applyOrder)}`);
        if (final.threadHead) check(state.head === final.threadHead, `final: thread head ${state.head}`);
      }
    }
  }
  return notes.filter(Boolean).join('; ');
}

function checkReceipt(text, er, answered, document, at) {
  const got = referenceVerify(text, { typ: TYP.receipt, mode: 'evidence', answered }, [document]);
  check(got.ok, `${at}: the receipt fails the reference verifier: ${got.code} (${got.why})`);
  const r = got.record;
  check(deepEqual(Object.keys(r).sort(), [...er.members].sort()), `${at}: receipt members ${Object.keys(r).sort().join(',')}`);
  for (const [k, value] of Object.entries(er.equals ?? {})) {
    if (k === 'data') {
      check(r.data?.sha256 === value.sha256, `${at}: receipt data.sha256`);
      check(instant(r.data?.storedAt) === instant(value.storedAt), `${at}: receipt data.storedAt ${r.data?.storedAt}; expected ${value.storedAt} (injected clock)`);
    } else check(deepEqual(r[k], value), `${at}: receipt ${k} is ${JSON.stringify(r[k])}`);
  }
  if (er.timeAtOrAfter) check(instant(r.time) >= instant(er.timeAtOrAfter), `${at}: receipt time ${r.time} precedes storedAt`);
}

function checkRejection(stored, exp, document, at) {
  if (!stored.rejection) {
    check(exp.optional, `${at}: no signed rejection record was emitted`);
    return 'optional (MAY) rejection record not emitted';
  }
  const got = referenceVerify(stored.rejection.recordBytes, { typ: exp.typ, mode: 'evidence', answered: stored.recordBytes }, [document]);
  check(got.ok, `${at}: the rejection record fails the reference verifier: ${got.code} (${got.why})`);
  for (const [path, value] of Object.entries(exp.equals ?? {})) check(deepEqual(dotted(got.record, path), value), `${at}: rejection ${path} is ${JSON.stringify(dotted(got.record, path))}`);
  for (const m of exp.absent ?? []) check(!(m in got.record), `${at}: rejection has ${m}`);
  for (const m of exp.present ?? []) check(m in got.record, `${at}: rejection lacks ${m}`);
  if (exp.deliveredTo) check(deepEqual(stored.rejection.deliverTo, [exp.deliveredTo]), `${at}: rejection queued for ${JSON.stringify(stored.rejection.deliverTo)}`);
  return 'rejection ' + got.record.data.code;
}

// ---------- sender ----------

async function sender(adapter, v, advisories) {
  const server = await scriptedServer();
  try {
    const { params } = setup(v);
    const out = v.records.out;
    const fresh = async () => {
      await adapter.call('reset', { role: 'sender', ...params(() => server.url) });
      for (const r of Object.values(v.records)) await adapter.call('queueSigned', { recordBytes: r.recordBytes });
    };
    if (v.cases) {
      for (const [i, c] of v.cases.entries()) {
        await fresh();
        await adapter.call('setClock', { now: new Date(instant(out.envelope.time) + 30_000).toISOString() });
        server.answer(c.respond);
        const { result } = await adapter.call('attempt', { id: out.envelope.id, recipient: out.envelope.to[0] });
        check(result === c.expect.attemptResult, `case ${i} (HTTP ${c.respond.status}): ${result}; expected ${c.expect.attemptResult}`);
      }
      return `${v.cases.length} cases`;
    }
    await fresh();
    const notes = [];
    let previousBackoff = 0;
    for (const [i, step] of v.steps.entries()) {
      const at = `step ${i}`;
      await adapter.call('setClock', { now: step.at });
      const exp = step.expect;
      const req = step.request;
      const name = req?.bodyEqualsRecord ?? 'out';
      const recipient = req?.headers['darep-recipient'] ?? out.envelope.to[0];
      const key = { id: v.records[name].envelope.id, recipient };
      if (req) {
        const before = await adapter.call('inspectOutgoing', key);
        check(before.status === 'queued', `${at}: delivery is ${before.status} before the attempt`);
        // A redirect points at a loopback trap: a sender that follows it (https-binding.md §2.1, §3) is caught there.
        const respond = step.respond.headers?.location ? { ...step.respond, headers: { ...step.respond.headers, location: server.trapUrl } } : step.respond;
        server.answer(respond);
        const { result } = await adapter.call('attempt', key);
        check(server.trapped.length === 0, `${at}: the sender followed a redirect`);
        check(server.received.length === 1, `${at}: the sender made ${server.received.length} requests for one attempt`);
        const got = server.received[0];
        checkRequest(got, v.records[name].recordBytes, recipient, at);
        if (exp.attemptResult) check(result === exp.attemptResult, `${at}: attempt result ${result}; expected ${exp.attemptResult}`);
      } else {
        await adapter.call('tick');
      }
      const state = await adapter.call('inspectOutgoing', key);
      const lastAttempt = state.attempts?.at(-1);
      if (exp.delivery) check(state.status === exp.delivery, `${at}: delivery ${state.status}; expected ${exp.delivery}`);
      if (exp.verifyCode) check(lastAttempt?.code === exp.verifyCode, `${at}: recorded code ${lastAttempt?.code}; expected ${exp.verifyCode}`);
      if (exp.evidenceKept) {
        const kept = exp.evidenceKept;
        if (step.respond.body !== undefined && /body|receipt bytes/.test(kept)) check(lastAttempt?.body === step.respond.body, `${at}: response body not kept as evidence`);
        if (/status/.test(kept)) check(lastAttempt?.status === step.respond.status, `${at}: response status not kept as evidence`);
        if (/retry-after/.test(kept)) check(String(lastAttempt?.headers?.['retry-after']) === step.respond.headers['retry-after'], `${at}: Retry-After not kept as evidence`);
      }
      const nextAt = state.nextAttemptAt ? instant(state.nextAttemptAt) : null;
      if (exp.nextAttemptNotBefore) {
        if (nextAt === null) notes.push(`${at}: retry time not checked (adapter reports no nextAttemptAt)`);
        else check(nextAt >= instant(exp.nextAttemptNotBefore), `${at}: next attempt ${state.nextAttemptAt}; must not be before ${exp.nextAttemptNotBefore}`);
      }
      if (exp.backoff) {
        if (state.backoffMs === undefined || nextAt === null) notes.push(`${at}: backoff not checked (adapter reports no backoffMs)`);
        else {
          check(state.backoffMs >= exp.backoff.minimumSeconds * 1000, `${at}: backoff ${state.backoffMs} ms is below the minimum`);
          if (exp.backoff.nonDecreasing) check(state.backoffMs >= previousBackoff, `${at}: backoff decreased`);
          check(nextAt >= instant(step.at) + state.backoffMs, `${at}: the next attempt precedes the backoff delay`);
          previousBackoff = state.backoffMs;
        }
      }
      if (exp.should?.backoffSeconds !== undefined && state.backoffMs !== undefined) {
        const met = state.backoffMs === exp.should.backoffSeconds * 1000 && nextAt === instant(exp.should.nextAttemptAt);
        advisories.push({ id: `backoff-profile-${i}`, refs: ['delivery.md §7.2'], met,
          detail: `zero-jitter profile backoff ${exp.should.backoffSeconds} s; got ${state.backoffMs / 1000} s` });
      }
      if (exp.furtherAttempts === 0) {
        await adapter.call('setClock', { now: new Date(instant(step.at) + 3600_000).toISOString() });
        await adapter.call('tick');
        const { deliveries } = await adapter.call('due');
        check(!deliveries.some(d => d.id === key.id && d.recipient === recipient), `${at}: further attempts are still due`);
      }
      if (exp.receiptStored) check(state.receipt === step.respond.body, `${at}: receipt not stored byte for byte`);
      for (const [id, dep] of Object.entries(exp.dependentRecords ?? {})) {
        const d = await adapter.call('inspectOutgoing', { id, recipient });
        advisories.push({ id: 'dependent-records', refs: ['delivery.md §7.3'], met: d.status === 'failed' && (d.attempts?.length ?? 0) === 0,
          detail: `${dep.should}: dependent delivery is ${d.status} after ${d.attempts?.length ?? 0} attempts` });
      }
    }
    return notes.join('; ');
  } finally { await server.close(); }
}

function checkRequest(got, recordBytes, recipient, at) {
  check(got.method === 'POST', `${at}: method ${got.method}`);
  check(got.body.toString('latin1') === recordBytes, `${at}: the request body is not the stored record bytes`);
  check((got.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase() === 'application/jose', `${at}: content-type ${got.headers['content-type']}`);
  const recipients = got.rawHeaders.filter((value, i) => i % 2 === 1 && got.rawHeaders[i - 1].toLowerCase() === 'darep-recipient');
  check(recipients.length === 1 && recipients[0] === recipient, `${at}: Darep-Recipient ${JSON.stringify(recipients)}`);
  check(!got.headers.authorization && !got.headers.cookie, `${at}: the sender sent credentials`);
  check(!got.headers['content-encoding'] || got.headers['content-encoding'] === 'identity', `${at}: content-encoding ${got.headers['content-encoding']}`);
}
