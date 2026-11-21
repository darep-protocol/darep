import assert from 'node:assert/strict';
import test from 'node:test';
import { createPrivateKey } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { Store } from '../src/store.js';
import { advance, parseAction } from '../src/protocol.js';
import { typs, verifyRecord } from '../src/records.js';
import { checkCarrier, problemResponse, receive, send } from '../src/provider.js';

const root = new URL('../../../vectors/v2/delivery/', import.meta.url);
const load = path => JSON.parse(readFileSync(new URL(path, root), 'utf8'));
const { documents, inboxes } = load('identities.json');
const keys = load('test-keys.json').keys;
const resolve = id => documents.find(d => d.id === id);
const payload = token => JSON.parse(Buffer.from(token.split('.')[1], 'base64url'));
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
for (const role of ['receiver', 'sender']) {
  for (const file of readdirSync(new URL(role + '/', root)).filter(f => f.endsWith('.json')).sort()) {
    test(`delivery vector ${role}/${file}`, async t => {
      const v = load(role + '/' + file);
      if (role === 'sender') {
        // Cases are independent attempts; steps share durable state and exponential backoff.
        const scenarios = v.cases ? v.cases.map(c => [c]) : [v.steps];
        for (const steps of scenarios) {
          const f = fixture(v, t), { store, config } = f;
          for (const r of Object.values(v.records)) store.transaction(() => store.queueSigned(r.recordBytes));
          const out = store.db.prepare('SELECT * FROM events WHERE event_id=?').get(v.records.out.envelope.id);
          for (const step of steps) {
            if (step.at) f.clock(step.at);
            let calls = 0;
            if (step.respond) await send(out, config, store, async (url, options) => {
              calls++;
              assert.equal(options.body, v.records.out.recordBytes);
              assert.equal(options.redirect, 'manual');
              assert.equal(String(url), inboxes[out.recipient]);
              assert.equal(options.method, 'POST');
              assert.equal(options.headers['darep-recipient'], out.recipient);
              assert.equal(options.headers['content-type'], 'application/jose');
              if (step.respond.connection) throw new Error('Injected connection reset');
              return new Response(step.respond.body ?? '', { status: step.respond.status, headers: step.respond.headers });
            });
            else store.applyReady();
            const delivery = store.db.prepare('SELECT * FROM outbox WHERE event_row=?').get(out.row_id);
            const attempt = store.db.prepare('SELECT * FROM attempts WHERE event_row=? ORDER BY id DESC LIMIT 1').get(out.row_id);
            const expected = step.expect;
            if (expected.delivery) assert.equal(delivery.status, expected.delivery);
            if (expected.attemptResult) assert.equal(attempt.result, expected.attemptResult);
            if (expected.verifyCode) assert.equal(attempt.code, expected.verifyCode);
            if (expected.nextAttemptNotBefore) assert.ok(delivery.next_at >= Date.parse(expected.nextAttemptNotBefore));
            if (step.respond) {
              assert.equal(calls, 1);
              if (!step.respond.connection) {
                assert.equal(attempt.status, step.respond.status);
                assert.equal(attempt.body, step.respond.body ?? '');
                fields(JSON.parse(attempt.headers), step.respond.headers ?? {});
              }
            }
            if (expected.delivery === 'delivered') assert.equal(delivery.receipt, step.respond.body);
            if (expected.furtherAttempts === 0) assert.equal(store.due().length, 0);
            for (const id of Object.keys(expected.dependentRecords ?? {})) {
              const dep = store.db.prepare('SELECT o.* FROM outbox o JOIN events e ON e.row_id=o.event_row WHERE e.event_id=?').get(id);
              assert.equal(dep.status, 'failed'); assert.equal(dep.attempts, 0);
            }
          }
        }
        return;
      }
      const f = fixture(v, t), { store } = f;
      for (const prior of v.priorState ?? []) seed(f, v.records[prior.record]);
      if (file === 'reject-rate-limited.json') store.capacity = () => 'rate-limited';
      if (file === 'reject-unavailable.json') {
        store.db.exec("CREATE TRIGGER fail_store BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT, 'Injected storage failure'); END");
      }
      const applied = (v.priorState ?? []).map(prior => v.records[prior.record].envelope.id);
      const setOutcome = store.outcome.bind(store);
      store.outcome = (row, outcome, code) => {
        const result = setOutcome(row, outcome, code);
        if (outcome === 'applied' && row.typ === typs.event) applied.push(row.event_id);
        return result;
      };
      const answers = [];
      let row;
      for (const step of v.steps) {
        f.clock(step.at);
        const expected = step.expect;
        const countBefore = store.db.prepare('SELECT count(*) AS n FROM events').get().n;
        if (step.request) {
          const req = step.request;
          const body = req.bodyFill ? req.bodyFill.octet.repeat(req.bodyFill.length) : req.body ?? v.records[req.bodyEqualsRecord]?.recordBytes;
          let response;
          try {
            checkCarrier(req.method, req.headers);
            response = { status: 200, headers: { 'content-type': 'application/jose' }, body: receive(body, req.headers['darep-recipient'], f) };
          } catch (error) { response = problemResponse(error.code); }
          answers.push(response.body);
          assert.equal(response.status, expected.status);
          assert.equal(response.headers['content-type'], expected.contentType);
          if (expected.problem) fields(response.body, expected.problem);
          for (const [key, value] of Object.entries(expected.headers ?? {})) {
            if (!value.startsWith('<')) assert.equal(response.headers[key], value);
          }
          if (expected.stored === false || expected.stored === 'unchanged') {
            assert.equal(store.db.prepare('SELECT count(*) AS n FROM events').get().n, countBefore);
          }
          if (response.status === 200) {
            const receipt = verifyRecord(response.body, { typ: typs.receipt, mode: 'evidence' }, resolve).record;
            row = store.db.prepare("SELECT * FROM events WHERE direction='in' AND event_id=?").get(receipt.inReplyTo);
            assert.ok(row);
            assert.equal(row.digest, receipt.data.sha256);
            assert.equal(row.receipt, response.body);
            if (expected.stored === true) {
              assert.equal(row.jws, body);
              assert.equal(row.outcome, null, 'Application must not precede acknowledgement');
            }
            if (expected.receipt?.equals) fields(receipt, expected.receipt.equals);
            if (expected.receipt?.members) assert.deepEqual(Object.keys(receipt).sort(), expected.receipt.members.toSorted());
            if (expected.receipt?.timeAtOrAfter) assert.ok(Date.parse(receipt.time) >= Date.parse(expected.receipt.timeAtOrAfter));
            if (expected.receipt?.retainedAtLeastUntil) assert.ok(Date.parse(row.retain_until) >= Date.parse(expected.receipt.retainedAtLeastUntil));
            if (expected.receiptBytesEqualStep !== undefined) assert.equal(response.body, answers[expected.receiptBytesEqualStep]);
          }
        }
        store.applyReady();
        if (row) row = store.db.prepare('SELECT * FROM events WHERE row_id=?').get(row.row_id);
        if (expected.applyOutcome) assert.equal(row.outcome, expected.applyOutcome);
        if (expected.applyCount !== undefined) assert.equal(row.apply_count, expected.applyCount);
        for (const after of expected.afterApply ?? []) {
          const dependent = store.db.prepare('SELECT * FROM events WHERE event_id=?').get(after.record);
          assert.equal(dependent.outcome, after.applyOutcome);
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
          for (const key of expected.rejectionRecord.absent ?? []) assert.ok(!(key in rejection));
          for (const key of expected.rejectionRecord.present ?? []) assert.ok(key in rejection);
          assert.equal(store.db.prepare('SELECT status FROM outbox WHERE event_row=?').get(rejectionRow.row_id).status, 'queued');
        }
      }
      if (v.finalState?.applyOrder) assert.deepEqual(applied, v.finalState.applyOrder);
      if (v.finalState?.rejectionRecords !== undefined) {
        assert.equal(store.db.prepare("SELECT count(*) AS n FROM events WHERE direction='out' AND typ=?").get(typs.rejection).n,
          v.finalState.rejectionRecords);
      }
      if (v.finalState?.threadHead) assert.equal(store.state(row.topic).head, v.finalState.threadHead);
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
