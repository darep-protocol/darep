// Runs every Wire v2 signed-record vector in vectors/v2/records/ through src/records.js (records.md §11).
import assert from 'node:assert/strict';
import test from 'node:test';
import { generateKeyPairSync } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { RecordRejection, makeEventRecord, makeIdentityDocument, makeReceiptRecord, sha256, signRecord,
  typs, validateDocument, verifyRecord, strictJson, isMonotonicUpdate, isUriHost, isHttpsUri, checkEnvelope } from '../src/records.js';

const root = new URL('../../../vectors/v2/records/', import.meta.url);
const load = path => JSON.parse(readFileSync(new URL(path, root), 'utf8'));
const { documents } = load('identities.json');
const index = load('index.json').vectors;
const files = ['positive', 'negative'].flatMap(dir =>
  readdirSync(new URL(dir + '/', root)).filter(f => f.endsWith('.json')).map(f => dir + '/' + f.slice(0, -5))).sort();

// P-0 and TA-4 across the pinned set: unique document ids and no shared address.
for (const d of documents) validateDocument(d);
assert.equal(new Set(documents.map(d => d.id)).size, documents.length);
assert.equal(new Set(documents.flatMap(d => d.addresses)).size, documents.flatMap(d => d.addresses).length);
const resolve = id => documents.find(d => d.id === id) ?? null;

function run(vector) {
  const c = vector.context;
  const context = { ...c, now: Date.parse(c.now) };
  try {
    const out = verifyRecord(vector.jws, context, resolve);
    return { verdict: 'accept', kid: out.kid, record: out.record, sha: sha256(out.payload), body: out.body };
  } catch (error) {
    if (!(error instanceof RecordRejection)) throw error;
    return { verdict: 'reject', code: error.code, why: error.message };
  }
}

test('index.json lists exactly the vector files on disk', () => {
  assert.deepEqual(index.map(v => v.name).sort(), files);
});

for (const name of files) {
  test('records vector ' + name, () => {
    const vector = load(name + '.json');
    const listed = index.find(v => v.name === name);
    assert.equal(listed.verdict, vector.expected.verdict);
    const got = run(vector);
    if (vector.expected.verdict === 'reject') {
      assert.deepEqual({ verdict: got.verdict, code: got.code }, vector.expected, got.why);
      assert.equal(listed.code, vector.expected.code);
      return;
    }
    assert.equal(got.verdict, 'accept', got.why);
    assert.equal(got.kid, vector.expected.kid);
    assert.deepEqual(got.record, vector.expected.record);
    assert.equal(got.sha, vector.payloadSha256);
    // NC1: the stored body is the exact payload text, never a re-serialization.
    assert.equal(got.body, vector.payloadUtf8);
    if (vector.expected.receiptFor) {
      const target = load(vector.expected.receiptFor + '.json');
      assert.equal(got.record.data.sha256, target.payloadSha256);
      assert.equal(got.record.inReplyTo, target.expected.record.id);
    }
  });
}

test('evidence mode accepts an expired record but still refuses a revoked key', () => {
  const expired = load('positive/evidence-mode-expired.json');
  const receiver = expired.expected.record.to[0];
  assert.equal(run({ ...expired, context: { understood: [], ...expired.context, mode: 'admission', receiver } }).code, 'expired');
  const revoked = load('negative/revoked-key.json');
  assert.equal(revoked.context.mode, 'evidence');
  assert.equal(run(revoked).code, 'key-not-valid');
});

test('the Node signer produces events and receipts that pass §8, and the receipt answers the exact bytes', () => {
  const keys = { a: generateKeyPairSync('ec', { namedCurve: 'P-256' }), b: generateKeyPairSync('ec', { namedCurve: 'P-256' }) };
  const docA = makeIdentityDocument('acct:alice@a.test', keys.a.publicKey, new Date(Date.now() - 60_000));
  const docB = makeIdentityDocument('acct:bob@b.test', keys.b.publicKey, new Date(Date.now() - 60_000));
  const pins = id => [docA, docB].find(d => d.id === id) ?? null;
  const event = makeEventRecord({ source: 'acct:alice@a.test', to: 'acct:bob@b.test', type: 'https://darep.org/ext/work/v2#handoff',
    data: { summary: 's', nextStep: 'n', expectedResult: 'r' }, grant: { id: 'g-1', actor: 'agent' } });
  // Any serialization is valid; it is the signed bytes that count (C-3).
  const body = JSON.stringify(event, null, 3);
  const token = signRecord(body, { key: keys.a.privateKey, kid: docA.keys[0].id }, typs.event);
  const now = Date.now();
  const got = verifyRecord(token, { typ: typs.event, now, receiver: 'acct:bob@b.test', understood: event.required }, pins);
  assert.equal(got.body, body);
  assert.throws(() => verifyRecord(token, { typ: typs.event, now, receiver: 'acct:carol@c.test', understood: event.required }, pins),
    { code: 'wrong-recipient' });
  assert.throws(() => verifyRecord(token, { typ: typs.event, now, receiver: 'acct:bob@b.test', understood: [] }, pins),
    { code: 'unsupported-extension' });
  const receipt = makeReceiptRecord('acct:bob@b.test', event, { sha256: sha256(body), storedAt: new Date(now).toISOString() });
  const receiptToken = signRecord(JSON.stringify(receipt), { key: keys.b.privateKey, kid: docB.keys[0].id }, typs.receipt);
  verifyRecord(receiptToken, { typ: typs.receipt, now, receiver: 'acct:alice@a.test', answered: token }, pins);
  const other = signRecord(JSON.stringify(event), { key: keys.a.privateKey, kid: docA.keys[0].id }, typs.event);
  assert.throws(() => verifyRecord(receiptToken, { typ: typs.receipt, now, receiver: 'acct:alice@a.test', answered: other }, pins),
    { code: 'receipt-mismatch' });
  // The signer refuses to emit what a verifier must reject.
  assert.throws(() => signRecord(JSON.stringify({ ...event, extra: 1 }), { key: keys.a.privateKey, kid: docA.keys[0].id }, typs.event),
    { code: 'malformed' });
  assert.throws(() => signRecord(body, { key: keys.a.privateKey, kid: docA.keys[0].id }, 'agent-network-event+jws'),
    { code: 'bad-header' });
});

test('strict JSON keeps __proto__ as a member and rejects lone surrogates', () => {
  const { value } = strictJson(Buffer.from('{"__proto__":{"x":1}}'));
  assert.deepEqual(Object.keys(value), ['__proto__']);
  assert.equal(Object.getPrototypeOf(value), Object.prototype);
  assert.throws(() => strictJson(Buffer.from('"\\ud800"')), { code: 'malformed' });
});

test('a snapshot update is routine only when it is monotonic (records.md §5.5)', () => {
  const bob = structuredClone(documents.find(d => d.id.includes('bob')));
  const retired = structuredClone(bob);
  retired.keys.at(-1).validUntil = '2027-01-01T00:00:00Z';
  assert.ok(isMonotonicUpdate(bob, retired));
  const swapped = structuredClone(bob);
  swapped.keys[0].publicKeyJwk = documents.find(d => d.id.includes('carol')).keys[0].publicKeyJwk;
  assert.ok(!isMonotonicUpdate(bob, swapped));
  const dropped = structuredClone(bob);
  dropped.keys.pop();
  assert.ok(!isMonotonicUpdate(bob, dropped));
  const unrevoked = structuredClone(bob);
  delete unrevoked.keys[0].revoked;
  assert.ok(!isMonotonicUpdate(bob, unrevoked));
});

test('hardening found in review: hostile header values, deep nesting, empty fragments, step 15 order, rejection codes', () => {
  const enc = v => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url');
  // An object-valued alg must still be unsupported-alg, never a crash.
  assert.throws(() => verifyRecord(enc('{"alg":{"toString":0}}') + '.e30.', { typ: typs.event, mode: 'evidence' }, resolve),
    { code: 'unsupported-alg' });
  // Nesting is bounded by the 64 KiB carrier limit only (delivery.md §3.4), not by the call stack.
  const deep = '['.repeat(30_000) + ']'.repeat(30_000);
  assert.equal(strictJson(Buffer.from(deep)).text.length, 60_000);
  // A document URL with an empty fragment or query is not a valid document id (records.md §5.1).
  const carol = structuredClone(documents.find(d => d.id.includes('carol')));
  for (const id of [carol.id + '#', carol.id + '?']) {
    const bad = { ...carol, id, keys: carol.keys.map(k => ({ ...k, id: id + '#k' })) };
    assert.throws(() => validateDocument(bad), { code: 'malformed' });
  }
  // A receipt with the wrong digest after the delivery window is a mismatch first (RC-1 before TM-4a).
  const mismatch = load('negative/receipt-mismatch.json');
  const late = { ...mismatch.context, now: Date.parse('2027-06-01T00:00:00Z') };
  assert.throws(() => verifyRecord(mismatch.jws, late, resolve), { code: 'receipt-mismatch' });
});

for (const c of load('invalid-identities.json').cases) {
  test('invalid identity vector ' + c.name, () => {
    assert.throws(() => validateDocument(c.document), { code: 'malformed' });
  });
}

test('K-1 host grammar: lowercase LDH DNS and test-only canonical IPv4', () => {
  for (const host of ['a.test', 'a-b.example', 'xn--anything.test', 'a'.repeat(63) + '.test',
    ['a'.repeat(63), 'b'.repeat(63), 'c'.repeat(63), 'd'.repeat(61)].join('.')]) assert.ok(isUriHost(host), host);
  for (const host of ['', 'localhost', '-a.test', 'a-.test', 'a..test', 'a.test.', 'A.test', 'a_b.test',
    'a.123', 'a.0xff', 'a.0x', 'a'.repeat(64) + '.test', ['a'.repeat(63), 'b'.repeat(63), 'c'.repeat(63), 'd'.repeat(62)].join('.'),
    '127.1', '0177.0.0.1', '0x7f.0.0.1', '256.0.0.1', '[::1]', 'a.test\n']) {
    assert.equal(isUriHost(host, { testOnly: true }), false, host);
  }
  for (const host of ['127.0.0.1', '0.0.0.0', '255.255.255.255']) {
    assert.equal(isUriHost(host), false, host);
    assert.equal(isUriHost(host, { testOnly: true }), true, host);
  }
});

test('K-1 URI grammar rejects normalization and empty forbidden delimiters', () => {
  for (const uri of ['https://a.test/', 'https://a.test:1/p?x=1', 'https://a.test:65535/p?']) {
    assert.ok(isHttpsUri(uri, { fragment: false }), uri);
  }
  assert.ok(isHttpsUri('https://127.0.0.1/p#k', { fragment: true, testOnly: true }));
  for (const uri of ['https://a.test', 'https://u@a.test/p', 'https://a.test:443/p', 'https://a.test:0/p',
    'https://a.test:0444/p', 'https://a.test:65536/p', 'https://a.test:444\n/p',
    'https://a.test/./p', 'https://a.test/%2E%2e/p', 'https://a.test/.%2e/p', 'https://a.test/%2e./p',
    'https://a.test/p#', 'https://a.test/p#k#extra', 'https://a.test/p?q=\'x', 'https://a.test/é']) {
    assert.equal(isHttpsUri(uri, { fragment: uri.includes('#') }), false, uri);
  }
  assert.equal(isHttpsUri('https://a.test/p#', { fragment: false }), false);
  for (const suffix of ['?', '?v=1']) assert.equal(isHttpsUri('https://a.test/p' + suffix, { fragment: false, query: false }), false);
});

test('invalid kid is rejected before pin lookup; unknown refusal codes obey syntax', () => {
  for (const name of ['kid-hyphen-host', 'kid-single-label-host', 'kid-empty-fragment', 'kid-default-port', 'kid-userinfo']) {
    const v = load('negative/' + name + '.json');
    assert.throws(() => verifyRecord(v.jws, v.context, () => assert.fail('must not resolve a bad kid')), { code: 'bad-header' });
  }
  const r = load('positive/rejection-unknown-code.json').expected.record;
  for (const code of ['future-refusal', 'x'.repeat(64), 'https://a.test/refusal#new']) {
    assert.doesNotThrow(() => checkEnvelope({ ...r, data: { code } }, typs.rejection));
  }
  for (const code of [undefined, null, 1, '', 'Bad', 'x'.repeat(65), 'bad code', 'bad\n']) {
    assert.throws(() => checkEnvelope({ ...r, data: { code } }, typs.rejection), { code: 'malformed' });
  }
});


test('P-0 permits unknown members and a validUntil at the Unix epoch', () => {
  const d = structuredClone(documents[0]);
  d.extra = { informational: true };
  d.keys = [d.keys[0]];
  Object.assign(d.keys[0], { validFrom: '1960-01-01T00:00:00Z', validUntil: '1970-01-01T00:00:00Z',
    revoked: '1959-01-01T00:00:00Z', extra: true });
  // Revocation has no ordering constraint relative to the signing window.
  assert.doesNotThrow(() => validateDocument(d));
});

test('test-only IPv4 URI policy is explicit for document and kid syntax (#19)', () => {
  for (const [uri, fragment, query] of [
    ['https://127.0.0.1/identity', false, false],
    ['https://127.0.0.1/identity#key-1', true, true],
  ]) {
    assert.equal(isHttpsUri(uri, { fragment, query, testOnly: false }), false);
    assert.equal(isHttpsUri(uri, { fragment, query, testOnly: true }), true);
    assert.equal(isHttpsUri(uri, { fragment, query }), false);
  }
});
