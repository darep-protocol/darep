// Generates the Wire v2 delivery vectors (spec/delivery.md, spec/https-binding.md).
//
//   node vectors/v2/delivery/generate.mjs           write test-keys.json (if missing), identities.json and every vector
//   node vectors/v2/delivery/generate.mjs --check   verify the committed files without writing anything
//
// TEST ONLY. Every private key used here is in test-keys.json, which is published on purpose.
// No key from this directory may ever sign a real record. The addresses use the reserved .test TLD.
//
// Output is byte-for-byte deterministic: ids are derived from fixed names, times are fixed, and ES256
// signatures use deterministic ECDSA (RFC 6979) over the committed test keys in test-keys.json.
// Uses only existing dependencies (jose for --check cross-verification) and node:crypto.
//
// Record, receipt, rejection and identity-document shapes follow spec/records.md. --check runs every record and
// receipt through the records reference verifier (vectors/v2/records/check.mjs) and fails if a vector's expected code
// differs from the code that procedure returns, so the two vector sets cannot drift apart.

import { createECDH, createHash, createHmac } from 'node:crypto';
import { mkdir, readFile, writeFile, readdir, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compactVerify, decodeProtectedHeader, exportJWK, generateKeyPair, importJWK } from 'jose';
import { verifyRecord, validatePins } from '../records/check.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const CHECK = process.argv.includes('--check');

// ---------- constants from the spec ----------

const TYP = { event: 'darep-event+jws', receipt: 'darep-receipt+jws', rejection: 'darep-rejection+jws' };
const CORE = 'https://darep.org/ext/core/v2';
const WORK = 'https://darep.org/ext/work/v2';
const HANDOFF = WORK + '#handoff';
const PROBLEM = 'https://darep.org/problems/';
const SKEW_S = 300;          // records.md §7.2
const WINDOW_DAYS = 7;       // records.md §7.2: SHOULD-default expires; delivery.md §2: hold window
const RETAIN_DAYS = 30;      // D4
const MAX_RECORD = 65536;

const T0 = '2026-11-20T10:00:00Z';
const at = (seconds, base = T0) => new Date(Date.parse(base) + seconds * 1000).toISOString().replace('.000Z', 'Z');
const days = n => n * 86400;

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
// Deterministic UUID v4 shape derived from a name, so payload bytes stay stable across regeneration.
function uuid(name) {
  const h = createHash('sha256').update('darep-vectors:' + name).digest('hex');
  const v = (parseInt(h[16], 16) & 0x3 | 0x8).toString(16);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-${v}${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

// ---------- test identities ----------

const PEOPLE = {
  bob: { address: 'acct:bob@vectors.test', host: 'bob.vectors.test', keys: {
    'sig-1': { purpose: ['record'], validFrom: '2026-01-01T00:00:00Z', validUntil: '2027-12-31T23:59:59Z' },
    'sig-old': { purpose: ['record'], validFrom: '2025-01-01T00:00:00Z', validUntil: '2026-06-01T00:00:00Z' },
    'rcpt-1': { purpose: ['provider'], validFrom: '2026-01-01T00:00:00Z', validUntil: '2027-12-31T23:59:59Z' },
  } },
  carol: { address: 'acct:carol@vectors.test', host: 'carol.vectors.test', keys: {
    'sig-1': { purpose: ['record'], validFrom: '2026-01-01T00:00:00Z', validUntil: '2027-12-31T23:59:59Z' },
    'rcpt-1': { purpose: ['provider'], validFrom: '2026-01-01T00:00:00Z', validUntil: '2027-12-31T23:59:59Z' },
  } },
  dave: { address: 'acct:dave@vectors.test', host: 'dave.vectors.test', keys: {
    'sig-1': { purpose: ['record', 'provider'], validFrom: '2026-01-01T00:00:00Z', validUntil: '2027-12-31T23:59:59Z' },
  } },
  mallory: { address: 'acct:mallory@vectors.test', host: 'mallory.vectors.test', keys: {
    'sig-1': { purpose: ['record'], validFrom: '2026-01-01T00:00:00Z', validUntil: '2027-12-31T23:59:59Z' },
  } },
};
const docUrl = who => `https://${PEOPLE[who].host}/.well-known/darep/${who}`;
// Binding configuration (https-binding.md §1.1): one inbox per provider host, not part of the identity document.
const inbox = who => `https://${PEOPLE[who].host}/darep/v2/inbox`;
const kid = (who, key) => `${docUrl(who)}#${key}`;
const addr = who => PEOPLE[who].address;

async function loadOrCreateKeys() {
  const file = join(here, 'test-keys.json');
  if (existsSync(file)) {
    const text = await readFile(file, 'utf8');
    const out = JSON.parse(text);
    if (!CHECK) {
      // Relabel the existing public test keys after the protocol path rename; preserve key material.
      out.keys = Object.fromEntries(Object.entries(out.keys).map(([id, key]) =>
        [id.replace(/\/\.well-known\/[^/]+\//, '/.well-known/darep/'), key]));
      const updated = JSON.stringify(out, null, 2) + '\n';
      if (updated !== text) await writeFile(file, updated);
    }
    return out;
  }
  if (CHECK) throw new Error('test-keys.json is missing');
  const out = {
    warning: 'TEST ONLY. These private keys are public on purpose and MUST NOT sign any real record. Never pin them outside tests.',
    hmacSecretForUnsupportedAlgorithm: 'vectors-only-hs256-secret-not-a-real-key',
    keys: {},
  };
  for (const [who, p] of Object.entries(PEOPLE)) for (const name of Object.keys(p.keys)) {
    const { privateKey } = await generateKeyPair('ES256', { extractable: true });
    out.keys[kid(who, name)] = { ...(await exportJWK(privateKey)), alg: 'ES256' };
  }
  await writeFile(file, JSON.stringify(out, null, 2) + '\n');
  return out;
}

function publicJwk(jwk) {
  const { kty, crv, x, y } = jwk;
  return { kty, crv, x, y };
}

// Identity documents in the shape of records.md §5.1.
function identityDocuments(testKeys) {
  return Object.entries(PEOPLE).map(([who, p]) => ({
    darep: '2', id: docUrl(who), addresses: [p.address], updated: '2026-01-01T00:00:00Z',
    keys: Object.entries(p.keys).map(([name, k]) => ({
      id: kid(who, name), purpose: k.purpose, publicKeyJwk: publicJwk(testKeys.keys[kid(who, name)]),
      validFrom: k.validFrom, validUntil: k.validUntil,
    })),
  }));
}

// ---------- deterministic P-256 ECDSA (RFC 6979) ----------

const N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551n;
const big = bytes => BigInt('0x' + Buffer.from(bytes).toString('hex'));
const be32 = n => Buffer.from(n.toString(16).padStart(64, '0'), 'hex');
const mod = (a, m) => ((a % m) + m) % m;
const sha256Buf = bytes => createHash('sha256').update(bytes).digest();
const hmac = (key, ...parts) => createHmac('sha256', key).update(Buffer.concat(parts.map(p => Buffer.from(p)))).digest();
const b64u = bytes => Buffer.from(bytes).toString('base64url');

function invert(a, m) {
  let [r0, r1, s0, s1] = [mod(a, m), m, 1n, 0n];
  while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }
  return mod(s0, m);
}
function basePointTimes(scalar32) {
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(scalar32);
  return { x: ecdh.getPublicKey().subarray(1, 33) };
}
function nonce(d32, h1, extra = Buffer.alloc(0)) {
  const h = be32(mod(big(h1), N));
  let V = Buffer.alloc(32, 1);
  let K = Buffer.alloc(32, 0);
  K = hmac(K, V, [0], d32, h, extra); V = hmac(K, V);
  K = hmac(K, V, [1], d32, h, extra); V = hmac(K, V);
  for (;;) {
    V = hmac(K, V);
    const k = big(V);
    if (k >= 1n && k < N) return k;
    K = hmac(K, V, [0]); V = hmac(K, V);
  }
}
function ecdsaSign(d32, message, extraEntropy) {
  const h1 = sha256Buf(message);
  const extra = extraEntropy ? sha256Buf(Buffer.from(extraEntropy)) : Buffer.alloc(0);
  const d = big(d32);
  for (let k = nonce(d32, h1, extra); ; k = nonce(d32, sha256Buf(Buffer.concat([h1, be32(k)])), extra)) {
    const r = mod(big(basePointTimes(be32(k)).x), N);
    const s = mod(invert(k, N) * (big(h1) + r * d), N);
    if (r && s) return Buffer.concat([be32(r), be32(s)]);
  }
}

// ---------- record construction ----------

let KEYS; // filled in main()
async function signBytes(payloadUtf8, { who, key = 'sig-1', typ = TYP.event, alg = 'ES256', header = {}, extraEntropy }) {
  const hdr = JSON.stringify({ alg, kid: kid(who, key), typ, ...header });
  const input = b64u(hdr) + '.' + b64u(Buffer.from(payloadUtf8, 'utf8'));
  if (alg === 'HS256') {
    const mac = createHmac('sha256', Buffer.from(KEYS.hmacSecretForUnsupportedAlgorithm, 'utf8')).update(input, 'ascii').digest();
    return input + '.' + b64u(mac);
  }
  const jwk = KEYS.keys[kid(who, key)];
  const sig = ecdsaSign(Buffer.from(jwk.d, 'base64url'), Buffer.from(input, 'ascii'), extraEntropy);
  return input + '.' + b64u(sig);
}

// Event envelope per records.md §4.1 and §4.3. expires is required; the default is time + 7 days (records.md §7.2).
function envelope({ name, from, to, thread, inReplyTo = null, type = CORE + '#message', time = T0, expires, required = [], data, extra = {} }) {
  const id = uuid(name);
  const env = { darep: '2', id, type, source: addr(from), to: to.map(addr), thread: thread ?? id, inReplyTo, time,
    expires: expires ?? at(days(WINDOW_DAYS), time) };
  Object.assign(env, { ext: {}, required, grant: { id: 'grant-vectors-' + from, actor: 'agent' }, data }, extra);
  return env;
}

async function record(env, signOpts) {
  const payloadUtf8 = JSON.stringify(env);
  const bytes = await signBytes(payloadUtf8, signOpts);
  return { envelope: env, payloadUtf8, payloadSha256: sha256(payloadUtf8), recordBytes: bytes };
}

// Work-extension data shapes are illustrative (records.md §6.1); the v1 action.kind is the type fragment.
const handoffData = { summary: 'Vector handoff 測試 🗓', nextStep: 'Check the attached label.', expectedResult: 'One clear answer.' };

// Receipt per records.md §4.4: a record from the recipient address back to the source.
function receiptPayload({ name, rec, receiver, storedAt, time = storedAt }) {
  return {
    darep: '2', id: uuid('receipt:' + name), source: addr(receiver), type: CORE + '#receipt', time,
    to: [rec.envelope.source], thread: rec.envelope.thread, inReplyTo: rec.envelope.id, ext: {}, required: [],
    data: { sha256: rec.payloadSha256, storedAt },
  };
}
async function receipt(payload, { who, key = 'rcpt-1' }) {
  const payloadUtf8 = JSON.stringify(payload);
  return { payload, receiptBytes: await signBytes(payloadUtf8, { who, key, typ: TYP.receipt }) };
}

const post = (who, body, contentType = 'application/jose', recipient = addr(who)) => ({ method: 'POST', url: inbox(who),
  headers: { 'content-type': contentType, ...(recipient ? { 'darep-recipient': recipient } : {}) }, body });
const problem = (status, code, extraHeaders) => ({
  status, contentType: 'application/problem+json', ...(extraHeaders ? { headers: extraHeaders } : {}),
  problem: { type: PROBLEM + code, status, code }, stored: false, receipt: null,
});
const expectReceipt = (rec, receiver, storedAt, applyOutcome) => ({
  status: 200, contentType: 'application/jose', stored: true,
  receipt: {
    typ: TYP.receipt, signedBy: `a key of ${addr(receiver)} with purpose provider`,
    members: ['darep', 'id', 'source', 'type', 'time', 'to', 'thread', 'inReplyTo', 'ext', 'required', 'data'],
    equals: { darep: '2', source: addr(receiver), type: CORE + '#receipt', to: [rec.envelope.source], thread: rec.envelope.thread,
      inReplyTo: rec.envelope.id, ext: {}, required: [], data: { sha256: rec.payloadSha256, storedAt } },
    timeAtOrAfter: storedAt,
    retainedAtLeastUntil: at(days(RETAIN_DAYS), storedAt),
  },
  applyOutcome,
});
const step = (o) => o;

// ---------- receiver vectors ----------

async function receiverVectors() {
  const v = {};
  const base = { role: 'receiver', clock: 'Each step has "at": the receiver clock at that moment. Runners inject it. A receiver with a real clock checks storedAt format only.' };
  const carolReceiver = { address: addr('carol'), inbox: inbox('carol'), signingKeys: [kid('carol', 'sig-1'), kid('carol', 'rcpt-1')], pinned: [addr('bob'), addr('dave')], extensions: [CORE] };
  const bobReceiver = { address: addr('bob'), inbox: inbox('bob'), signingKeys: [kid('bob', 'sig-1'), kid('bob', 'rcpt-1')], pinned: [addr('carol'), addr('dave')], extensions: [CORE] };

  // A baseline that every other vector builds on.
  const opening = await record(envelope({ name: 'baseline', from: 'bob', to: ['carol'], data: { text: 'Check the label.' } }), { who: 'bob' });
  v['first-delivery'] = { ...base, description: 'A valid core message is verified, stored, acknowledged and applied.',
    spec: ['delivery.md §3', 'delivery.md §4', 'https-binding.md §2'], decisions: ['D4', 'NC1'], receiver: carolReceiver,
    records: { opening }, steps: [step({ at: at(30), request: post('carol', opening.recordBytes), expect: expectReceipt(opening, 'carol', at(30), 'applied') })] };

  // Duplicate delivery, including one after the record has expired.
  const dup = await record(envelope({ name: 'duplicate', from: 'bob', to: ['carol'], data: { text: 'Check the label.' } }), { who: 'bob' });
  const dupResigned = { ...dup, recordBytes: await signBytes(dup.payloadUtf8, { who: 'bob', extraEntropy: 'dup-resigned' }) };
  if (dupResigned.recordBytes === dup.recordBytes) throw new Error('dupResigned must have distinct signature bytes');
  v['duplicate-delivery'] = { ...base, description: 'The same record delivered again gets the byte-identical stored receipt, is not stored twice and is not applied twice. Deduplication runs before the time window, so a retry after expiry still gets its receipt. A re-signed copy with identical payload bytes is also a duplicate.',
    spec: ['delivery.md §6', 'delivery.md §3.1 check D'], decisions: ['D4', 'NC1'], receiver: carolReceiver, records: { dup, dupResigned },
    steps: [
      step({ at: at(30), request: post('carol', dup.recordBytes), expect: expectReceipt(dup, 'carol', at(30), 'applied') }),
      step({ at: at(90), request: post('carol', dup.recordBytes), expect: { status: 200, contentType: 'application/jose', receiptBytesEqualStep: 0, stored: 'unchanged', applyCount: 1 } }),
      step({ at: at(120), request: post('carol', dupResigned.recordBytes), expect: { status: 200, contentType: 'application/jose', receiptBytesEqualStep: 0, stored: 'unchanged', applyCount: 1, note: 'Different signature bytes, same payload bytes. The first record bytes stay stored.' } }),
      step({ at: at(days(WINDOW_DAYS) + SKEW_S + 3600), request: post('carol', dup.recordBytes), expect: { status: 200, contentType: 'application/jose', receiptBytesEqualStep: 0, stored: 'unchanged', applyCount: 1, note: 'Past expires; a fresh record would get "expired". Deduplication (check D) runs before R13.' } }),
    ] };

  // Out of order: carol's complete (R3) arrives before her accept (R2). Receiver is bob, who opened the thread.
  const r1 = await record(envelope({ name: 'ooo-open', from: 'bob', to: ['carol'], type: HANDOFF, required: [WORK], data: handoffData }), { who: 'bob' });
  const r2 = await record(envelope({ name: 'ooo-accept', from: 'carol', to: ['bob'], thread: r1.envelope.id, inReplyTo: r1.envelope.id, time: at(60), type: WORK + '#accept', required: [WORK], data: {} }), { who: 'carol' });
  const r3 = await record(envelope({ name: 'ooo-complete', from: 'carol', to: ['bob'], thread: r1.envelope.id, inReplyTo: r2.envelope.id, time: at(120), type: WORK + '#complete', required: [WORK], data: { result: 'Label checked.' } }), { who: 'carol' });
  v['out-of-order'] = { ...base, description: 'A record whose predecessor has not arrived is stored and acknowledged, held as pending, and applied after the predecessor is applied.',
    spec: ['delivery.md §3.2', 'delivery.md §8.2', 'delivery.md §8.4'], decisions: ['D4', 'D6'], receiver: bobReceiver,
    priorState: [{ direction: 'outgoing', record: 'r1', applyOutcome: 'applied', note: 'Bob opened the thread; r1 is his own stored outgoing record.' }],
    records: { r1, r2, r3 },
    steps: [
      step({ at: at(180), request: post('bob', r3.recordBytes), expect: expectReceipt(r3, 'bob', at(180), 'pending') }),
      step({ at: at(240), request: post('bob', r2.recordBytes), expect: { ...expectReceipt(r2, 'bob', at(240), 'applied'), afterApply: [{ record: r3.envelope.id, applyOutcome: 'applied' }] } }),
    ],
    finalState: { threadHead: r3.envelope.id, applyOrder: [r1.envelope.id, r2.envelope.id, r3.envelope.id], rejectionRecords: 0 } };

  const r3lonely = await record(envelope({ name: 'ooo-lonely-complete', from: 'carol', to: ['bob'], thread: r1.envelope.id, inReplyTo: uuid('ooo-never-arrives'), time: at(120), expires: at(days(14)), type: WORK + '#complete', required: [WORK], data: { result: 'Label checked.' } }), { who: 'carol' });
  v['out-of-order-hold-deadline'] = { ...base, description: 'A pending record whose predecessor never arrives is refused with missing-predecessor at its hold deadline: the earlier of its expires (here 14 days out) and storedAt + the 7-day hold window. It stays stored and its receipt stands.',
    spec: ['delivery.md §8.2', 'delivery.md §5.3'], decisions: ['D6'], receiver: bobReceiver,
    priorState: [{ direction: 'outgoing', record: 'r1', applyOutcome: 'applied' }], records: { r1, r3lonely },
    steps: [
      step({ at: at(180), request: post('bob', r3lonely.recordBytes), expect: expectReceipt(r3lonely, 'bob', at(180), 'pending') }),
      step({ at: at(days(WINDOW_DAYS) - 1, at(180)), event: 'one second before the hold deadline', expect: { applyOutcome: 'pending' } }),
      step({ at: at(days(WINDOW_DAYS), at(180)), event: 'hold deadline (storedAt + 7 days) reached', expect: {
        applyOutcome: 'refused', rejectionRecord: rejectionExpect(r3lonely, 'bob', 'missing-predecessor') } }),
    ],
    note: 'If expires came first, the code would be expired-before-apply instead.' };

  // Predecessor held as pending (not yet applied): dependent record must also stay pending until predecessor finishes.
  const m1 = await record(envelope({ name: 'chain-m1', from: 'bob', to: ['carol'], type: CORE + '#message', required: [], data: { text: 'First.' } }), { who: 'bob' });
  const m2 = await record(envelope({ name: 'chain-m2', from: 'bob', to: ['carol'], thread: m1.envelope.id, inReplyTo: m1.envelope.id, time: at(30), type: CORE + '#message', required: [], data: { text: 'Second.' } }), { who: 'bob' });
  const m3 = await record(envelope({ name: 'chain-m3', from: 'bob', to: ['carol'], thread: m1.envelope.id, inReplyTo: m2.envelope.id, time: at(60), type: CORE + '#message', required: [], data: { text: 'Third.' } }), { who: 'bob' });
  v['out-of-order-pending-predecessor'] = { ...base, description: 'A record whose predecessor is stored with outcome pending stays pending until that predecessor reaches a final outcome, then the chain applies in causal order.',
    spec: ['delivery.md §8.2', 'delivery.md §8.4'], decisions: ['D4', 'D6'], receiver: carolReceiver,
    records: { m1, m2, m3 },
    steps: [
      step({ at: at(120), request: post('carol', m2.recordBytes), expect: expectReceipt(m2, 'carol', at(120), 'pending') }),
      step({ at: at(180), request: post('carol', m3.recordBytes), expect: expectReceipt(m3, 'carol', at(180), 'pending'), note: 'm2 is stored but still pending, so m3 must stay pending.' }),
      step({ at: at(240), request: post('carol', m1.recordBytes), expect: { ...expectReceipt(m1, 'carol', at(240), 'applied'),
        afterApply: [{ record: m2.envelope.id, applyOutcome: 'applied' }, { record: m3.envelope.id, applyOutcome: 'applied' }] } }),
    ],
    finalState: { applyOrder: [m1.envelope.id, m2.envelope.id, m3.envelope.id], rejectionRecords: 0 } };

  // Predecessor refused on apply: dependent waiting record is applied normally and judged by its own type logic (stale-head for a handoff).
  const refOpen = await record(envelope({ name: 'refpred-open', from: 'bob', to: ['carol'], type: HANDOFF, required: [WORK], data: handoffData }), { who: 'bob' });
  const refAcceptBad = await record(envelope({ name: 'refpred-accept-bad', from: 'carol', to: ['bob'], thread: refOpen.envelope.id, inReplyTo: refOpen.envelope.id, time: at(60), type: WORK + '#accept', required: [WORK], data: { unexpected: true } }), { who: 'carol' });
  const refComplete = await record(envelope({ name: 'refpred-complete', from: 'carol', to: ['bob'], thread: refOpen.envelope.id, inReplyTo: refAcceptBad.envelope.id, time: at(120), type: WORK + '#complete', required: [WORK], data: { result: 'Label checked.' } }), { who: 'carol' });
  v['out-of-order-refused-predecessor'] = { ...base, description: 'When a pending record\'s predecessor arrives and is refused (invalid-data), the waiting dependent record is applied normally and judged by its own type logic: for a handoff its inReplyTo is not the thread head, yielding stale-head.',
    spec: ['delivery.md §8.2', 'delivery.md §8.3', 'delivery.md §8.4', 'delivery.md §5.3'], decisions: ['D4', 'D6'], receiver: bobReceiver,
    priorState: [{ direction: 'outgoing', record: 'refOpen', applyOutcome: 'applied', note: 'Bob opened the thread; refOpen is his own stored outgoing record.' }],
    records: { refOpen, refAcceptBad, refComplete },
    steps: [
      step({ at: at(180), request: post('bob', refComplete.recordBytes), expect: expectReceipt(refComplete, 'bob', at(180), 'pending') }),
      step({ at: at(240), request: post('bob', refAcceptBad.recordBytes), expect: { ...expectReceipt(refAcceptBad, 'bob', at(240), 'refused'),
        rejectionRecord: rejectionExpect(refAcceptBad, 'bob', 'invalid-data'),
        afterApply: [{ record: refComplete.envelope.id, applyOutcome: 'refused', rejectionRecord: rejectionExpect(refComplete, 'bob', 'stale-head') }] } }),
    ],
    finalState: { threadHead: refOpen.envelope.id, stored: [refOpen.envelope.id, refComplete.envelope.id, refAcceptBad.envelope.id], rejectionRecords: 2 } };

  // Stale head: carol sends accept (r2) then, racing, a decline (r4) that still points at r1.
  const r4 = await record(envelope({ name: 'stale-decline', from: 'carol', to: ['bob'], thread: r1.envelope.id, inReplyTo: r1.envelope.id, time: at(90), type: WORK + '#decline', required: [WORK], data: {} }), { who: 'carol' });
  const exampleRejection = await rejectionRecord({ name: 'stale-rejection', refused: r4, by: 'bob', code: 'stale-head', time: at(300) });
  v['stale-head'] = { ...base, description: 'A record whose inReplyTo names a known record that is no longer the head is stored and acknowledged, then refused with a signed rejection record into the thread. The receipt does not change.',
    spec: ['delivery.md §8.3', 'delivery.md §5.3', 'delivery.md §3'], decisions: ['D4', 'D6'], receiver: bobReceiver,
    priorState: [{ direction: 'outgoing', record: 'r1', applyOutcome: 'applied' }], records: { r1, r2, r4, exampleRejection },
    steps: [
      step({ at: at(240), request: post('bob', r2.recordBytes), expect: expectReceipt(r2, 'bob', at(240), 'applied') }),
      step({ at: at(300), request: post('bob', r4.recordBytes), expect: { ...expectReceipt(r4, 'bob', at(300), 'refused'), rejectionRecord: rejectionExpect(r4, 'bob', 'stale-head') } }),
    ],
    finalState: { threadHead: r2.envelope.id, stored: [r1.envelope.id, r2.envelope.id, r4.envelope.id], outbox: ['one rejection record to acct:carol@vectors.test, delivered under delivery.md §7'] },
    exampleNote: 'records.exampleRejection is one valid rejection record signed with bob\'s provider test key. Signatures are randomized, so a conforming receiver produces different bytes; compare the fields in expect.rejectionRecord.' };

  // Unknown type.
  const unknown = await record(envelope({ name: 'unknown-type', from: 'bob', to: ['carol'], type: 'https://vectors.test/ext/survey/v1#question', required: [], data: { question: 'Which label?' } }), { who: 'bob' });
  v['unknown-type'] = { ...base, description: 'A record of a type the receiver does not implement, not covered by required[], is stored and acknowledged. Its outcome is unsupported. A rejection record with unsupported-type is allowed but not required.',
    spec: ['delivery.md §3.2', 'delivery.md §3.3'], decisions: ['D4', 'D6'], receiver: carolReceiver, records: { unknown },
    steps: [step({ at: at(30), request: post('carol', unknown.recordBytes), expect: { ...expectReceipt(unknown, 'carol', at(30), 'unsupported'), rejectionRecord: { optional: true, ...rejectionExpect(unknown, 'carol', 'unsupported-type') } } })] };

  // ---- pre-store rejections, one code each ----
  const pre = async (code, status, description, build, extra = {}) => {
    const { request, records = {}, steps } = await build();
    v['reject-' + code] = { ...base, description, spec: ['delivery.md §3.1', 'delivery.md §5.1', 'https-binding.md §2.3', 'https-binding.md §3'], decisions: ['D6'],
      receiver: extra.receiver ?? carolReceiver, ...(extra.precondition ? { precondition: extra.precondition } : {}), records,
      steps: steps ?? [step({ at: at(30), request, expect: problem(status, code, extra.headers) })] };
  };
  const good = (name, opts = {}) => record(envelope({ name, from: 'bob', to: ['carol'], data: { text: 'Check the label.' }, ...opts }), { who: 'bob' });

  await pre('method-not-allowed', 405, 'GET on an inbox is refused.', async () => ({ request: { method: 'GET', url: inbox('carol'), headers: {} } }), { headers: { allow: 'POST' } });
  await pre('unsupported-media-type', 415, 'A valid record sent as application/json is refused.', async () => {
    const r = await good('media-type'); return { request: post('carol', r.recordBytes, 'application/json'), records: { r } };
  });
  await pre('too-large', 413, 'A body of 65,537 octets is refused before parsing.', async () => ({
    request: { ...post('carol', null), bodyFill: { octet: 'A', length: MAX_RECORD + 1 }, note: 'Runners build the body: 65,537 copies of "A".' } }));
  await pre('malformed', 400, 'Not a well-formed Wire v2 record: a body that is not a three-part compact JWS, a valid record with a trailing CRLF, and a correctly signed record without to[] (records.md §8 steps 1 and 9).', async () => {
    const r = await good('malformed');
    const { to, ...noToEnv } = envelope({ name: 'no-to', from: 'bob', to: ['carol'], data: { text: 'Check the label.' } });
    const noTo = await record(noToEnv, { who: 'bob' });
    return { records: { r, noTo }, steps: [
      step({ at: at(30), request: post('carol', 'eyJhbGciOiJFUzI1NiJ9.bm90LWEtcmVjb3Jk'), expect: problem(400, 'malformed') }),
      step({ at: at(31), request: post('carol', r.recordBytes + '\r\n'), expect: problem(400, 'malformed') }),
      step({ at: at(32), request: post('carol', noTo.recordBytes), expect: problem(400, 'malformed') }),
    ] };
  });
  await pre('bad-header', 400, 'A v1-style kid (an acct: address, not an HTTPS key URL) is refused.', async () => {
    const env = envelope({ name: 'v1-kid', from: 'bob', to: ['carol'], data: { text: 'Check the label.' } });
    const payloadUtf8 = JSON.stringify(env);
    const recordBytes = await signBytes(payloadUtf8, { who: 'bob', header: { kid: addr('bob') } });
    return { request: post('carol', recordBytes), records: { r: { envelope: env, payloadUtf8, payloadSha256: sha256(payloadUtf8), recordBytes } } };
  });
  await pre('unsupported-alg', 400, 'alg HS256 is not on the allow-list.', async () => {
    const env = envelope({ name: 'hs256', from: 'bob', to: ['carol'], data: { text: 'Check the label.' } });
    const payloadUtf8 = JSON.stringify(env);
    const recordBytes = await signBytes(payloadUtf8, { who: 'bob', alg: 'HS256' });
    return { request: post('carol', recordBytes), records: { r: { envelope: env, payloadUtf8, recordBytes } } };
  });
  await pre('unknown-key', 403, 'A record signed by a key in an identity document carol has not pinned is refused. The receiver does not fetch the document (D2).', async () => {
    const r = await record(envelope({ name: 'mallory', from: 'mallory', to: ['carol'], data: { text: 'Check the label.' } }), { who: 'mallory' });
    return { request: post('carol', r.recordBytes), records: { r } };
  }, { });
  await pre('bad-signature', 400, 'The payload segment was replaced after signing.', async () => {
    const r = await good('tampered');
    const tamperedEnv = { ...r.envelope, data: { text: 'Something else.' } };
    const [h, , s] = r.recordBytes.split('.');
    const recordBytes = [h, Buffer.from(JSON.stringify(tamperedEnv)).toString('base64url'), s].join('.');
    return { request: post('carol', recordBytes), records: { original: r, tampered: { envelope: tamperedEnv, recordBytes } } };
  });
  await pre('unsupported-version', 400, 'A correctly signed record with darep "3".', async () => {
    const r = await record({ ...envelope({ name: 'ack3', from: 'bob', to: ['carol'], data: { text: 'Check the label.' } }), darep: '3' }, { who: 'bob' });
    return { request: post('carol', r.recordBytes), records: { r } };
  });
  await pre('signer-mismatch', 403, 'Signed with dave\'s pinned key but claiming source acct:bob@vectors.test.', async () => {
    const r = await record(envelope({ name: 'dave-as-bob', from: 'bob', to: ['carol'], data: { text: 'Check the label.' } }), { who: 'dave' });
    return { request: post('carol', r.recordBytes), records: { r } };
  });
  await pre('key-not-valid', 403, 'Signed with bob\'s sig-old key, whose validity window ended on 2026-06-01, for a record with time 2026-11-20.', async () => {
    const r = await record(envelope({ name: 'old-key', from: 'bob', to: ['carol'], data: { text: 'Check the label.' } }), { who: 'bob', key: 'sig-old' });
    return { request: post('carol', r.recordBytes), records: { r } };
  });
  await pre('wrong-recipient', 403, 'Three ways to name the wrong recipient: a record addressed only to dave delivered with Darep-Recipient carol (R12), a request with no Darep-Recipient header (C1), and Darep-Recipient naming an address carol\'s provider does not host (C1 before signature verification on a multi-tenant receiver, or R12 after signature verification).', async () => {
    const r = await record(envelope({ name: 'for-dave', from: 'bob', to: ['dave'], data: { text: 'Check the label.' } }), { who: 'bob' });
    const ok = await good('no-recipient-header');
    return { records: { r, ok }, steps: [
      step({ at: at(30), request: post('carol', r.recordBytes), expect: problem(403, 'wrong-recipient') }),
      step({ at: at(31), request: post('carol', ok.recordBytes, 'application/jose', null), expect: problem(403, 'wrong-recipient') }),
      step({ at: at(32), request: post('carol', r.recordBytes, 'application/jose', addr('dave')), expect: problem(403, 'wrong-recipient'),
        note: 'acct:dave@vectors.test is in to[] but not hosted by this receiver. A receiver MAY return wrong-recipient at C1 (before signature verification, e.g. a multi-tenant provider with per-address pins) or at R12.' }),
    ] };
  });
  await pre('id-conflict', 409, 'A second record with the same source and id but different payload bytes is refused, and the first stays stored unchanged.', async () => {
    const first = await good('conflict');
    const second = await record({ ...first.envelope, data: { text: 'Changed message.' } }, { who: 'bob' });
    return { records: { first, second }, steps: [
      step({ at: at(30), request: post('carol', first.recordBytes), expect: expectReceipt(first, 'carol', at(30), 'applied') }),
      step({ at: at(60), request: post('carol', second.recordBytes), expect: { ...problem(409, 'id-conflict'), stored: 'unchanged' } }),
    ] };
  });
  await pre('not-yet-valid', 425, 'time is 10 minutes ahead of the receiver clock (skew allowance is 5 minutes). Transient.', async () => {
    const r = await good('future', { time: at(600) });
    return { request: post('carol', r.recordBytes), records: { r } };
  });
  await pre('expired', 422, 'Two expired records: one with a short expires in the past, one with the default 7-day expires whose time is older than 7 days plus the skew allowance.', async () => {
    const a = await good('expired-explicit', { time: at(-3600), expires: at(-600) });
    const b = await good('expired-default', { time: at(-(days(WINDOW_DAYS) + SKEW_S + 60)) });
    return { records: { a, b }, steps: [
      step({ at: at(30), request: post('carol', a.recordBytes), expect: problem(422, 'expired') }),
      step({ at: at(31), request: post('carol', b.recordBytes), expect: problem(422, 'expired') }),
    ] };
  });
  await pre('unsupported-extension', 422, 'required[] lists an extension carol does not implement.', async () => {
    const r = await good('needs-escrow', { required: ['https://vectors.test/ext/escrow/v1'] });
    return { request: post('carol', r.recordBytes), records: { r } };
  });
  await pre('rate-limited', 429, 'The receiver is configured as over quota for bob. Transient, with Retry-After.', async () => {
    const r = await good('quota'); return { request: post('carol', r.recordBytes), records: { r } };
  }, { precondition: 'Receiver quota for source acct:bob@vectors.test is exhausted.', headers: { 'retry-after': '<integer seconds, SHOULD be present>' } });
  await pre('unavailable', 503, 'The receiver cannot commit (storage forced to fail). It must not issue a receipt. Transient.', async () => {
    const r = await good('no-storage'); return { request: post('carol', r.recordBytes), records: { r } };
  }, { precondition: 'Receiver storage commit is forced to fail.' });

  return v;
}

function rejectionExpect(refused, by, code) {
  return {
    typ: TYP.rejection, signedBy: `a key of ${addr(by)} with purpose provider`, deliveredTo: refused.envelope.source,
    equals: { darep: '2', source: addr(by), type: CORE + '#rejection', to: [refused.envelope.source], thread: refused.envelope.thread,
      inReplyTo: refused.envelope.id, 'data.code': code },
    absent: ['grant'], present: ['expires'],
  };
}
// Rejection record per records.md §4.5, signed with a provider-purpose key (delivery.md §5.3).
async function rejectionRecord({ name, refused, by, code, time }) {
  const env = { darep: '2', id: uuid(name), source: addr(by), type: CORE + '#rejection', time, to: [refused.envelope.source],
    thread: refused.envelope.thread, inReplyTo: refused.envelope.id, expires: at(days(WINDOW_DAYS), time), ext: {}, required: [],
    data: { code, detail: 'The thread head moved; read the thread again.' } };
  return record(env, { who: by, key: 'rcpt-1', typ: TYP.rejection });
}

// ---------- sender vectors ----------

async function senderVectors() {
  const v = {};
  const base = { role: 'sender', clock: 'Each step has "at": the sender clock when the attempt is made. Runners inject it and act as the receiving endpoint.' };
  const sender = { address: addr('bob'), signingKeys: [kid('bob', 'sig-1')], pinned: [addr('carol')] };
  const out = await record(envelope({ name: 'sender-outgoing', from: 'bob', to: ['carol'], data: { text: 'Check the label.' } }), { who: 'bob' });
  const ok = await receipt(receiptPayload({ name: 'sender-ok', rec: out, receiver: 'carol', storedAt: at(40) }), { who: 'carol' });
  const sameBytes = { request: { method: 'POST', url: inbox('carol'), headers: { 'content-type': 'application/jose', 'darep-recipient': addr('carol') }, bodyEqualsRecord: 'out' } };

  // Each bad receipt names the code the records procedure (records.md §8) returns for it; --check enforces that.
  const bad = async (label, verifyCode, patch, opts = { who: 'carol' }) => {
    const p = { ...receiptPayload({ name: 'bad-' + label, rec: out, receiver: 'carol', storedAt: at(40) }), ...patch };
    for (const k of Object.keys(patch)) if (patch[k] === undefined) delete p[k];
    return { label, verifyCode, ...(await receipt(p, opts)) };
  };
  const okData = { sha256: out.payloadSha256, storedAt: at(40) };
  const mismatches = [
    await bad('wrong-sha256', 'receipt-mismatch', { data: { ...okData, sha256: sha256('not the payload') } }),
    await bad('wrong-inReplyTo', 'receipt-mismatch', { inReplyTo: uuid('some-other-record') }),
    await bad('predates-record', 'receipt-mismatch', { time: at(-600), data: { ...okData, storedAt: at(-600) } }),
    await bad('wrong-source', 'signer-mismatch', { source: addr('dave') }),
    await bad('wrong-to', 'wrong-recipient', { to: [addr('dave')] }),
    await bad('extra-data-member', 'malformed', { data: { ...okData, accepted: true } }),
    await bad('non-empty-ext', 'malformed', { ext: { 'https://vectors.test/ext/trace/v1': 'x' } }),
    await bad('records-key', 'key-not-valid', {}, { who: 'carol', key: 'sig-1' }),
  ];
  // Step spacing doubles (gaps 2, 4, 8, 16, 32, 64, 128, 256 s) so a doubling sender with up to 20% jitter is never forced early.
  const mismatchAt = i => 40 + 2 * (2 ** i - 1);
  v['receipt-mismatch'] = { ...base, description: 'Each response is 200 with a receipt that fails delivery.md §7.4. None marks the delivery delivered. Each mismatched receipt is kept as evidence, and every retry sends the identical record bytes. Mandatory backoff bounds are separate from SHOULD-level doubling profile expectations. The last attempt gets a valid receipt.',
    spec: ['delivery.md §7.4', 'delivery.md §7.2', 'delivery.md §9.2', 'https-binding.md §2.2'], decisions: ['D4', 'NC1'], sender, records: { out },
    retryProfile: { initialBackoffSeconds: 1, multiplier: 2, jitterPercent: 0, level: 'SHOULD' },
    steps: [
      ...mismatches.map((m, i) => step({ at: at(mismatchAt(i)), ...sameBytes, respond: { status: 200, headers: { 'content-type': 'application/jose' }, body: m.receiptBytes, receiptPayload: m.payload, mismatch: m.label },
        expect: { delivery: 'queued', attemptResult: 'receipt-mismatch', verifyCode: m.verifyCode, evidenceKept: 'receipt bytes', nextAttemptNotBefore: at(mismatchAt(i) + 1),
          backoff: { minimumSeconds: 1, nonDecreasing: true },
          should: { backoffSeconds: 2 ** i, nextAttemptAt: at(mismatchAt(i) + 2 ** i) } } })),
      step({ at: at(mismatchAt(mismatches.length)), ...sameBytes, respond: { status: 200, headers: { 'content-type': 'application/jose' }, body: ok.receiptBytes, receiptPayload: ok.payload },
        expect: { delivery: 'delivered', receiptStored: 'byte-identical to respond.body' } }),
    ] };

  // Dave's receipt passes records RC-1 because Dave is in out.to, but cannot acknowledge delivery to Carol.
  const multiOut = await record(envelope({ name: 'sender-multi-outgoing', from: 'bob', to: ['carol', 'dave'], data: { text: 'Check both labels.' } }), { who: 'bob' });
  const daveReceipt = await receipt(receiptPayload({ name: 'sender-other-recipient', rec: multiOut, receiver: 'dave', storedAt: at(40) }), { who: 'dave', key: 'sig-1' });
  const carolReceipt = await receipt(receiptPayload({ name: 'sender-multi-ok', rec: multiOut, receiver: 'carol', storedAt: at(42) }), { who: 'carol' });
  v['receipt-other-recipient'] = { ...base,
    description: 'A record is addressed to Carol and Dave. Dave signs a fully correlated receipt with his provider-purpose test key. Records §8 accepts it, but delivery to Carol fails §7.4 rule 2. Keep the receipt and retry unchanged bytes. The separate receipt-mismatch scenario retains its signer-mismatch case.',
    spec: ['records.md §8', 'delivery.md §7.4', 'delivery.md §7.1', 'delivery.md §9.2'], decisions: ['D4', 'NC1'],
    sender: { ...sender, pinned: [addr('carol'), addr('dave')] }, records: { out: multiOut },
    steps: [
      step({ at: at(40), ...sameBytes, respond: { status: 200, headers: { 'content-type': 'application/jose' }, body: daveReceipt.receiptBytes, receiptPayload: daveReceipt.payload, mismatch: 'other-recipient' },
        expect: { recordsVerdict: 'accept', delivery: 'queued', attemptResult: 'receipt-mismatch', verifyCode: 'receipt-mismatch', evidenceKept: 'receipt bytes', nextAttemptNotBefore: at(41) } }),
      step({ at: at(42), ...sameBytes, respond: { status: 200, headers: { 'content-type': 'application/jose' }, body: carolReceipt.receiptBytes, receiptPayload: carolReceipt.payload },
        expect: { recordsVerdict: 'accept', delivery: 'delivered', receiptStored: 'byte-identical to respond.body' } }),
    ] };

  v['retry-same-bytes'] = { ...base, description: 'Transient failures are retried with backoff, honoring Retry-After as a one-attempt floor without advancing the backoff sequence, and every attempt sends the same record bytes.',
    spec: ['delivery.md §7.1', 'delivery.md §7.2', 'https-binding.md §3'], decisions: ['NC1'], sender, records: { out },
    steps: [
      step({ at: at(30), ...sameBytes, respond: { status: 503, headers: { 'content-type': 'application/problem+json', 'retry-after': '20' }, body: JSON.stringify({ type: PROBLEM + 'unavailable', title: 'Unavailable', status: 503, code: 'unavailable' }) },
        expect: { delivery: 'queued', attemptResult: 'transient', nextAttemptNotBefore: at(50), evidenceKept: 'status, retry-after, problem body' } }),
      step({ at: at(50), ...sameBytes, respond: { connection: 'reset before any response' }, expect: { delivery: 'queued', attemptResult: 'transient', nextAttemptNotBefore: at(51), note: 'Retry-After on step 0 was a floor for that one attempt only and did not count as a backoff step; the first backoff delay is at least 1 s.' } }),
      step({ at: at(60), ...sameBytes, respond: { status: 302, headers: { location: 'https://elsewhere.vectors.test/' } }, expect: { delivery: 'queued', attemptResult: 'transient', followedRedirect: false } }),
      step({ at: at(70), ...sameBytes, respond: { status: 200, headers: { 'content-type': 'application/jose' }, body: ok.receiptBytes, receiptPayload: ok.payload }, expect: { delivery: 'delivered' } }),
    ] };

  const dependent = await record(envelope({ name: 'sender-dependent', from: 'bob', to: ['carol'], thread: out.envelope.id, inReplyTo: out.envelope.id, time: at(10), type: CORE + '#message', required: [], data: { text: 'Any update?' } }), { who: 'bob' });
  v['permanent-rejection'] = { ...base, description: 'A permanent pre-store code ends the delivery at once. The problem body is kept. A queued later record in the same thread to the same recipient SHOULD be failed without being sent.',
    spec: ['delivery.md §7.3', 'delivery.md §5.1'], decisions: ['D6'], sender, records: { out, dependent },
    steps: [step({ at: at(30), ...sameBytes, respond: { status: 403, headers: { 'content-type': 'application/problem+json' }, body: JSON.stringify({ type: PROBLEM + 'unknown-key', title: 'Unknown key', status: 403, code: 'unknown-key' }) },
      expect: { delivery: 'failed', attemptResult: 'permanent', evidenceKept: 'status and problem body', furtherAttempts: 0, dependentRecords: { [dependent.envelope.id]: { should: 'failed without an attempt' } } } })] };

  v['status-fallback'] = { ...base, description: 'Without a recognized code the sender classifies by status: other 4xx permanent; 408, 425, 429, 5xx transient. A recognized code wins over its status. Deliberately inconsistent code/status pairs test sender robustness, not conforming receiver output.',
    spec: ['https-binding.md §3'], decisions: ['D6'], sender, records: { out },
    cases: [
      { respond: { status: 400, headers: { 'content-type': 'application/problem+json' }, body: JSON.stringify({ type: PROBLEM + 'brand-new-code', title: 'Future', status: 400, code: 'brand-new-code' }) }, expect: { attemptResult: 'permanent' } },
      { respond: { status: 500, headers: { 'content-type': 'application/problem+json' }, body: JSON.stringify({ type: PROBLEM + 'malformed', title: 'Malformed', status: 500, code: 'malformed' }) }, expect: { attemptResult: 'permanent' } },
      { respond: { status: 400, headers: { 'content-type': 'application/problem+json' }, body: JSON.stringify({ type: PROBLEM + 'unavailable', title: 'Unavailable', status: 400, code: 'unavailable' }) }, expect: { attemptResult: 'transient' } },
      { respond: { status: 404 }, expect: { attemptResult: 'permanent' } },
      { respond: { status: 500 }, expect: { attemptResult: 'transient' } },
      { respond: { status: 408 }, expect: { attemptResult: 'transient' } },
      { respond: { status: 425, headers: { 'content-type': 'application/problem+json' }, body: JSON.stringify({ type: PROBLEM + 'not-yet-valid', title: 'Not yet valid', status: 425, code: 'not-yet-valid' }) }, expect: { attemptResult: 'transient' } },
      { respond: { status: 201, headers: { 'content-type': 'application/jose' }, body: ok.receiptBytes }, expect: { attemptResult: 'receipt-mismatch', note: '200 is the only success status.' } },
    ] };

  v['give-up-at-expiry'] = { ...base, description: 'A delivery that only ever meets transient failures is marked failed at its expires plus the skew allowance (here time + 7 days + 300 s). After that the sender accepts no receipt for it (records.md TM-4a).',
    spec: ['delivery.md §7.3'], decisions: ['D4'], sender, records: { out },
    steps: [
      step({ at: at(days(WINDOW_DAYS) + SKEW_S - 60), ...sameBytes, respond: { status: 503 }, expect: { delivery: 'queued', attemptResult: 'transient' } }),
      step({ at: at(days(WINDOW_DAYS) + SKEW_S + 1), event: 'expires plus skew allowance has passed', expect: { delivery: 'failed', furtherAttempts: 0 } }),
    ] };
  return v;
}

// ---------- harness self-test fixtures ----------
// These are not conformance vectors. They exercise runner capabilities (source-qualified record keys, binary request
// bodies, raw HTTP response framing) with behaviour the frozen text already fixes, so each runner can show that a
// deliberately wrong implementation fails them. Runners load them only from their own self-tests.

const SELFTEST = 'Harness self-test fixture: it checks the vector runners and is not a conformance vector.';
const raw = {
  text: text => ({ text }),
  // HTTP/1.1 chunked transfer coding (RFC 9112 §7.1) of the given text, in chunks of the given sizes.
  chunked: (text, sizes) => {
    if (!/^[\x20-\x7e]*$/.test(text)) throw new Error('chunked() takes printable ASCII only; use base64 segments otherwise');
    const bytes = Buffer.from(text, 'ascii');
    const out = [];
    let offset = 0;
    for (const size of sizes) {
      if (!(size > 0)) throw new Error('chunk sizes must be positive');
      const part = bytes.subarray(offset, offset + size);
      offset += part.length;
      out.push({ text: part.length.toString(16) + '\r\n' + part.toString('ascii') + '\r\n' });
    }
    if (offset !== bytes.length) throw new Error('chunk sizes do not cover the body');
    out.push({ text: '0\r\n\r\n' });
    return out;
  },
};

async function selftestReceiverVectors() {
  const v = {};
  const base = { role: 'receiver', selftest: SELFTEST, clock: 'Each step has "at": the receiver clock at that moment. Runners inject it.' };
  const carolReceiver = { address: addr('carol'), inbox: inbox('carol'), signingKeys: [kid('carol', 'sig-1'), kid('carol', 'rcpt-1')], pinned: [addr('bob'), addr('dave')], extensions: [CORE] };

  // Two records with the same id from two sources are two dedupe keys (delivery.md §6). Their outcomes differ, so a
  // runner that finds stored records by id alone inspects the wrong one.
  const shared = uuid('selftest-shared-id');
  const fromBob = await record(envelope({ name: 'selftest-shared-id', from: 'bob', to: ['carol'], data: { text: 'From Bob.' } }), { who: 'bob' });
  const fromDave = await record(envelope({ name: 'selftest-shared-id', from: 'dave', to: ['carol'], time: at(5),
    type: 'https://vectors.test/ext/survey/v1#question', data: { question: 'From Dave, same id.' } }), { who: 'dave' });
  if (fromBob.envelope.id !== shared || fromDave.envelope.id !== shared) throw new Error('self-test records must share one id');
  const bobKey = { source: addr('bob'), id: shared };
  const daveKey = { source: addr('dave'), id: shared };
  v['same-id-two-sources'] = { ...base, description: 'Bob and Dave each send a record with the same id. They are different dedupe keys, so both are stored and acknowledged. Bob\'s core message is applied; Dave\'s record of an unknown type is unsupported. Runners must address stored records by (source, id).',
    spec: ['delivery.md §6', 'delivery.md §3.3'], receiver: carolReceiver, records: { fromBob, fromDave },
    steps: [
      step({ at: at(30), request: post('carol', fromBob.recordBytes), expect: expectReceipt(fromBob, 'carol', at(30), 'applied') }),
      step({ at: at(40), request: post('carol', fromDave.recordBytes), expect: expectReceipt(fromDave, 'carol', at(40), 'unsupported') }),
      step({ at: at(50), event: 'no delivery; inspect both records', expect: { afterApply: [
        { record: shared, source: addr('bob'), applyOutcome: 'applied' },
        { record: shared, source: addr('dave'), applyOutcome: 'unsupported' },
      ] } }),
    ],
    finalState: { applyOrder: [bobKey], stored: [bobKey, daveKey] } };

  // bodyBase64 carries exact request octets, including octets that are not UTF-8.
  const plain = await record(envelope({ name: 'selftest-binary-plain', from: 'bob', to: ['carol'], data: { text: 'Sent as base64.' } }), { who: 'bob' });
  const prefixed = await record(envelope({ name: 'selftest-binary-prefixed', from: 'bob', to: ['carol'], data: { text: 'Preceded by two octets that are not UTF-8.' } }), { who: 'bob' });
  const binaryPost = bytes => { const { body, ...rest } = post('carol', null); return { ...rest, bodyBase64: bytes.toString('base64') }; };
  v['binary-body'] = { ...base, description: 'Request bodies given as bodyBase64 are sent octet for octet. A record sent that way is accepted as usual. The same kind of record preceded by the octets 0xFF 0xFE is not a compact JWS and is refused as malformed before storage; a receiver that drops octets it cannot decode would accept it.',
    spec: ['delivery.md §3.1', 'https-binding.md §2.1'], receiver: carolReceiver, records: { plain, prefixed },
    steps: [
      step({ at: at(30), request: binaryPost(Buffer.from(plain.recordBytes, 'ascii')), expect: expectReceipt(plain, 'carol', at(30), 'applied') }),
      step({ at: at(40), request: binaryPost(Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(prefixed.recordBytes, 'ascii')])), expect: problem(400, 'malformed') }),
    ] };
  return v;
}

async function selftestSenderVectors() {
  const v = {};
  const base = { role: 'sender', selftest: SELFTEST, clock: 'Each step has "at": the sender clock when the attempt is made. Runners inject it and act as the receiving endpoint.' };
  const sender = { address: addr('bob'), signingKeys: [kid('bob', 'sig-1')], pinned: [addr('carol')] };
  const out = await record(envelope({ name: 'selftest-raw-out', from: 'bob', to: ['carol'], data: { text: 'Answered with raw framing.' } }), { who: 'bob' });
  const ok = await receipt(receiptPayload({ name: 'selftest-raw-ok', rec: out, receiver: 'carol', storedAt: at(40) }), { who: 'carol' });
  const sameBytes = { request: { method: 'POST', url: inbox('carol'), headers: { 'content-type': 'application/jose', 'darep-recipient': addr('carol') }, bodyEqualsRecord: 'out' } };
  v['raw-framing'] = { ...base, description: 'The runner answers with exact response octets. A connection reset in the middle of the response head is a transient failure. A receipt sent with chunked transfer coding, split across chunks, is a delivery; a sender that does not remove the chunk framing sees a body that is not the receipt.',
    spec: ['https-binding.md §2.2', 'https-binding.md §3', 'delivery.md §7.2'], sender, records: { out },
    steps: [
      step({ at: at(30), ...sameBytes, respond: { raw: { segments: [raw.text('HTTP/1.1 200 OK\r\nContent-Type: applic')], end: 'reset' } },
        expect: { delivery: 'queued', attemptResult: 'transient' } }),
      step({ at: at(60), ...sameBytes, respond: { raw: {
        segments: [raw.text('HTTP/1.1 200 OK\r\nContent-Type: application/jose\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n'),
          ...raw.chunked(ok.receiptBytes, [100, 300, ok.receiptBytes.length - 400])],
        end: 'close', decodedBody: ok.receiptBytes } },
      expect: { delivery: 'delivered', attemptResult: 'delivered', receiptStored: 'byte-identical to respond.raw.decodedBody' } }),
    ] };
  return v;
}

// ---------- check mode ----------

const RECORDS_CODES = new Set(['malformed', 'unsupported-alg', 'bad-header', 'unknown-key', 'bad-signature', 'unsupported-version',
  'signer-mismatch', 'key-not-valid', 'wrong-recipient', 'not-yet-valid', 'expired', 'unsupported-extension']);

async function verifyJws(token, docs, typ) {
  const h = decodeProtectedHeader(token);
  if (h.typ !== typ) throw new Error(`typ ${h.typ} != ${typ}`);
  const doc = docs.find(d => d.keys.some(k => k.id === h.kid));
  if (!doc) throw new Error('kid not in identities: ' + h.kid);
  const key = await importJWK({ ...doc.keys.find(k => k.id === h.kid).publicKeyJwk, alg: 'ES256' }, 'ES256');
  const { payload } = await compactVerify(token, key, { algorithms: ['ES256'] });
  return new TextDecoder('utf-8', { fatal: true }).decode(payload);
}

// Runs one JWS through records.md §8 and returns 'accept' or the rejection code.
function recordsVerdict(jws, context, docs) {
  try { verifyRecord(jws, context, docs); return 'accept'; } catch (e) { if (e.code) return e.code; throw e; }
}

async function check() {
  const ids = JSON.parse(await readFile(join(here, 'identities.json'), 'utf8'));
  const docs = ids.documents;
  validatePins(docs); // records.md P-0
  const pinnedDocs = who => docs.filter(d => (ids.pinnedBy[who] ?? []).some(a => d.addresses.includes(a)));
  let n = 0; let procedure = 0;
  const fail = msg => { throw new Error(msg); };
  const dirs = [['receiver', 'receiver'], ['sender', 'sender'], ['receiver', 'selftest/receiver'], ['sender', 'selftest/sender']];
  for (const [role, dir] of dirs) for (const f of (await readdir(join(here, dir))).filter(f => f.endsWith('.json'))) {
    const vec = JSON.parse(await readFile(join(here, dir, f), 'utf8'));
    // These records are built to fail signature verification against the published keys.
    const mustFail = { 'reject-bad-header.json': ['r'], 'reject-unsupported-alg.json': ['r'], 'reject-bad-signature.json': ['tampered'] };
    for (const [name, r] of Object.entries(vec.records ?? {})) {
      if (!r.recordBytes) continue;
      const typ = decodeProtectedHeader(r.recordBytes).typ;
      if (mustFail[f]?.includes(name)) {
        let failed = false;
        try { await verifyJws(r.recordBytes, docs, typ); } catch { failed = true; }
        if (!failed) fail(`${role}/${f} ${name}: expected verification to fail`);
        n++;
        continue;
      }
      const payload = await verifyJws(r.recordBytes, docs, typ);
      if (payload !== r.payloadUtf8) fail(`${role}/${f} ${name}: payload bytes differ`);
      if (r.payloadSha256 && sha256(payload) !== r.payloadSha256) fail(`${role}/${f} ${name}: digest differs`);
      if (JSON.stringify(JSON.parse(payload)) !== JSON.stringify(r.envelope)) fail(`${role}/${f} ${name}: envelope differs`);
      n++;
    }
    if (role === 'receiver') {
      // Every POSTed body goes through records.md §8 as this receiver would run it (delivery.md §3.1, rows R1–R14).
      const me = vec.receiver;
      const mine = pinnedDocs(me.address);
      for (const s of vec.steps ?? []) {
        const body = s.request?.bodyBase64 !== undefined ? Buffer.from(s.request.bodyBase64, 'base64').toString('latin1') : s.request?.body;
        const recipient = s.request?.headers?.['darep-recipient'];
        if (typeof body !== 'string' || !recipient || s.request.headers['content-type'] !== 'application/jose') continue; // carrier checks C1/C2
        const duplicate = s.expect.receiptBytesEqualStep !== undefined;
        const context = { mode: duplicate ? 'evidence' : 'admission', now: s.at, receiver: recipient,
          typ: [TYP.event, TYP.rejection], understood: [CORE, ...me.extensions] };
        let got = recordsVerdict(body, context, mine);
        if (got === 'accept' && duplicate && !JSON.parse(Buffer.from(body.split('.')[1], 'base64url')).to.includes(recipient)) got = 'wrong-recipient';
        const code = s.expect.problem?.code;
        const want = s.expect.status === 200 ? 'accept' : RECORDS_CODES.has(code) ? code : 'accept';
        const hostedElsewhere = recipient !== me.address && code === 'wrong-recipient';
        if (hostedElsewhere) { if (got !== 'accept') fail(`${role}/${f}: records procedure returned ${got} for an unhosted recipient`); }
        else if (got !== want) fail(`${role}/${f} at ${s.at}: records procedure returned ${got}, vector expects ${want}`);
        procedure++;
      }
      for (const [name, r] of Object.entries(vec.records ?? {})) {
        if (!r.recordBytes || decodeProtectedHeader(r.recordBytes).typ !== TYP.rejection) continue;
        const refused = Object.values(vec.records).find(x => x.envelope?.id === r.envelope.inReplyTo);
        const got = recordsVerdict(r.recordBytes, { mode: 'admission', now: r.envelope.time, receiver: r.envelope.to[0],
          typ: [TYP.event, TYP.rejection], understood: [CORE], answered: refused.recordBytes }, docs);
        if (got !== 'accept') fail(`${role}/${f} ${name}: example rejection record fails records.md §8: ${got}`);
        procedure++;
      }
    }
    if (role === 'sender') {
      // Every receipt the runner returns goes through records.md §8 as the sender, with the delivered record as R.
      const out = vec.records.out.recordBytes;
      for (const s of [...(vec.steps ?? []), ...(vec.cases ?? [])]) {
        // A raw response counts as a receipt only when its own head says 200 application/jose.
        const rawHead = s.respond?.raw ? Buffer.concat(s.respond.raw.segments.map(x => Buffer.from(x.text ?? '', 'utf8'))).toString('latin1').split('\r\n\r\n') : null;
        const rawIsReceipt = rawHead?.length > 1 && /^HTTP\/1\.1 200 /.test(rawHead[0]) && /\r\ncontent-type:\s*application\/jose\s*(\r\n|$)/i.test(rawHead[0]);
        const receiptBytes = s.respond?.raw ? (rawIsReceipt ? s.respond.raw.decodedBody : undefined) : s.respond?.body;
        if (!receiptBytes || (!s.respond.raw && s.respond.headers?.['content-type'] !== 'application/jose')) continue;
        const got = recordsVerdict(receiptBytes, { mode: 'admission', now: s.at ?? vec.steps?.[0]?.at ?? at(40), receiver: vec.sender.address,
          typ: TYP.receipt, understood: [CORE], answered: out }, pinnedDocs(vec.sender.address));
        const want = s.expect.recordsVerdict ?? s.expect.verifyCode ?? 'accept';
        if (got !== want) fail(`${role}/${f} ${s.respond.mismatch ?? ''}: records procedure returned ${got}, vector expects ${want}`);
        if (got === 'accept' && JSON.parse(Buffer.from(receiptBytes.split('.')[1], 'base64url')).source !== s.request?.headers?.['darep-recipient'] && s.request) {
          if (s.expect.attemptResult !== 'receipt-mismatch' || s.expect.delivery !== 'queued') {
            fail(`${role}/${f}: another recipient's valid receipt must be a delivery receipt-mismatch`);
          }
        }
        if (s.respond.receiptPayload) {
          const p = await verifyJws(s.respond.body, docs, TYP.receipt);
          if (JSON.stringify(JSON.parse(p)) !== JSON.stringify(s.respond.receiptPayload)) fail(`${role}/${f}: receipt payload differs`);
          n++;
        }
        procedure++;
      }
    }
  }
  console.log(`check ok: ${n} signatures verified, payload bytes and digests match; ${procedure} records.md §8 verdicts match the vectors`);
}

// ---------- main ----------

async function main() {
  KEYS = await loadOrCreateKeys();
  if (CHECK) return check();
  const docs = identityDocuments(KEYS);
  const pinned = { [addr('carol')]: [addr('bob'), addr('dave')], [addr('bob')]: [addr('carol'), addr('dave')] };
  await writeFile(join(here, 'identities.json'), JSON.stringify({
    warning: 'TEST ONLY. Public halves of the keys in test-keys.json. Identity documents in the shape of spec/records.md §5.1.',
    pinnedBy: pinned, unpinned: [addr('mallory')], documents: docs,
    inboxes: Object.fromEntries(Object.keys(PEOPLE).map(who => [addr(who), inbox(who)])),
    inboxesNote: 'Binding configuration (https-binding.md §1.1), exchanged out of band with the pin. Not part of any identity document.',
  }, null, 2) + '\n');
  const experimentalWork = new Set(['out-of-order', 'out-of-order-hold-deadline', 'out-of-order-refused-predecessor', 'stale-head']);
  const header = (name, role) => ({ vector: `delivery/${role}/${name}`, generatedBy: 'vectors/v2/delivery/generate.mjs', testOnly: true });
  for (const [role, build] of [['receiver', receiverVectors], ['sender', senderVectors]]) {
    await rm(join(here, role), { recursive: true, force: true });
    await mkdir(join(here, role), { recursive: true });
    const vecs = await build();
    for (const [name, body] of Object.entries(vecs)) {
      if (role === 'receiver' && experimentalWork.has(name)) {
        body.conformance = 'depends on the experimental work/v2 extension';
        body.receiver = { ...body.receiver, extensions: [CORE, WORK] };
      }
      await writeFile(join(here, role, name + '.json'), JSON.stringify({ ...header(name, role), ...body }, null, 2) + '\n');
    }
    console.log(`${role}: ${Object.keys(vecs).length} vectors`);
  }
  await rm(join(here, 'selftest'), { recursive: true, force: true });
  for (const [role, build] of [['receiver', selftestReceiverVectors], ['sender', selftestSenderVectors]]) {
    await mkdir(join(here, 'selftest', role), { recursive: true });
    const vecs = await build();
    for (const [name, body] of Object.entries(vecs)) {
      const head = { vector: `delivery/selftest/${role}/${name}`, generatedBy: 'vectors/v2/delivery/generate.mjs', testOnly: true };
      await writeFile(join(here, 'selftest', role, name + '.json'), JSON.stringify({ ...head, ...body }, null, 2) + '\n');
    }
    console.log(`selftest/${role}: ${Object.keys(vecs).length} harness fixtures`);
  }
}

await main();
