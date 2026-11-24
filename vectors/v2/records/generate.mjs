// Regenerates every file in vectors/v2/records/ from fixed inputs.
//
//   node vectors/v2/records/generate.mjs
//
// The output is byte-for-byte deterministic: test keys are derived from fixed seed strings and every
// signature uses deterministic ECDSA (RFC 6979), so a rerun on any machine produces identical files.
// Uses only Node built-ins. The spec is spec/records.md; check.mjs verifies the output against it.
//
// THE PRIVATE KEYS WRITTEN TO keys.json ARE PUBLIC TEST KEYS. NEVER USE THEM FOR ANYTHING REAL.

import { createECDH, createHash, createHmac, createPublicKey, verify as nodeVerify } from 'node:crypto';
import { mkdir, readdir, rm, writeFile } from 'node:fs/promises';

const here = new URL('./', import.meta.url);

// ---------- P-256 ECDSA with RFC 6979 deterministic nonces ----------

const N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551n;
const big = bytes => BigInt('0x' + Buffer.from(bytes).toString('hex'));
const be32 = n => Buffer.from(n.toString(16).padStart(64, '0'), 'hex');
const mod = (a, m) => ((a % m) + m) % m;
const sha256 = bytes => createHash('sha256').update(bytes).digest();
const hmac = (key, ...parts) => createHmac('sha256', key).update(Buffer.concat(parts.map(p => Buffer.from(p)))).digest();

function invert(a, m) {
  let [r0, r1, s0, s1] = [mod(a, m), m, 1n, 0n];
  while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }
  return mod(s0, m);
}
// Scalar multiplication of the base point, done by OpenSSL through ECDH key derivation.
function basePointTimes(scalar32) {
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(scalar32);
  const point = ecdh.getPublicKey(); // 0x04 || X || Y
  return { x: point.subarray(1, 33), y: point.subarray(33, 65) };
}
function nonce(d32, h1) {
  const h = be32(mod(big(h1), N)); // bits2octets for a 256-bit hash on a 256-bit curve
  let V = Buffer.alloc(32, 1);
  let K = Buffer.alloc(32, 0);
  K = hmac(K, V, [0], d32, h); V = hmac(K, V);
  K = hmac(K, V, [1], d32, h); V = hmac(K, V);
  for (;;) {
    V = hmac(K, V);
    const k = big(V);
    if (k >= 1n && k < N) return k;
    K = hmac(K, V, [0]); V = hmac(K, V);
  }
}
function ecdsaSign(d32, message) {
  const h1 = sha256(message);
  const d = big(d32);
  for (let k = nonce(d32, h1); ; k = nonce(d32, sha256(Buffer.concat([h1, be32(k)])))) {
    const r = mod(big(basePointTimes(be32(k)).x), N);
    const s = mod(invert(k, N) * (big(h1) + r * d), N);
    if (r && s) return Buffer.concat([be32(r), be32(s)]); // JWS form: R || S, 64 bytes (RFC 7518 §3.4)
  }
}
function selfTest() {
  // RFC 6979 appendix A.2.5, P-256 with SHA-256, message "sample".
  const d = Buffer.from('C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721', 'hex');
  const sig = ecdsaSign(d, Buffer.from('sample')).toString('hex').toUpperCase();
  const want = 'EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716' +
    'F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8';
  if (sig !== want) throw new Error('RFC 6979 self-test failed: ' + sig);
}

// ---------- fixed test identities ----------

function testKey(seed) {
  const d = be32(mod(big(sha256('DAREP vectors v2 TEST ONLY: ' + seed)), N - 1n) + 1n);
  const { x, y } = basePointTimes(d);
  const pub = { kty: 'EC', crv: 'P-256', x: x.toString('base64url'), y: y.toString('base64url') };
  return { seed, d, pub, priv: { ...pub, d: d.toString('base64url') } };
}

const NOW = '2026-11-20T12:00:00Z';
const T = '2026-11-20T11:58:00Z';        // ordinary record time, two minutes before NOW
const EXP = '2026-11-27T11:58:00Z';      // seven days after T (the SHOULD default)
const BOB = 'acct:bob@vectors.test';
const CAROL = 'acct:carol@vectors.test';
const DAVE = 'acct:dave@vectors.test';
const BOB_DOC = 'https://bob.vectors.test/.well-known/darep/bob';
const CAROL_DOC = 'https://carol.vectors.test/.well-known/darep/carol';
const DAVE_DOC = 'https://dave.vectors.test/.well-known/darep/dave';

const CORE = 'https://darep.org/ext/core/v2';
const WORK = 'https://darep.org/ext/work/v2';
const RESCHEDULE = 'https://darep.org/ext/reschedule/v2';
const UNDERSTOOD = [CORE, WORK, RESCHEDULE];

const keys = {
  bobOld: { ...testKey('bob sig-2026-05'), kid: BOB_DOC + '#sig-2026-05' },
  bob: { ...testKey('bob sig-2026-11'), kid: BOB_DOC + '#sig-2026-11' },
  bobProvider: { ...testKey('bob provider-2026-11'), kid: BOB_DOC + '#provider-2026-11' },
  bobRevoked: { ...testKey('bob sig-2026-01'), kid: BOB_DOC + '#sig-2026-01' },
  carol: { ...testKey('carol key-2026-11'), kid: CAROL_DOC + '#key-2026-11' },
  dave: { ...testKey('dave key-2026-11'), kid: DAVE_DOC + '#key-2026-11' },
  attacker: { ...testKey('attacker (never pinned)'), kid: null },
};

const identities = [
  {
    darep: '2', id: BOB_DOC, addresses: [BOB], updated: '2026-11-01T00:00:00Z',
    keys: [
      { id: keys.bobRevoked.kid, purpose: ['record'], publicKeyJwk: keys.bobRevoked.pub,
        validFrom: '2026-01-01T00:00:00Z', revoked: '2026-05-01T00:00:00Z' },
      { id: keys.bobOld.kid, purpose: ['record'], publicKeyJwk: keys.bobOld.pub,
        validFrom: '2026-05-01T00:00:00Z', validUntil: '2026-11-15T00:00:00Z' },
      { id: keys.bob.kid, purpose: ['record'], publicKeyJwk: keys.bob.pub, validFrom: '2026-11-01T00:00:00Z' },
      { id: keys.bobProvider.kid, purpose: ['provider'], publicKeyJwk: keys.bobProvider.pub,
        validFrom: '2026-11-01T00:00:00Z' },
    ],
  },
  {
    darep: '2', id: CAROL_DOC, addresses: [CAROL], updated: '2026-11-01T00:00:00Z',
    keys: [{ id: keys.carol.kid, purpose: ['record', 'provider'], publicKeyJwk: keys.carol.pub,
      validFrom: '2026-11-01T00:00:00Z' }],
  },
  {
    darep: '2', id: DAVE_DOC, addresses: [DAVE], updated: '2026-11-01T00:00:00Z',
    keys: [{ id: keys.dave.kid, purpose: ['record', 'provider'], publicKeyJwk: keys.dave.pub,
      validFrom: '2026-11-01T00:00:00Z' }],
  },
];

// ---------- helpers ----------

function uuid(label) {
  const b = sha256('DAREP vectors v2 uuid: ' + label).subarray(0, 16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = b.toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
const b64u = bytes => Buffer.from(bytes).toString('base64url');
const header = (kid, typ = 'darep-event+jws', alg = 'ES256') => JSON.stringify({ alg, kid, typ });
function compact(headerText, payloadBytes, key) {
  const input = b64u(headerText) + '.' + b64u(payloadBytes);
  const sig = ecdsaSign(key.d, Buffer.from(input, 'ascii'));
  const pem = createPublicKey({ key: key.pub, format: 'jwk' });
  if (!nodeVerify('sha256', Buffer.from(input), { key: pem, dsaEncoding: 'ieee-p1363' }, sig)) {
    throw new Error('generated signature does not verify');
  }
  return input + '.' + b64u(sig);
}
// Payload serializations deliberately differ (indent, key order) to show that no canonical form exists.
const pretty = v => Buffer.from(JSON.stringify(v, null, 1) + '\n');
const tight = v => Buffer.from(JSON.stringify(v));

const handoffId = uuid('handoff');
const handoff = {
  darep: '2',
  id: handoffId,
  source: BOB,
  type: WORK + '#handoff',
  time: T,
  to: [CAROL],
  thread: handoffId,
  inReplyTo: null,
  expires: EXP,
  ext: {},
  required: [WORK],
  grant: { id: 'grant-7f3a', actor: 'agent' },
  data: {
    summary: '合成預覽 🗓',
    nextStep: '核對荷蘭文標籤「één」。',
    expectedResult: '回覆一個明確結果。',
  },
};
const event = (overrides = {}) => ({ ...handoff, ...overrides });

const eventCtx = { mode: 'admission', now: NOW, receiver: CAROL, typ: 'darep-event+jws', understood: UNDERSTOOD };
const vectors = [];
function add(name, description, spec, { context = eventCtx, headerText, payload, key, jws, expected }) {
  const payloadBytes = Buffer.isBuffer(payload) ? payload : pretty(payload);
  const token = jws ?? compact(headerText ?? header(key.kid), payloadBytes, key);
  let payloadUtf8 = null;
  try { payloadUtf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(payloadBytes); } catch { /* not UTF-8 */ }
  vectors.push({
    name, description, spec, context,
    jws: token,
    headerUtf8: Buffer.from(token.split('.')[0], 'base64url').toString('utf8'),
    payloadUtf8,
    payloadHex: payloadUtf8 === null ? payloadBytes.toString('hex') : undefined,
    payloadSha256: sha256(Buffer.from(token.split('.')[1], 'base64url')).toString('hex'),
    expected,
  });
}
const accept = (payload, kid) => ({ verdict: 'accept', kid, record: JSON.parse(Buffer.from(payload).toString('utf8')) });
const reject = code => ({ verdict: 'reject', code });

// ---------- positive vectors ----------

{
  const p = pretty(handoff);
  add('positive/handoff', 'Opening handoff record from Bob to Carol, signed with the current record key.',
    '§4, §5, §8', { payload: p, key: keys.bob, expected: accept(p, keys.bob.kid) });
}
const handoffBytes = pretty(handoff);
const handoffSha = sha256(handoffBytes).toString('hex');
{
  const id = uuid('reschedule');
  const r = {
    darep: '2', id, source: BOB, type: RESCHEDULE + '#request', time: T, to: [CAROL], thread: id, inReplyTo: null,
    expires: EXP, ext: {}, required: [RESCHEDULE], grant: { id: 'grant-7f3a', actor: 'agent' },
    data: {
      activity: 'Tennis lesson', originalStart: '2026-11-24T09:00:00Z', durationMinutes: 60,
      slots: ['2026-11-25T09:00:00Z', '2026-11-26T18:30:00Z'],
    },
  };
  const p = tight(r);
  add('positive/reschedule', 'Opening reschedule request, serialized without whitespace.', '§4, §8',
    { payload: p, key: keys.bob, expected: accept(p, keys.bob.kid) });
}
{
  const r = {
    darep: '2', id: uuid('receipt'), source: CAROL, type: CORE + '#receipt', time: '2026-11-20T11:58:01Z',
    to: [BOB], thread: handoffId, inReplyTo: handoffId, ext: {}, required: [],
    data: { sha256: handoffSha, storedAt: '2026-11-20T11:58:01Z' },
  };
  const p = tight(r);
  add('positive/receipt', 'Carol\'s receipt for positive/handoff. data.sha256 is the SHA-256 of that vector\'s exact payload bytes.',
    '§4.4, §8', {
      context: { ...eventCtx, receiver: BOB, typ: 'darep-receipt+jws', answered: compact(header(keys.bob.kid), handoffBytes, keys.bob) },
      headerText: header(keys.carol.kid, 'darep-receipt+jws'), payload: p, key: keys.carol,
      expected: { ...accept(p, keys.carol.kid), receiptFor: 'positive/handoff' },
    });
}
{
  const r = {
    darep: '2', id: uuid('rejection'), source: CAROL, type: CORE + '#rejection', time: '2026-11-20T11:59:00Z',
    to: [BOB], thread: handoffId, inReplyTo: uuid('stale accept'), expires: '2026-11-27T11:59:00Z', ext: {}, required: [],
    data: { code: 'stale-head', detail: 'The thread head moved; read the thread again.' },
  };
  const p = pretty(r);
  add('positive/rejection', 'Post-store signed rejection (D6 tier 2) from Carol\'s provider back into the thread.',
    '§4.5, §8', {
      context: { ...eventCtx, receiver: BOB, typ: 'darep-rejection+jws' },
      headerText: header(keys.carol.kid, 'darep-rejection+jws'), payload: p, key: keys.carol,
      expected: accept(p, keys.carol.kid),
    });
}
{
  const r = {
    darep: '2', id: uuid('rejection ext code'), source: CAROL, type: CORE + '#rejection', time: '2026-11-20T11:59:00Z',
    to: [BOB], thread: handoffId, inReplyTo: handoffId, expires: '2026-11-27T11:59:00Z', ext: {}, required: [],
    data: { code: WORK + '#terms-mismatch' },
  };
  const p = tight(r);
  add('positive/rejection-extension-code', 'Signed rejection whose code is an extension-defined code URI rather than a bare registry code (§4.5).',
    '§4.5', {
      context: { ...eventCtx, receiver: BOB, typ: ['darep-event+jws', 'darep-rejection+jws'], answered: compact(header(keys.bob.kid), handoffBytes, keys.bob) },
      headerText: header(keys.carol.kid, 'darep-rejection+jws'), payload: p, key: keys.carol,
      expected: accept(p, keys.carol.kid),
    });
}
{
  const r = {
    darep: '2', id: uuid('rejection unknown code'), source: CAROL, type: CORE + '#rejection', time: '2026-11-20T11:59:00Z',
    to: [BOB], thread: handoffId, inReplyTo: handoffId, expires: '2026-11-27T11:59:00Z', ext: {}, required: [],
    data: { code: 'future-refusal' },
  };
  const p = tight(r);
  add('positive/rejection-unknown-code', 'Signed rejection with a syntactically valid bare code not in the registry. Verifiers must accept it as an unknown refusal for forward compatibility (§4.5).',
    '§4.5', {
      context: { ...eventCtx, receiver: BOB, typ: ['darep-event+jws', 'darep-rejection+jws'], answered: compact(header(keys.bob.kid), handoffBytes, keys.bob) },
      headerText: header(keys.carol.kid, 'darep-rejection+jws'), payload: p, key: keys.carol,
      expected: accept(p, keys.carol.kid),
    });
}
{
  const id = uuid('message');
  const r = { ...event({ id, thread: id, type: CORE + '#message', required: [], to: [CAROL, DAVE],
    data: { text: 'Two recipients receive the same signed bytes.' } }) };
  const p = pretty(r);
  add('positive/message-multi-recipient', 'Core message addressed to two recipients; verified here as Carol.', '§4.2',
    { payload: p, key: keys.bob, expected: accept(p, keys.bob.kid) });
}
{
  const p = handoffBytes;
  add('positive/extra-header-member', 'Protected header carries an unregistered member, which the receiver ignores (§3.3).',
    '§3.3', { headerText: JSON.stringify({ alg: 'ES256', kid: keys.bob.kid, typ: 'darep-event+jws', 'x-trace': 'abc123' }),
      payload: p, key: keys.bob, expected: accept(p, keys.bob.kid) });
}
{
  const id = uuid('unknown type');
  const r = event({ id, thread: id, type: 'https://example.test/ext/poll/v1#vote', required: [], data: { choice: 2 } });
  const p = pretty(r);
  add('positive/unknown-type-not-required', 'A type the receiver does not implement, with no required extension, still verifies and can be stored and acked (§6.3).',
    '§6.3', { payload: p, key: keys.bob, expected: accept(p, keys.bob.kid) });
}
{
  const r = event({ ext: { 'https://example.test/ext/trace/v1': { span: '00f067aa0ba902b7' } } });
  const p = pretty(r);
  add('positive/unknown-optional-extension', 'An unknown ext entry that is not listed in required is ignored.', '§6.2',
    { payload: p, key: keys.bob, expected: accept(p, keys.bob.kid) });
}
{
  const id = uuid('old key');
  const r = event({ id, thread: id, time: '2026-11-14T12:00:00Z', expires: '2026-11-21T12:00:00Z' });
  const p = pretty(r);
  add('positive/rotated-key-within-validity', 'Signed with Bob\'s retired key at a time inside its validity window. Rotation does not invalidate earlier signatures (§5.4).',
    '§5.4', { payload: p, key: keys.bobOld, expected: accept(p, keys.bobOld.kid) });
}
{
  const id = uuid('evidence');
  const r = event({ id, thread: id, time: '2026-11-02T08:00:00Z', expires: '2026-11-09T08:00:00Z' });
  const p = pretty(r);
  add('positive/evidence-mode-expired', 'The same check in evidence mode: an expired record is still a valid signed record (§7.3).',
    '§7.3', { context: { mode: 'evidence', now: NOW, typ: 'darep-event+jws' }, payload: p, key: keys.bob,
      expected: accept(p, keys.bob.kid) });
}

// ---------- negative vectors ----------

add('negative/wrong-kid', 'kid names a fragment that Bob\'s pinned document does not list.', '§8 step 5',
  { headerText: header(BOB_DOC + '#sig-2099-01'), payload: handoffBytes, key: keys.bob, expected: reject('unknown-key') });
add('negative/kid-not-url', 'kid is the bare acct: address, as in Wire v1.', '§3.2',
  { headerText: header(BOB), payload: handoffBytes, key: keys.bob, expected: reject('bad-header') });
add('negative/kid-of-other-identity', 'Dave signs with his own valid key but claims source Bob.', '§8 step 10',
  { payload: handoffBytes, key: keys.dave, expected: reject('signer-mismatch') });
add('negative/alg-none', 'Unsecured JWS (alg "none", empty signature).', '§3.1', {
  jws: b64u(header(keys.bob.kid, 'darep-event+jws', 'none')) + '.' + b64u(handoffBytes) + '.',
  payload: handoffBytes, expected: reject('unsupported-alg') });
{
  // Classic key-confusion attempt: HMAC keyed with the public key's JWK text.
  const input = b64u(header(keys.bob.kid, 'darep-event+jws', 'HS256')) + '.' + b64u(handoffBytes);
  const mac = createHmac('sha256', JSON.stringify(keys.bob.pub)).update(input).digest();
  add('negative/alg-hs256', 'HS256 keyed with the signer\'s public key material.', '§3.1',
    { jws: input + '.' + b64u(mac), payload: handoffBytes, expected: reject('unsupported-alg') });
}
add('negative/alg-es384-label', 'ES256 signature bytes under an ES384 label. The allow-list check happens before key lookup.', '§3.1',
  { headerText: header(keys.bob.kid, 'darep-event+jws', 'ES384'), payload: handoffBytes, key: keys.bob, expected: reject('unsupported-alg') });
add('negative/legacy-typ', 'Wire v1 typ value.', '§3.2',
  { headerText: header(keys.bob.kid, 'agent-network-event+jws'), payload: handoffBytes, key: keys.bob, expected: reject('bad-header') });
add('negative/typ-context-mismatch', 'A receipt-typed JWS presented where an event is expected.', '§3.2',
  { headerText: header(keys.bob.kid, 'darep-receipt+jws'), payload: handoffBytes, key: keys.bob, expected: reject('bad-header') });
add('negative/crit-header', 'Protected header uses crit. Wire v2 defines no critical header parameters.', '§3.3',
  { headerText: JSON.stringify({ alg: 'ES256', kid: keys.bob.kid, typ: 'darep-event+jws', crit: ['exp'], exp: 1 }),
    payload: handoffBytes, key: keys.bob, expected: reject('bad-header') });
add('negative/embedded-jwk-ignored', 'Attacker signs and embeds their own key in the header jwk member with Bob\'s kid. The verifier uses only the pinned key.', '§3.3, §5.3',
  { headerText: JSON.stringify({ alg: 'ES256', kid: keys.bob.kid, typ: 'darep-event+jws', jwk: keys.attacker.pub }),
    payload: handoffBytes, key: keys.attacker, expected: reject('bad-signature') });
add('negative/duplicate-header-member', 'Protected header contains alg twice.', '§2.2',
  { headerText: `{"alg":"none","alg":"ES256","kid":"${keys.bob.kid}","typ":"darep-event+jws"}`,
    payload: handoffBytes, key: keys.bob, expected: reject('malformed') });
{
  const signed = compact(header(keys.bob.kid), handoffBytes, keys.bob).split('.');
  const altered = Buffer.from(handoffBytes.toString('utf8').replace('grant-7f3a', 'grant-0000'));
  add('negative/tampered-payload', 'Payload of positive/handoff altered after signing; the original signature is kept.', '§8 step 6',
    { jws: `${signed[0]}.${b64u(altered)}.${signed[2]}`, payload: altered, expected: reject('bad-signature') });
}
{
  const text = handoffBytes.toString('utf8').replace(`"to": [\n  "${CAROL}"\n ],`,
    `"to": [\n  "${CAROL}"\n ],\n "to": [\n  "${DAVE}"\n ],`);
  if (!text.includes(DAVE)) throw new Error('duplicate-key fixture did not apply');
  const p = Buffer.from(text);
  add('negative/duplicate-payload-member', 'Validly signed payload that lists "to" twice. Parsers disagree on which wins, so it is rejected.', '§2.2',
    { payload: p, key: keys.bob, expected: reject('malformed') });
}
{
  const p = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), handoffBytes]);
  add('negative/bom', 'Validly signed payload that starts with a UTF-8 byte order mark.', '§2.1',
    { payload: p, key: keys.bob, expected: reject('malformed') });
}
{
  const p = Buffer.from(handoffBytes.toString('utf8').replace('合成預覽', 'X'));
  const bad = Buffer.concat([p.subarray(0, p.indexOf('X')), Buffer.from([0xc3, 0x28]), p.subarray(p.indexOf('X') + 1)]);
  add('negative/invalid-utf8', 'Validly signed payload containing an invalid UTF-8 sequence.', '§2.1',
    { payload: bad, key: keys.bob, expected: reject('malformed') });
}
{
  const r = { specversion: '1.0', type: 'net.agentnetwork.handoff.v1', id: handoffId, source: BOB, subject: handoffId,
    time: T, datacontenttype: 'application/json', data: { to: CAROL, previous: null, action: { kind: 'handoff' } } };
  add('negative/v1-envelope', 'A Wire v1 CloudEvents envelope signed with a valid v2 header.', '§4.1',
    { payload: pretty(r), key: keys.bob, expected: reject('unsupported-version') });
}
add('negative/unknown-top-level-member', 'Envelope carries a member that Wire v2 does not define.', '§4.1',
  { payload: pretty(event({ priority: 'high' })), key: keys.bob, expected: reject('malformed') });
add('negative/unknown-required-extension', 'required lists an extension the receiver does not implement.', '§6.2',
  { payload: pretty(event({ required: [WORK, 'https://example.test/ext/escrow/v1'] })), key: keys.bob,
    expected: reject('unsupported-extension') });
add('negative/expired', 'expires plus the 300-second skew allowance is before now.', '§7.2',
  { payload: pretty(event({ time: '2026-11-13T11:00:00Z', expires: '2026-11-20T11:00:00Z' })), key: keys.bob,
    expected: reject('expired') });
add('negative/not-yet-valid', 'time is more than 300 seconds after now.', '§7.2',
  { payload: pretty(event({ time: '2026-11-20T12:06:00Z', expires: '2026-11-27T12:06:00Z' })), key: keys.bob,
    expected: reject('not-yet-valid') });
add('negative/expiry-window-too-long', 'expires is more than 30 days after time.', '§4.2, §7.1',
  { payload: pretty(event({ expires: '2026-12-21T11:58:00Z' })), key: keys.bob, expected: reject('malformed') });
add('negative/retired-key-after-validity', 'Bob\'s retired key signs a record dated after its validUntil.', '§5.4',
  { payload: handoffBytes, key: keys.bobOld, expected: reject('key-not-valid') });
{
  const id = uuid('revoked');
  add('negative/revoked-key', 'A revoked key signs a record dated inside its original validity window.', '§5.4',
    { payload: pretty(event({ id, thread: id, time: '2026-04-15T00:00:00Z', expires: '2026-04-16T00:00:00Z' })),
      context: { mode: 'evidence', now: NOW, typ: 'darep-event+jws' }, key: keys.bobRevoked, expected: reject('key-not-valid') });
}
add('negative/wrong-key-purpose', 'Bob\'s provider key (purpose "provider" only) signs an event record.', '§5.2',
  { payload: handoffBytes, key: keys.bobProvider, expected: reject('key-not-valid') });
add('negative/b64-header', 'Protected header carries b64:false without crit. Honoring and ignoring it would read different payloads.', '§3.3',
  { headerText: JSON.stringify({ alg: 'ES256', kid: keys.bob.kid, typ: 'darep-event+jws', b64: false }),
    payload: handoffBytes, key: keys.bob, expected: reject('bad-header') });
{
  // Pad the payload so its length is a multiple of 3, then append one base64url character (length = 1 mod 4).
  let text = handoffBytes.toString('utf8');
  while (Buffer.byteLength(text) % 3) text += ' ';
  const segs = [b64u(header(keys.bob.kid)), b64u(Buffer.from(text)) + 'A'];
  const input = segs.join('.');
  const jws = input + '.' + b64u(ecdsaSign(keys.bob.d, Buffer.from(input, 'ascii')));
  add('negative/noncanonical-base64url', 'Payload segment has a dangling base64url character that lenient decoders drop. The signature covers the segment as sent.', '§3 S-1',
    { jws, payload: Buffer.from(text), expected: reject('malformed') });
}
add('negative/noncharacter', 'Validly signed payload whose data contains the noncharacter U+FFFF, which I-JSON forbids.', '§2.2',
  { payload: pretty(event({ data: { ...handoff.data, summary: 'x\uFFFF' } })), key: keys.bob, expected: reject('malformed') });
{
  const r = { darep: '2', id: uuid('stale receipt'), source: CAROL, type: CORE + '#receipt', time: '2026-11-20T11:50:00Z',
    to: [BOB], thread: handoffId, inReplyTo: handoffId, ext: {}, required: [], data: { sha256: handoffSha, storedAt: '2026-11-20T11:50:00Z' } };
  add('negative/receipt-predates-record', 'A receipt for positive/handoff dated more than 300 seconds before that record\'s own time. Receipts have no expires, so RC-1 bounds their time by the answered record (TM-4a).', '§4.4 RC-1, §7.2 TM-4a',
    { context: { ...eventCtx, receiver: BOB, typ: 'darep-receipt+jws', answered: compact(header(keys.bob.kid), handoffBytes, keys.bob) },
      headerText: header(keys.carol.kid, 'darep-receipt+jws'), payload: tight(r), key: keys.carol, expected: reject('receipt-mismatch') });
}
{
  const r = { darep: '2', id: uuid('receipt with ext'), source: CAROL, type: CORE + '#receipt', time: '2026-11-20T11:58:01Z',
    to: [BOB], thread: handoffId, inReplyTo: handoffId, ext: { 'https://example.test/ext/trace/v1': { span: '00f067aa0ba902b7' } }, required: [],
    data: { sha256: handoffSha, storedAt: '2026-11-20T11:58:01Z' } };
  add('negative/receipt-with-ext', 'A receipt that carries an ext entry. Receipts are evidence with an exact shape: ext must be {} and required must be [] (§4.4).', '§4.4',
    { context: { ...eventCtx, receiver: BOB, typ: 'darep-receipt+jws', answered: compact(header(keys.bob.kid), handoffBytes, keys.bob) },
      headerText: header(keys.carol.kid, 'darep-receipt+jws'), payload: tight(r), key: keys.carol, expected: reject('malformed') });
}
{
  const r = { darep: '2', id: uuid('mismatched receipt'), source: CAROL, type: CORE + '#receipt', time: '2026-11-20T11:58:01Z',
    to: [BOB], thread: handoffId, inReplyTo: handoffId, ext: {}, required: [], data: { sha256: '0'.repeat(64), storedAt: '2026-11-20T11:58:01Z' } };
  add('negative/receipt-mismatch', 'A correctly signed receipt for positive/handoff whose digest does not match that record\'s payload bytes.', '§4.4 RC-1, §8 step 15',
    { context: { ...eventCtx, receiver: BOB, typ: 'darep-receipt+jws', answered: compact(header(keys.bob.kid), handoffBytes, keys.bob) },
      headerText: header(keys.carol.kid, 'darep-receipt+jws'), payload: tight(r), key: keys.carol, expected: reject('receipt-mismatch') });
}
{
  const r = { darep: '2', id: uuid('late receipt'), source: CAROL, type: CORE + '#receipt', time: '2026-11-20T11:58:01Z',
    to: [BOB], thread: handoffId, inReplyTo: handoffId, ext: {}, required: [], data: { sha256: handoffSha, storedAt: '2026-11-20T11:58:01Z' } };
  add('negative/receipt-after-delivery-window', 'A valid receipt for positive/handoff presented to the sender after that record\'s expires plus skew. The delivery has closed, so the receipt is not admitted (TM-4a).', '§7.2 TM-4a',
    { context: { ...eventCtx, now: '2026-11-27T12:04:00Z', receiver: BOB, typ: 'darep-receipt+jws', answered: compact(header(keys.bob.kid), handoffBytes, keys.bob) },
      headerText: header(keys.carol.kid, 'darep-receipt+jws'), payload: tight(r), key: keys.carol, expected: reject('expired') });
}
add('negative/wrong-recipient', 'Carol receives a record addressed only to Dave.', '§8 step 12',
  { payload: pretty(event({ to: [DAVE] })), key: keys.bob, expected: reject('wrong-recipient') });

// ---------- errata 2026-11-21 negative vectors ----------

// §8 step 15 order: RC-1 correlation (including receipt digest) runs before TM-4a delivery-window expiry.
{
  const r = { darep: '2', id: uuid('mismatched late receipt'), source: CAROL, type: CORE + '#receipt', time: '2026-11-20T11:58:01Z',
    to: [BOB], thread: handoffId, inReplyTo: handoffId, ext: {}, required: [], data: { sha256: '0'.repeat(64), storedAt: '2026-11-20T11:58:01Z' } };
  add('negative/receipt-mismatch-after-window', 'A receipt for positive/handoff with both a wrong digest and a now past expires + skew. Full RC-1 correlation runs before TM-4a, so the code must be receipt-mismatch, not expired.',
    '§4.4 RC-1, §8 step 15', {
      context: { ...eventCtx, now: '2026-11-27T12:04:00Z', receiver: BOB, typ: 'darep-receipt+jws', answered: compact(header(keys.bob.kid), handoffBytes, keys.bob) },
      headerText: header(keys.carol.kid, 'darep-receipt+jws'), payload: tight(r), key: keys.carol, expected: reject('receipt-mismatch'),
    });
}

// §4.5 rejection data.code validation.
{
  const mkRej = (label, data) => ({
    darep: '2', id: uuid(label), source: CAROL, type: CORE + '#rejection', time: '2026-11-20T11:59:00Z',
    to: [BOB], thread: handoffId, inReplyTo: handoffId, expires: '2026-11-27T11:59:00Z', ext: {}, required: [], data,
  });
  const rejCtx = { ...eventCtx, receiver: BOB, typ: 'darep-rejection+jws' };
  add('negative/rejection-missing-code', 'Signed rejection whose data carries detail but omits code (§4.5).', '§4.5', {
    context: rejCtx, headerText: header(keys.carol.kid, 'darep-rejection+jws'),
    payload: tight(mkRej('rejection missing code', { detail: 'No code was supplied.' })), key: keys.carol, expected: reject('malformed'),
  });
  add('negative/rejection-nonstring-code', 'Signed rejection whose data.code is a number rather than a string (§4.5).', '§4.5', {
    context: rejCtx, headerText: header(keys.carol.kid, 'darep-rejection+jws'),
    payload: tight(mkRej('rejection nonstring code', { code: 123 })), key: keys.carol, expected: reject('malformed'),
  });
  add('negative/rejection-empty-data', 'Signed rejection whose data is an empty object (§4.5).', '§4.5', {
    context: rejCtx, headerText: header(keys.carol.kid, 'darep-rejection+jws'),
    payload: tight(mkRej('rejection empty data', {})), key: keys.carol, expected: reject('malformed'),
  });
}

// Empty # in URIs where no fragment or a non-empty fragment is required (§3.2 K-1, §6.1 U-1/U-2).
add('negative/ext-empty-fragment', 'An ext key ends with a trailing #, which is forbidden even though WHATWG .hash is empty.', '§3.2 K-1, §6.2 X-1',
  { payload: pretty(event({ id: uuid('ext empty frag'), thread: uuid('ext empty frag'), ext: { 'https://example.test/ext/trace/v1#': { span: '1' } } })),
    key: keys.bob, expected: reject('malformed') });
add('negative/required-empty-fragment', 'A required entry ends with a trailing #, which is forbidden even though WHATWG .hash is empty.', '§3.2 K-1, §6.1 U-1',
  { payload: pretty(event({ id: uuid('req empty frag'), thread: uuid('req empty frag'), required: ['https://example.test/ext/trace/v1#'] })),
    key: keys.bob, expected: reject('malformed') });
add('negative/type-empty-fragment', 'A type URI ends with a trailing # and empty fragment.', '§3.2 K-1, §6.1 U-2',
  { payload: pretty(event({ id: uuid('type empty frag'), thread: uuid('type empty frag'), type: 'https://example.test/ext/poll/v1#', required: [] })),
    key: keys.bob, expected: reject('malformed') });
add('negative/kid-empty-fragment', 'kid ends with a trailing # and empty fragment.', '§3.2 K-1',
  { headerText: header(BOB_DOC + '#'), payload: handoffBytes, key: keys.bob, expected: reject('bad-header') });

// K-1 host, port, path and userinfo rules for kid and type URIs.
add('negative/kid-uppercase-host', 'kid host contains an uppercase letter, which K-1 forbids.', '§3.2 K-1',
  { headerText: header('https://Bob.vectors.test/.well-known/darep/bob#sig-2026-11'), payload: handoffBytes, key: keys.bob, expected: reject('bad-header') });
add('negative/type-uppercase-host', 'type URI host contains an uppercase letter, which K-1 forbids.', '§3.2 K-1, §6.1 U-2',
  { payload: pretty(event({ id: uuid('type upper host'), thread: uuid('type upper host'), type: 'https://Example.test/ext/poll/v1#vote', required: [] })),
    key: keys.bob, expected: reject('malformed') });
add('negative/kid-hyphen-host', 'kid host has a label starting with a hyphen, which K-1 forbids.', '§3.2 K-1',
  { headerText: header('https://-bob.vectors.test/.well-known/darep/bob#sig-2026-11'), payload: handoffBytes, key: keys.bob, expected: reject('bad-header') });
add('negative/type-trailing-hyphen-host', 'type URI host has a label ending with a hyphen, which K-1 forbids.', '§3.2 K-1, §6.1 U-2',
  { payload: pretty(event({ id: uuid('type hyphen host'), thread: uuid('type hyphen host'), type: 'https://example-.test/ext/poll/v1#vote', required: [] })),
    key: keys.bob, expected: reject('malformed') });
add('negative/kid-single-label-host', 'kid host has no dot (single-label host), which K-1 forbids.', '§3.2 K-1',
  { headerText: header('https://localhost/.well-known/darep/bob#sig-2026-11'), payload: handoffBytes, key: keys.bob, expected: reject('bad-header') });
add('negative/kid-default-port', 'kid writes out the default port :443, which K-1 forbids.', '§3.2 K-1',
  { headerText: header('https://bob.vectors.test:443/.well-known/darep/bob#sig-2026-11'), payload: handoffBytes, key: keys.bob, expected: reject('bad-header') });
add('negative/type-default-port', 'type URI writes out the default port :443, which K-1 forbids.', '§3.2 K-1, §6.1 U-2',
  { payload: pretty(event({ id: uuid('type default port'), thread: uuid('type default port'), type: 'https://example.test:443/ext/poll/v1#vote', required: [] })),
    key: keys.bob, expected: reject('malformed') });
add('negative/kid-dot-segment', 'kid path contains a dot segment (..), which K-1 forbids.', '§3.2 K-1',
  { headerText: header('https://bob.vectors.test/.well-known/darep/../darep/bob#sig-2026-11'), payload: handoffBytes, key: keys.bob, expected: reject('bad-header') });
add('negative/type-dot-segment', 'type URI path contains a dot segment (.), which K-1 forbids.', '§3.2 K-1, §6.1 U-2',
  { payload: pretty(event({ id: uuid('type dot seg'), thread: uuid('type dot seg'), type: 'https://example.test/ext/./poll/v1#vote', required: [] })),
    key: keys.bob, expected: reject('malformed') });
add('negative/kid-hex-ipv4', 'kid host is a hex IPv4 address, which K-1 forbids.', '§3.2 K-1',
  { headerText: header('https://0x7f.0.0.1/.well-known/darep/bob#sig-2026-11'), payload: handoffBytes, key: keys.bob, expected: reject('bad-header') });
add('negative/kid-octal-ipv4', 'kid host is an octal IPv4 address, which K-1 forbids.', '§3.2 K-1',
  { headerText: header('https://0177.0.0.1/.well-known/darep/bob#sig-2026-11'), payload: handoffBytes, key: keys.bob, expected: reject('bad-header') });
add('negative/kid-userinfo', 'kid contains userinfo, which K-1 forbids.', '§3.2 K-1',
  { headerText: header('https://user@bob.vectors.test/.well-known/darep/bob#sig-2026-11'), payload: handoffBytes, key: keys.bob, expected: reject('bad-header') });
add('negative/type-userinfo', 'type URI contains userinfo, which K-1 forbids.', '§3.2 K-1, §6.1 U-2',
  { payload: pretty(event({ id: uuid('type userinfo'), thread: uuid('type userinfo'), type: 'https://user@example.test/ext/poll/v1#vote', required: [] })),
    key: keys.bob, expected: reject('malformed') });

// Clarification regressions: K-1 syntax is broader than valid pinned key IDs (#18).
for (const [name, suffix] of [['query', '?v=1#sig-2026-11'], ['empty-query', '?#sig-2026-11'], ['broad-fragment', '#key{wide}']]) {
  add('negative/kid-' + name, 'K-1 permits this kid syntax, but it cannot match a valid pinned key; step 5, not step 4, fails.', '§3.2 K-1/K-2, §5.1, §8 step 5',
    { headerText: header(BOB_DOC + suffix), payload: handoffBytes, key: keys.bob, expected: reject('unknown-key') });
}
for (const query of ['?', '?v=1']) {
  const uri = 'https://example.test/ext/poll/v1' + query;
  const p = pretty(event({ id: uuid('extension query ' + query), thread: uuid('extension query ' + query), type: uri + '#vote', ext: { [uri]: {} }, required: [] }));
  add('positive/extension-' + (query === '?' ? 'empty-query' : 'query'), 'Extension and type URIs permit queries, including an empty query; this optional extension need not be understood.', '§6.1 U-1/U-2',
    { payload: p, key: keys.bob, expected: accept(p, keys.bob.kid) });
}
// Issuer inconsistency does not add a records-verifier rejection condition (#20).
{
  const original = vectors.find(v => v.name === 'positive/receipt');
  const r = { ...original.expected.record, id: uuid('receipt signing before storedAt'), data: { ...original.expected.record.data, storedAt: '2026-11-20T11:58:02Z' } };
  const p = tight(r);
  add('positive/receipt-signing-before-stored-at', 'Verifier acceptance only: time is before storedAt, violating the issuer obligation in delivery §4.1 but not adding a Wire v2 §8 rejection condition.', '§4.4, §8 step 9; delivery §4.1',
    { context: original.context, headerText: header(keys.carol.kid, 'darep-receipt+jws'), payload: p, key: keys.carol, expected: accept(p, keys.carol.kid) });
}

// ---------- invalid identity documents (P-0 pin validation) ----------

const badDoc = (name, description, spec, id) => ({
  name, description, spec,
  expected: { verdict: 'reject', rule: 'P-0' },
  document: {
    darep: '2', id, addresses: [CAROL], updated: '2026-11-01T00:00:00Z',
    keys: [{ id: id + '#key-2026-11', purpose: ['record', 'provider'], publicKeyJwk: structuredClone(keys.carol.pub), validFrom: '2026-11-01T00:00:00Z' }],
  },
});
const invalidIdentities = [
  badDoc('id-with-query', 'Identity document id carries a query string, which §5.1 forbids.', '§5.1, §5.3 P-0', CAROL_DOC + '?v=1'),
  badDoc('id-with-empty-query', 'Identity document id ends with a trailing ?, which §5.1 forbids even though WHATWG .search is empty.', '§3.2 K-1, §5.1, §5.3 P-0', CAROL_DOC + '?'),
  badDoc('id-with-empty-fragment', 'Identity document id ends with a trailing #, which §5.1 forbids even though WHATWG .hash is empty.', '§3.2 K-1, §5.1, §5.3 P-0', CAROL_DOC + '#'),
  badDoc('id-uppercase-host', 'Identity document id host has an uppercase letter, which K-1 forbids.', '§3.2 K-1, §5.1, §5.3 P-0', 'https://Carol.vectors.test/.well-known/darep/carol'),
  badDoc('id-default-port', 'Identity document id writes out default port :443, which K-1 forbids.', '§3.2 K-1, §5.1, §5.3 P-0', 'https://carol.vectors.test:443/.well-known/darep/carol'),
];

// P-0 shape and format regressions. Each case changes one field of a valid pin.
function invalidPin(name, description, mutate) {
  const c = badDoc(name, description, '§5.1, §5.2, §5.3 P-0', CAROL_DOC);
  mutate(c.document);
  invalidIdentities.push(c);
}
for (const field of ['darep', 'id', 'addresses', 'updated', 'keys']) {
  invalidPin(field + '-missing', 'Missing required document member ' + field + '.', d => { delete d[field]; });
  invalidPin(field + '-wrong-type', 'Wrong type for document member ' + field + '.', d => { d[field] = 42; });
}
invalidPin('wrong-version', 'Identity document version must be "2".', d => { d.darep = '3'; });
invalidPin('keys-empty', 'A pin must contain at least one key.', d => { d.keys = []; });
invalidPin('key-not-object', 'Each key must be an object.', d => { d.keys = [null]; });
invalidPin('key-id-duplicate', 'Key ids must be distinct.', d => { d.keys.push(structuredClone(d.keys[0])); });
invalidPin('addresses-empty', 'A pin must contain at least one address.', d => { d.addresses = []; });
invalidPin('addresses-duplicate', 'Addresses must be distinct.', d => { d.addresses.push(d.addresses[0]); });
invalidPin('address-wrong-type', 'Every address must be a string.', d => { d.addresses = [42]; });
invalidPin('address-invalid', 'An address must satisfy E-4.', d => { d.addresses = ['bob@example.com']; });
invalidPin('address-newline', 'An address cannot end in a line break.', d => { d.addresses[0] += '\n'; });
for (const field of ['id', 'purpose', 'publicKeyJwk', 'validFrom']) {
  invalidPin('key-' + field + '-missing', 'Missing required key member ' + field + '.', d => { delete d.keys[0][field]; });
  invalidPin('key-' + field + '-wrong-type', 'Wrong type for key member ' + field + '.', d => { d.keys[0][field] = 42; });
}
invalidPin('key-id-other-document', 'A key id must belong to its document.', d => { d.keys[0].id = BOB_DOC + '#key'; });
invalidPin('key-id-empty-fragment', 'Key fragments must not be empty.', d => { d.keys[0].id = d.id + '#'; });
invalidPin('key-id-long-fragment', 'Key fragments are at most 64 characters.', d => { d.keys[0].id = d.id + '#' + 'k'.repeat(65); });
invalidPin('key-id-newline', 'Key fragments cannot end in a line break.', d => { d.keys[0].id += '\n'; });
for (const [name, purpose] of Object.entries({ empty: [], duplicate: ['record', 'record'], unknown: ['unknown'],
  nonstring: [{}], 'reserved-mixed': ['record', 'root'] })) {
  invalidPin('purpose-' + name, 'Invalid key purpose: ' + name + '.', d => { d.keys[0].purpose = purpose; });
}
for (const field of ['updated', 'validFrom', 'validUntil', 'revoked']) {
  for (const [name, value] of Object.entries({ 'not-rfc3339': 'November 1, 2026', 'invalid-date': '2026-02-30T00:00:00Z',
    'invalid-hour': '2026-11-01T24:00:00Z', offset: '2026-11-01T00:00:00+00:00',
    'too-precise': '2026-11-01T00:00:00.0001Z', newline: '2026-11-01T00:00:00Z\n', null: null })) {
    invalidPin(field + '-' + name, 'Invalid instant for ' + field + ': ' + name + '.', d => {
      (field === 'updated' ? d : d.keys[0])[field] = value;
    });
  }
}
for (const [name, end] of Object.entries({ equal: '2026-11-01T00:00:00Z', before: '2026-10-31T00:00:00Z' })) {
  invalidPin('validUntil-' + name, 'validUntil must be later than validFrom.', d => { d.keys[0].validUntil = end; });
}
// A malformed optional instant must not become a fallback numeric timestamp before 1970.
invalidPin('validUntil-invalid-before-epoch', 'Invalid validUntil is invalid even for a pre-epoch key.', d => {
  d.keys[0].validFrom = '1960-01-01T00:00:00Z'; d.keys[0].validUntil = 'invalid';
});
for (const field of ['kty', 'crv', 'x', 'y']) {
  invalidPin('jwk-' + field + '-missing', 'Missing JWK member ' + field + '.', d => { delete d.keys[0].publicKeyJwk[field]; });
  invalidPin('jwk-' + field + '-wrong-type', 'Wrong JWK member type ' + field + '.', d => { d.keys[0].publicKeyJwk[field] = 42; });
}
invalidPin('jwk-private', 'A public JWK must not contain d.', d => { d.keys[0].publicKeyJwk.d = 'test-only'; });
invalidPin('jwk-wrong-curve', 'Only P-256 is allowed.', d => { d.keys[0].publicKeyJwk.crv = 'P-384'; });
invalidPin('jwk-wrong-kty', 'Only EC is allowed.', d => { d.keys[0].publicKeyJwk.kty = 'RSA'; });
invalidPin('jwk-off-curve', 'Coordinates must lie on P-256.', d => {
  d.keys[0].publicKeyJwk.x = d.keys[0].publicKeyJwk.y = 'A'.repeat(43);
});
for (const field of ['x', 'y']) {
  invalidPin('jwk-' + field + '-padded', 'JWK coordinates use unpadded base64url.', d => { d.keys[0].publicKeyJwk[field] += '='; });
  invalidPin('jwk-' + field + '-short', 'P-256 coordinates encode exactly 32 octets.', d => { d.keys[0].publicKeyJwk[field] = 'AA'; });
  invalidPin('jwk-' + field + '-noncanonical', 'JWK coordinate pad bits must be zero.', d => {
    const j = d.keys[0].publicKeyJwk;
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    j[field] = j[field].slice(0, -1) + alphabet[alphabet.indexOf(j[field].at(-1)) + 1];
  });
}

// ---------- harness self-test fixtures ----------
// Not conformance vectors: they check the runners' own comparison modes (README "Harness self-test fixtures").
const selftest = [];
{
  const id = uuid('selftest-numbers');
  const head = { darep: '2', id, source: BOB, type: 'https://vectors.test/ext/numbers/v1#sample', time: T, to: [CAROL],
    thread: id, inReplyTo: null, expires: EXP, ext: {}, required: [], grant: { id: 'grant-7f3a', actor: 'agent' } };
  // Number lexemes that differ from their shortest form, so the payload bytes still pin the exact text (NC1).
  const text = JSON.stringify(head).slice(0, -1) + ',"data":{"ratio":0.10,"hundred":1e2,"amount":123456.789,"small":[2.5e-3]}}';
  const p = Buffer.from(text, 'utf8');
  const before = vectors.length;
  add('selftest/numbers-binary64', 'Harness self-test fixture, not a conformance vector. Numbers in expected.record are compared after rounding both sides to IEEE 754 binary64 (expected.numbers). A verifier that keeps less precision, such as binary32, must fail it.',
    '§8, J-1', { payload: p, key: keys.bob, expected: { ...accept(p, keys.bob.kid), numbers: 'binary64' } });
  selftest.push(...vectors.splice(before));
}

// Pin updates (§5.5): an old and a new snapshot of one identity document, and whether the update may be a routine
// rotation. Only rules the frozen text states are used here; address-set changes other than removal are left out.
const pinUpdates = [];
{
  const old = identities[0];
  const clone = () => JSON.parse(JSON.stringify(old));
  const keyIndex = kid => old.keys.findIndex(k => k.id === kid);
  const update = (name, expected, description, mutate, base = clone) => {
    const before = base();
    const after = JSON.parse(JSON.stringify(before));
    mutate(after);
    pinUpdates.push({ name, description, spec: '§5.5', expected, level: expected === 'routine' ? 'SHOULD' : 'MUST', old: before, new: after });
  };
  const newKey = { id: BOB_DOC + '#sig-2026-12', purpose: ['record'], publicKeyJwk: keys.dave.pub, validFrom: '2026-12-01T00:00:00Z' };
  update('unchanged', 'routine', 'The same snapshot again.', () => {});
  update('key-added', 'routine', 'A new key is added; every existing key is unchanged.', d => { d.keys.push(newKey); d.updated = '2026-11-20T00:00:00Z'; });
  update('valid-until-earlier', 'routine', 'An existing validUntil moves earlier.', d => { d.keys[keyIndex(keys.bobOld.kid)].validUntil = '2026-11-10T00:00:00Z'; });
  update('revoked-added', 'routine', 'An existing key gains revoked.', d => { d.keys[keyIndex(keys.bob.kid)].revoked = '2026-11-19T00:00:00Z'; });
  update('key-removed', 'owner-decision', 'An existing key is missing from the new snapshot.', d => { d.keys.splice(keyIndex(keys.bobOld.kid), 1); });
  update('public-key-changed', 'owner-decision', 'An existing key id now has a different publicKeyJwk.', d => { d.keys[keyIndex(keys.bob.kid)].publicKeyJwk = keys.dave.pub; });
  update('purpose-changed', 'owner-decision', 'An existing key gains a purpose.', d => { d.keys[keyIndex(keys.bob.kid)].purpose = ['record', 'provider']; });
  update('valid-from-changed', 'owner-decision', 'An existing key has a different validFrom.', d => { d.keys[keyIndex(keys.bob.kid)].validFrom = '2026-10-01T00:00:00Z'; });
  update('valid-until-later', 'owner-decision', 'An existing validUntil moves later.', d => { d.keys[keyIndex(keys.bobOld.kid)].validUntil = '2026-12-15T00:00:00Z'; });
  update('valid-until-removed', 'owner-decision', 'An existing validUntil is removed, which moves it later.', d => { delete d.keys[keyIndex(keys.bobOld.kid)].validUntil; });
  update('revoked-removed', 'owner-decision', 'An existing revoked is removed.', d => { delete d.keys[keyIndex(keys.bobRevoked.kid)].revoked; });
  update('id-changed', 'owner-decision', 'The document id differs (with its key ids, so that both snapshots stay valid pins).', d => {
    const id = 'https://bob.vectors.test/.well-known/darep/robert';
    for (const k of d.keys) k.id = id + k.id.slice(d.id.length);
    d.id = id;
  });
  update('address-removed', 'owner-decision', 'An address listed in the old snapshot is missing from the new one.',
    d => { d.addresses = [BOB]; }, () => ({ ...clone(), addresses: [BOB, 'acct:robert@vectors.test'] }));
}

// ---------- write ----------

selfTest();
const sorted = obj => JSON.stringify(obj, null, 2) + '\n';
for (const dir of ['positive', 'negative', 'selftest']) {
  await rm(new URL(dir + '/', here), { recursive: true, force: true });
  await mkdir(new URL(dir + '/', here), { recursive: true });
}
const testOnly = 'TEST ONLY. These private keys are published on purpose so anyone can regenerate the vectors. ' +
  'They protect nothing. Never accept them outside a test.';
await writeFile(new URL('keys.json', here), sorted({
  warning: testOnly,
  derivation: 'd = (SHA-256("DAREP vectors v2 TEST ONLY: " + seed) mod (n - 1)) + 1 on P-256',
  keys: Object.fromEntries(Object.entries(keys).map(([name, k]) => [name, { seed: k.seed, kid: k.kid, privateJwk: k.priv }])),
}));
await writeFile(new URL('identities.json', here), sorted({
  usage: 'Pinned identity-document snapshots (records.md §5). Every vector is checked against all of them.',
  documents: identities,
}));
await writeFile(new URL('invalid-identities.json', here), sorted({
  usage: 'Invalid identity documents that MUST fail pin validation (records.md §5.1, §5.3 P-0).',
  cases: invalidIdentities,
}));
for (const v of selftest) await writeFile(new URL(v.name + '.json', here), sorted(v));
await writeFile(new URL('selftest/pin-updates.json', here), sorted({
  usage: 'Harness self-test fixture for the optional checkUpdate adapter operation, not conformance vectors. Each case is an old and a new snapshot of one pinned identity document (records.md §5.5). expected is routine (a monotonic update, which an implementation SHOULD accept without a new trust decision) or owner-decision (any other change, which MUST be presented to the owner).',
  cases: pinUpdates,
}));
const index = [];
for (const v of vectors) {
  await writeFile(new URL(v.name + '.json', here), sorted(v));
  index.push({ name: v.name, verdict: v.expected.verdict, code: v.expected.code ?? null });
}
await writeFile(new URL('index.json', here), sorted({
  spec: 'spec/records.md',
  wire: 'DAREP Wire v2, frozen (spec v0.1)',
  generator: 'vectors/v2/records/generate.mjs',
  vectors: index,
}));
const counts = (await Promise.all(['positive', 'negative'].map(d => readdir(new URL(d + '/', here))))).map(f => f.length);
console.log(`wrote ${counts[0]} positive and ${counts[1]} negative vectors`);
