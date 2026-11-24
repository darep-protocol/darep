// Runs every vector in vectors/v2/records/ through the verification procedure of spec/records.md §8
// and fails if any verdict or rejection code differs from the vector's expectation.
//
//   node vectors/v2/records/check.mjs
//
// This file is a readable reference for the spec, not production code. It uses only Node built-ins and
// deliberately avoids a JOSE library so that each step maps to one numbered step in §8.

import { createHash, createPublicKey, verify as nodeVerify } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

const here = new URL('./', import.meta.url);
const load = async path => JSON.parse(await readFile(new URL(path, here), 'utf8'));

class Reject extends Error { constructor(code, why) { super(why); this.code = code; } }
const must = (ok, code, why) => { if (!ok) throw new Reject(code, why); };

// ---------- §2: strict JSON (UTF-8, no BOM, no duplicate members, I-JSON) ----------

export function strictJson(bytes) {
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); } catch { throw new Reject('malformed', 'not UTF-8'); }
  must(!text.startsWith('﻿'), 'malformed', 'byte order mark');
  let i = 0;
  const ws = () => { while (' \t\n\r'.includes(text[i]) && i < text.length) i++; };
  const fail = why => { throw new Reject('malformed', why + ' at ' + i); };
  function value() {
    ws();
    const c = text[i];
    if (c === '{') {
      i++; const obj = {}; const seen = new Set(); ws();
      if (text[i] === '}') { i++; return obj; }
      for (;;) {
        ws(); if (text[i] !== '"') fail('expected member name');
        const k = string();
        if (seen.has(k)) fail('duplicate member ' + JSON.stringify(k));
        seen.add(k); ws();
        if (text[i++] !== ':') fail('expected colon');
        Object.defineProperty(obj, k, { value: value(), enumerable: true, writable: true, configurable: true });
        ws();
        if (text[i] === ',') { i++; continue; }
        if (text[i] === '}') { i++; return obj; }
        fail('expected , or }');
      }
    }
    if (c === '[') {
      i++; const arr = []; ws();
      if (text[i] === ']') { i++; return arr; }
      for (;;) {
        arr.push(value()); ws();
        if (text[i] === ',') { i++; continue; }
        if (text[i] === ']') { i++; return arr; }
        fail('expected , or ]');
      }
    }
    if (c === '"') return string();
    const m = /^(?:-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null)/.exec(text.slice(i));
    if (!m) fail('unexpected token');
    i += m[0].length;
    const v = JSON.parse(m[0]);
    if (typeof v === 'number' && !Number.isFinite(v)) fail('number out of range');
    return v;
  }
  function string() {
    const m = /^"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/.exec(text.slice(i));
    if (!m) fail('bad string');
    i += m[0].length;
    const s = JSON.parse(m[0]);
    if (!s.isWellFormed()) fail('unpaired surrogate');
    for (const ch of s) {
      const cp = ch.codePointAt(0);
      if ((cp >= 0xFDD0 && cp <= 0xFDEF) || (cp & 0xFFFE) === 0xFFFE) fail('noncharacter');
    }
    return s;
  }
  const v = value(); ws();
  if (i !== text.length) fail('trailing data');
  return v;
}

// ---------- §4: envelope schema ----------

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
const ACCT = new RegExp('^acct:[a-z0-9][a-z0-9._-]{0,62}@' + LABEL + '(?:\\.' + LABEL + ')+$');
const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
const CORE = 'https://darep.org/ext/core/v2';
const TYPS = { event: 'darep-event+jws', receipt: 'darep-receipt+jws', rejection: 'darep-rejection+jws' };
const PURPOSE = { [TYPS.event]: 'record', [TYPS.receipt]: 'provider', [TYPS.rejection]: 'provider' };
const SKEW = 300_000;
const MAX_WINDOW = 30 * 24 * 3600_000;

const isObj = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const isUuid = v => typeof v === 'string' && UUID.test(v);
const isAcct = v => typeof v === 'string' && v.length <= 200 && ACCT.test(v);
const isStr = (v, max) => typeof v === 'string' && v.length >= 1 && [...v].length <= max;
const ms = t => { if (typeof t !== 'string') return NaN; const n = Date.parse(t); return TIME.test(t) && Number.isFinite(n) && new Date(n).toISOString().slice(0, 19) === t.slice(0, 19) ? n : NaN; };
const DNS_HOST = new RegExp('^' + LABEL + '(?:\\.' + LABEL + ')+$');
const NUMERIC_OR_HEX_LABEL = /^(?:[0-9]+|0x[0-9a-f]*)$/;
const IPV4_HOST = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const PORT = /^[1-9][0-9]{0,4}$/;
const DOT_SEGMENTS = new Set(['.', '..', '%2e', '%2e%2e', '.%2e', '%2e.']);
const printableAscii = (s, bad) => {
  for (let i = 0; i < s.length; i++) {
    const cp = s.charCodeAt(i);
    if (cp < 0x21 || cp > 0x7E || bad.includes(s[i])) return false;
  }
  return true;
};

// K-1 normalized https: URI check (no WHATWG URL parser required).
function httpsUri(v, { fragment, query = true, max = 512 }) {
  if (typeof v !== 'string' || v.length < 1 || v.length > max || !v.startsWith('https://')) return false;
  let rest = v.slice('https://'.length);
  const hashIdx = rest.indexOf('#');
  if (hashIdx >= 0) {
    if (!fragment) return false;
    const frag = rest.slice(hashIdx + 1);
    if (frag.length === 0 || !printableAscii(frag, ' "#<>`')) return false;
    rest = rest.slice(0, hashIdx);
  } else if (fragment) {
    return false;
  }
  const qIdx = rest.indexOf('?');
  if (qIdx >= 0) {
    if (!query) return false;
    const q = rest.slice(qIdx + 1);
    if (!printableAscii(q, ' "#<>\'')) return false;
    rest = rest.slice(0, qIdx);
  }
  const slash = rest.indexOf('/');
  if (slash < 1) return false;
  const authority = rest.slice(0, slash);
  const path = rest.slice(slash);
  if (authority.includes('@')) return false;
  const colonIdx = authority.indexOf(':');
  let host = authority;
  if (colonIdx >= 0) {
    if (authority.indexOf(':', colonIdx + 1) >= 0) return false;
    host = authority.slice(0, colonIdx);
    const portStr = authority.slice(colonIdx + 1);
    if (!PORT.test(portStr) || Number(portStr) > 65535 || portStr === '443') return false;
  }
  const isDns = host.length <= 253 && DNS_HOST.test(host) && !NUMERIC_OR_HEX_LABEL.test(host.slice(host.lastIndexOf('.') + 1));
  if (!isDns && !IPV4_HOST.test(host)) return false;
  if (!printableAscii(path, ' "#<>?`{}\\')) return false;
  for (const seg of path.split('/').slice(1)) {
    if (DOT_SEGMENTS.has(seg.toLowerCase())) return false;
  }
  return true;
}
const distinct = a => new Set(a).size === a.length;

function envelope(r, typ) {
  const allowed = new Set(['darep', 'id', 'source', 'type', 'subject', 'time', 'to', 'thread', 'inReplyTo', 'expires', 'ext', 'required', 'grant', 'data']);
  for (const k of Object.keys(r)) must(allowed.has(k), 'malformed', 'unknown member ' + k);
  for (const k of ['id', 'source', 'type', 'time', 'to', 'thread', 'inReplyTo', 'ext', 'required', 'data']) must(Object.hasOwn(r, k), 'malformed', 'missing ' + k);
  must(isUuid(r.id) && isUuid(r.thread), 'malformed', 'id/thread');
  must(r.inReplyTo === null || isUuid(r.inReplyTo), 'malformed', 'inReplyTo');
  must(r.thread !== r.id || r.inReplyTo === null, 'malformed', 'an opening record has no inReplyTo');
  must(isAcct(r.source), 'malformed', 'source');
  must(httpsUri(r.type, { fragment: true }), 'malformed', 'type');
  must(!('subject' in r) || isStr(r.subject, 200), 'malformed', 'subject');
  const time = ms(r.time);
  must(Number.isFinite(time), 'malformed', 'time');
  must(Array.isArray(r.to) && r.to.length >= 1 && r.to.length <= 32 && distinct(r.to) &&
    r.to.every(isAcct) && !r.to.includes(r.source), 'malformed', 'to');
  must(isObj(r.ext) && Object.keys(r.ext).every(k => httpsUri(k, { fragment: false })), 'malformed', 'ext');
  must(Array.isArray(r.required) && r.required.length <= 32 && distinct(r.required) &&
    r.required.every(k => httpsUri(k, { fragment: false })), 'malformed', 'required');
  must(isObj(r.data), 'malformed', 'data');

  const kind = typ === TYPS.receipt ? 'receipt' : typ === TYPS.rejection ? 'rejection' : 'event';
  must(kind === 'event' ? ![CORE + '#receipt', CORE + '#rejection'].includes(r.type) : r.type === CORE + '#' + kind,
    'malformed', 'type does not match typ');
  if (kind === 'receipt') must(!('expires' in r), 'malformed', 'a receipt has no expires');
  else {
    const exp = ms(r.expires);
    must(Number.isFinite(exp) && exp > time && exp - time <= MAX_WINDOW, 'malformed', 'expires');
  }
  if (kind === 'event') {
    must(isObj(r.grant) && Object.keys(r.grant).length === 2 && isStr(r.grant.id, 200) &&
      ['owner', 'agent'].includes(r.grant.actor), 'malformed', 'grant');
  } else {
    must(!('grant' in r), 'malformed', 'provider records carry no grant');
    must(r.inReplyTo !== null && r.to.length === 1, 'malformed', 'receipt/rejection answers one record');
  }
  if (kind === 'receipt') {
    must(Object.keys(r.ext).length === 0 && r.required.length === 0 && !('subject' in r), 'malformed', 'a receipt carries no ext, required or subject');
    must(Object.keys(r.data).length === 2 && typeof r.data.sha256 === 'string' && /^[0-9a-f]{64}$/.test(r.data.sha256) &&
      Number.isFinite(ms(r.data.storedAt)), 'malformed', 'receipt data');
  }
  if (kind === 'rejection') {
    must(Object.keys(r.data).every(k => k === 'code' || k === 'detail') &&
      Object.hasOwn(r.data, 'code') && typeof r.data.code === 'string' &&
      (/^[a-z0-9-]{1,64}$/.test(r.data.code) || httpsUri(r.data.code, { fragment: true })) &&
      (!('detail' in r.data) || isStr(r.data.detail, 1000)), 'malformed', 'rejection data');
  }
}

// ---------- §8: verification procedure ----------
// Exported so that vectors/v2/delivery/generate.mjs --check can run every delivery record through the same steps.
// context.typ is the expected typ, or an array of them (a delivery endpoint expects events and rejections).

export function verifyRecord(jws, context, documents) {
  // 1. Compact serialization.
  const parts = jws.split('.');
  must(parts.length === 3 && parts.every(p => /^[A-Za-z0-9_-]*$/.test(p) && p.length % 4 !== 1 &&
    Buffer.from(p, 'base64url').toString('base64url') === p) && parts[0] && parts[1], 'malformed', 'not canonical compact JWS');
  // 2. Protected header is strict JSON.
  const header = strictJson(Buffer.from(parts[0], 'base64url'));
  must(isObj(header), 'malformed', 'header is not an object');
  // 3. Algorithm allow-list.
  must(header.alg === 'ES256', 'unsupported-alg', String(header.alg));
  // 4. typ, crit and kid.
  must([].concat(context.typ).includes(header.typ), 'bad-header', 'typ');
  must(!Object.hasOwn(header, 'crit') && !Object.hasOwn(header, 'b64'), 'bad-header', 'crit/b64');
  must(httpsUri(header.kid, { fragment: true, max: 2048 }), 'bad-header', 'kid');
  // 5. Resolve kid against pinned snapshots only.
  const docId = header.kid.slice(0, header.kid.indexOf('#'));
  const doc = documents.find(d => d.id === docId); // unique by P-0
  const key = doc?.keys.find(k => k.id === header.kid);
  must(key, 'unknown-key', header.kid);
  if (key.publicKeyJwk.crv !== 'P-256') throw new Error('pinned key is not P-256; P-0 should have refused it');
  // 6. Signature over the exact ASCII signing input.
  const sig = Buffer.from(parts[2], 'base64url');
  const ok = sig.length === 64 && nodeVerify('sha256', Buffer.from(parts[0] + '.' + parts[1], 'ascii'),
    { key: createPublicKey({ key: key.publicKeyJwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, sig);
  must(ok, 'bad-signature', 'signature');
  // 7. Payload is strict JSON.
  const payload = Buffer.from(parts[1], 'base64url');
  const record = strictJson(payload);
  must(isObj(record), 'malformed', 'payload is not an object');
  // 8. Protocol version.
  must(record.darep === '2', 'unsupported-version', String(record.darep));
  // 9. Envelope schema.
  envelope(record, header.typ);
  // 10. The pinned document lists the source address.
  must(doc.addresses.includes(record.source), 'signer-mismatch', record.source);
  // 11. Key purpose, revocation and validity at the record's time.
  const t = Date.parse(record.time);
  must(key.purpose.includes(PURPOSE[header.typ]), 'key-not-valid', 'purpose');
  must(!('revoked' in key), 'key-not-valid', 'revoked');
  must(Date.parse(key.validFrom) <= t && (!('validUntil' in key) || t < Date.parse(key.validUntil)), 'key-not-valid', 'validity');
  if (context.mode === 'admission') {
    const now = Date.parse(context.now);
    // 12. Recipient.
    must(record.to.includes(context.receiver), 'wrong-recipient', context.receiver);
    // 13. Clock. A receipt has no expires; its lower bound is the answered record's time (step 15, RC-1).
    must(t <= now + SKEW, 'not-yet-valid', record.time);
    if (header.typ !== TYPS.receipt) must(now < Date.parse(record.expires) + SKEW, 'expired', record.expires);
    // 14. Required extensions.
    for (const uri of record.required) must(context.understood.includes(uri), 'unsupported-extension', uri);
  }
  // 15. Correlation with the answered record, when it is known (RC-1), then TM-4a delivery window.
  if (context.answered && header.typ !== TYPS.event) {
    const [, p] = context.answered.split('.');
    const R = strictJson(Buffer.from(p, 'base64url'));
    must(R.to.includes(record.source) && record.to.length === 1 && record.to[0] === R.source &&
      record.inReplyTo === R.id && record.thread === R.thread, 'receipt-mismatch', 'correlation');
    must(t >= Date.parse(R.time) - SKEW, 'receipt-mismatch', 'answer predates the answered record');
    if (header.typ === TYPS.receipt) {
      must(record.data.sha256 === createHash('sha256').update(Buffer.from(p, 'base64url')).digest('hex'), 'receipt-mismatch', 'digest');
      // A sender stops accepting answers once its delivery of R has closed (TM-4a, delivery.md §7.3).
      if (context.mode === 'admission') {
        must(Date.parse(context.now) < Date.parse(R.expires) + SKEW, 'expired', 'delivery window of the answered record has closed');
      }
    }
  }
  return { header, record, payload };
}

// ---------- run ----------

// P-0: validate every snapshot before it may be used as a pin.
export function validatePins(documents) {
  if (!Array.isArray(documents)) throw new Error('pins must be an array');
  const ids = new Set(); const addrs = new Set();
  for (const d of documents) {
    const fail = why => { throw new Error(`identities.json: ${d?.id}: ${why}`); };
    if (!isObj(d) || d.darep !== '2' || !httpsUri(d.id, { fragment: false, query: false, max: 2048 }) || ids.has(d.id)) fail('bad or duplicate id');
    ids.add(d.id);
    if (!Array.isArray(d.addresses) || !d.addresses.length || !d.addresses.every(isAcct) || !distinct(d.addresses) || d.addresses.some(a => addrs.has(a))) fail('addresses');
    d.addresses.forEach(a => addrs.add(a));
    if (!Number.isFinite(ms(d.updated))) fail('updated');
    if (!Array.isArray(d.keys) || !d.keys.length) fail('keys');
    const kids = new Set();
    for (const k of d.keys) {
      if (!isObj(k) || typeof k.id !== 'string' || !k.id.startsWith(d.id + '#') || !/^[A-Za-z0-9._-]{1,64}$/.test(k.id.slice(d.id.length + 1)) || kids.has(k.id)) fail('key id');
      kids.add(k.id);
      const j = k.publicKeyJwk;
      if (!isObj(j) || Object.keys(j).sort().join() !== 'crv,kty,x,y' || j.kty !== 'EC' || j.crv !== 'P-256' ||
        ![j.x, j.y].every(v => typeof v === 'string' && v.length === 43 && /^[A-Za-z0-9_-]+$/.test(v) &&
          Buffer.from(v, 'base64url').length === 32 && Buffer.from(v, 'base64url').toString('base64url') === v)) fail('jwk ' + k.id);
      createPublicKey({ key: j, format: 'jwk' }); // throws unless the point is on the curve
      const p = k.purpose;
      if (!Array.isArray(p) || !p.length || !distinct(p) || !p.every(x => ['record', 'provider', 'root', 'delegate'].includes(x)) ||
        (p.length > 1 && p.some(x => x === 'root' || x === 'delegate'))) fail('purpose ' + k.id);
      if (!Number.isFinite(ms(k.validFrom)) || ('validUntil' in k && !(ms(k.validUntil) > ms(k.validFrom))) ||
        ('revoked' in k && !Number.isFinite(ms(k.revoked)))) fail('validity ' + k.id);
    }
  }
}

// Compares a parsed record with a vector's expected.record. expected.numbers selects how numbers compare:
// absent or "exact" (the default) requires equal values; "binary64" rounds both sides to IEEE 754 binary64 first,
// for vectors whose number lexemes exceed binary64 precision. The exact lexemes stay pinned by payloadUtf8 (NC1).
export function recordsMatch(got, expected, numbers = 'exact') {
  if (!['exact', 'binary64'].includes(numbers)) throw new Error('unknown expected.numbers mode: ' + numbers);
  if (numbers === 'exact') return JSON.stringify(got) === JSON.stringify(expected);
  // A JavaScript number is already a binary64 value, so the parsed values compare directly here; runners whose JSON
  // parser keeps more precision (Python's arbitrary-size integers) round both sides first.
  const same = (a, b) => {
    if (typeof a === 'number' || typeof b === 'number') return typeof a === typeof b && a === b;
    if (Array.isArray(a) || Array.isArray(b)) return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((x, i) => same(x, b[i]));
    if (a && b && typeof a === 'object' && typeof b === 'object') {
      const ka = Object.keys(a).sort(), kb = Object.keys(b).sort();
      return ka.length === kb.length && ka.every((k, i) => k === kb[i] && same(a[k], b[k]));
    }
    return a === b;
  };
  return same(got, expected);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();

async function main() {
const { documents } = await load('identities.json');
validatePins(documents);
const { vectors } = await load('index.json');
let failures = 0;
const results = {};
for (const { name } of vectors) {
  const v = await load(name + '.json');
  let got;
  try {
    const out = verifyRecord(v.jws, v.context, documents);
    got = { verdict: 'accept', kid: out.header.kid, record: out.record, sha: createHash('sha256').update(out.payload).digest('hex') };
  } catch (e) {
    if (!(e instanceof Reject)) throw e;
    got = { verdict: 'reject', code: e.code, why: e.message };
  }
  results[name] = got;
  let ok = got.verdict === v.expected.verdict;
  if (ok && got.verdict === 'reject') ok = got.code === v.expected.code;
  if (ok && got.verdict === 'accept') {
    ok = got.kid === v.expected.kid && recordsMatch(got.record, v.expected.record, v.expected.numbers) && got.sha === v.payloadSha256;
    if (ok && v.payloadUtf8 !== null) ok = Buffer.from(v.jws.split('.')[1], 'base64url').toString('utf8') === v.payloadUtf8;
  }
  if (ok && v.expected.receiptFor) {
    const target = await load(v.expected.receiptFor + '.json');
    ok = got.record.data.sha256 === target.payloadSha256 && got.record.inReplyTo === target.expected.record.id &&
      got.record.to[0] === target.expected.record.source;
  }
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name} → ${got.verdict}${got.code ? ` ${got.code} (${got.why})` : ''}${ok ? '' : ' MISMATCH'}`);
  if (!ok) failures++;
}
const { cases: invalidPins } = await load('invalid-identities.json');
for (const c of invalidPins) {
  let rejected = false;
  let why = '';
  try { validatePins([c.document]); } catch (e) { rejected = true; why = e.message; }
  console.log(`${rejected ? 'ok  ' : 'FAIL'} pin/${c.name} → ${rejected ? `reject (${why})` : 'accept MISMATCH'}`);
  if (!rejected) failures++;
}
// Harness self-test: each fixture passes with this verifier, and fails when the parsed numbers lose precision.
const fround = value => typeof value === 'number' ? Math.fround(value) : Array.isArray(value) ? value.map(fround)
  : value && typeof value === 'object' ? Object.fromEntries(Object.entries(value).map(([k, x]) => [k, fround(x)])) : value;
// pin-updates.json has its own format: it is for the kit's optional checkUpdate operation.
const selftests = (await readdir(new URL('selftest/', import.meta.url))).filter(f => f.endsWith('.json') && f !== 'pin-updates.json').sort();
for (const file of selftests) {
  const v = await load('selftest/' + file);
  const out = verifyRecord(v.jws, v.context, documents);
  const passes = recordsMatch(out.record, v.expected.record, v.expected.numbers);
  const caught = !recordsMatch(fround(out.record), v.expected.record, v.expected.numbers);
  console.log(`${passes && caught ? 'ok  ' : 'FAIL'} selftest/${file.slice(0, -5)} → matches ${passes}, binary32 verifier caught ${caught}`);
  if (!(passes && caught)) failures++;
}
console.log(failures ? `${failures} vector(s) failed` : `all ${vectors.length} vectors, ${invalidPins.length} pin cases and ${selftests.length} harness self-tests match records.md`);
process.exit(failures ? 1 : 0);
}
