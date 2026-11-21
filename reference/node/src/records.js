// DAREP Wire v2 signed records: spec/records.md.
//
// This module owns the records layer only: strict JSON, the JWS protected header, the record envelope,
// identity documents and the §8 verification procedure. It knows nothing about storage or delivery.
// Every check is written against the received bytes. A payload is never parsed and re-serialized
// before it is verified, hashed or stored (NC1).

import { createHash, createPrivateKey, createPublicKey, randomUUID, sign as nodeSign, verify as nodeVerify } from 'node:crypto';

export const darepVersion = '2';
export const algorithms = Object.freeze(['ES256']); // records.md §3.1 A-1
export const typs = Object.freeze({
  event: 'darep-event+jws',
  receipt: 'darep-receipt+jws',
  rejection: 'darep-rejection+jws',
});
export const coreExtension = 'https://darep.org/ext/core/v2';
export const receiptType = coreExtension + '#receipt';
export const rejectionType = coreExtension + '#rejection';
export const messageType = coreExtension + '#message';
export const skew = 300_000; // records.md §7.2
export const maxWindow = 30 * 24 * 3600_000; // records.md TM-2
export const defaultLifetime = 7 * 24 * 3600_000; // records.md §4.3: senders SHOULD use 7 days
const purposeFor = { [typs.event]: 'record', [typs.receipt]: 'provider', [typs.rejection]: 'provider' };
const purposes = ['record', 'provider', 'root', 'delegate'];
const reservedPurposes = ['root', 'delegate'];

// HTTPS binding §3. The sender-side result receipt-mismatch never travels; 502 marks a bad peer answer locally.
export const statusFor = {
  'method-not-allowed': 405, 'unsupported-media-type': 415, 'too-large': 413, 'rate-limited': 429, 'unavailable': 503,
  'malformed': 400, 'bad-header': 400, 'unsupported-alg': 400, 'bad-signature': 400, 'unsupported-version': 400,
  'unknown-key': 403, 'signer-mismatch': 403, 'key-not-valid': 403, 'wrong-recipient': 403,
  'id-conflict': 409, 'expired': 422, 'unsupported-extension': 422, 'not-yet-valid': 425,
  'receipt-mismatch': 502,
};

// A verification failure with its code from the delivery contract's registry (delivery.md §5).
export class RecordRejection extends Error {
  constructor(code, reason) {
    super(reason ?? code);
    this.code = code;
    this.status = statusFor[code] ?? 400;
  }
}
const must = (ok, code, reason) => { if (!ok) throw new RecordRejection(code, reason); };

export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

// ---------- §2: bytes and strict JSON ----------

// UTF-8 without a BOM, I-JSON (RFC 7493), and no duplicate member names (J-2). Returns the value and the text.
export function strictJson(bytes) {
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); }
  catch { throw new RecordRejection('malformed', 'not UTF-8'); }
  must(!text.startsWith('﻿'), 'malformed', 'byte order mark');
  let i = 0;
  const fail = why => { throw new RecordRejection('malformed', why + ' at ' + i); };
  const ws = () => { while (i < text.length && (text[i] === ' ' || text[i] === '\t' || text[i] === '\n' || text[i] === '\r')) i++; };
  const stringToken = /"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/y;
  const literalToken = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null/y;
  function string() {
    stringToken.lastIndex = i;
    const m = stringToken.exec(text);
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
  function literal() {
    literalToken.lastIndex = i;
    const m = literalToken.exec(text);
    if (!m) fail('unexpected token');
    i += m[0].length;
    const v = JSON.parse(m[0]);
    if (typeof v === 'number' && !Number.isFinite(v)) fail('number out of range');
    return v;
  }
  function memberName(frame) {
    ws();
    if (text[i] !== '"') fail('expected member name');
    const k = string();
    if (frame.seen.has(k)) fail('duplicate member ' + JSON.stringify(k));
    frame.seen.add(k);
    ws();
    if (text[i++] !== ':') fail('expected colon');
    return k;
  }
  // Iterative, so nesting depth is bounded only by the input size (delivery.md §3.4), never by the call stack.
  function value() {
    const stack = [];
    for (;;) {
      ws();
      let v;
      const c = text[i];
      if (c === '{') {
        i++; ws();
        if (text[i] === '}') { i++; v = {}; }
        else { const frame = { obj: {}, seen: new Set() }; frame.key = memberName(frame); stack.push(frame); continue; }
      } else if (c === '[') {
        i++; ws();
        if (text[i] === ']') { i++; v = []; } else { stack.push({ arr: [] }); continue; }
      } else v = c === '"' ? string() : literal();
      for (;;) {
        const top = stack.at(-1);
        if (!top) return v;
        if (top.arr) top.arr.push(v);
        // defineProperty keeps "__proto__" an ordinary member instead of changing the prototype.
        else Object.defineProperty(top.obj, top.key, { value: v, enumerable: true, writable: true, configurable: true });
        ws();
        if (text[i] === ',') {
          i++;
          if (top.obj) top.key = memberName(top);
          break;
        }
        if (text[i] === (top.arr ? ']' : '}')) { i++; stack.pop(); v = top.arr ?? top.obj; continue; }
        fail(top.arr ? 'expected , or ]' : 'expected , or }');
      }
    }
  }
  const v = value();
  ws();
  if (i !== text.length) fail('trailing data');
  return { value: v, text };
}

// ---------- §3: compact serialization and header ----------

const segment = /^[A-Za-z0-9_-]*$/;
// S-1: canonical unpadded base64url. Node's decoder silently drops dangling characters, so re-encode and compare.
function canonicalSegment(s) {
  return segment.test(s) && s.length % 4 !== 1 && Buffer.from(s, 'base64url').toString('base64url') === s;
}
const isObj = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const distinct = a => new Set(a).size === a.length;

// K-1: validate the wire spelling directly; URL parsers silently normalize invalid input.
const LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
const DNS_HOST = new RegExp('^' + LABEL + '(?:\\.' + LABEL + ')+$');
const NUMERIC_LABEL = /^(?:[0-9]+|0x[0-9a-f]*)$/;
const IPV4 = /^(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$/;
export function isUriHost(host, { testOnly = false } = {}) {
  if (typeof host !== 'string' || /[^a-z0-9.-]/.test(host)) return false;
  const dns = host.length <= 253 && DNS_HOST.test(host) && !NUMERIC_LABEL.test(host.split('.').at(-1));
  return dns || (testOnly && IPV4.test(host));
}
const printable = (value, forbidden) => [...value].every(c =>
  c.charCodeAt(0) >= 0x21 && c.charCodeAt(0) <= 0x7e && !forbidden.includes(c));
const dotSegments = new Set(['.', '..', '%2e', '%2e%2e', '.%2e', '%2e.']);
export function isHttpsUri(v, { fragment, max = 512, query = true, testOnly = false }) {
  if (typeof v !== 'string' || v.length < 1 || v.length > max || !v.startsWith('https://') || !printable(v, '')) return false;
  let rest = v.slice(8);
  const hash = rest.indexOf('#');
  if (hash >= 0) {
    const value = rest.slice(hash + 1);
    if (!fragment || !value || !printable(value, ' "#<>`')) return false;
    rest = rest.slice(0, hash);
  } else if (fragment) return false;
  const question = rest.indexOf('?');
  if (question >= 0) {
    if (!query || !printable(rest.slice(question + 1), " \"#<>'")) return false;
    rest = rest.slice(0, question);
  }
  const slash = rest.indexOf('/');
  if (slash < 1) return false;
  const authority = rest.slice(0, slash), path = rest.slice(slash);
  const [host, port, extra] = authority.split(':');
  if (extra !== undefined || !isUriHost(host, { testOnly })) return false;
  if (port !== undefined && (!/^[1-9][0-9]{0,4}$/.test(port) || Number(port) > 65535 || port === '443')) return false;
  if (!printable(path, ' "#<>?`{}\\')) return false;
  return path.split('/').every(part => !dotSegments.has(part.toLowerCase()));
}

// ---------- §4: envelope ----------

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export const addressPattern = new RegExp('^acct:[a-z0-9][a-z0-9._-]{0,62}@' + LABEL + '(?:\\.' + LABEL + ')+$');
const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
const isUuid = v => typeof v === 'string' && UUID.test(v);
export const isAddress = v => typeof v === 'string' && v.length <= 200 && addressPattern.test(v);
const isText = (v, max) => typeof v === 'string' && v.length >= 1 && [...v].length <= max;
// TM-1: a UTC instant that is also a real calendar instant. Returns milliseconds or NaN.
export function instant(t) {
  if (typeof t !== 'string' || !TIME.test(t)) return NaN;
  const n = Date.parse(t);
  return Number.isFinite(n) && new Date(n).toISOString().slice(0, 19) === t.slice(0, 19) ? n : NaN;
}
// Registered post-store codes. Verification also accepts syntactically valid unknown refusal codes.
export const postStoreCodes = Object.freeze(['stale-head', 'wrong-turn', 'invalid-transition', 'invalid-data',
  'missing-predecessor', 'expired-before-apply', 'policy-denied', 'unsupported-type']);
const members = new Set(['darep', 'id', 'source', 'type', 'subject', 'time', 'to', 'thread', 'inReplyTo',
  'expires', 'ext', 'required', 'grant', 'data']);

// records.md §4 for the given typ (step 9). Assumes darep === '2' was already checked (E-1).
export function checkEnvelope(r, typ) {
  for (const k of Object.keys(r)) must(members.has(k), 'malformed', 'unknown member ' + k);
  for (const k of ['darep', 'id', 'source', 'type', 'time', 'to', 'thread', 'inReplyTo', 'ext', 'required', 'data']) {
    must(Object.hasOwn(r, k), 'malformed', 'missing ' + k);
  }
  must(isUuid(r.id) && isUuid(r.thread), 'malformed', 'id/thread');
  must(r.inReplyTo === null || isUuid(r.inReplyTo), 'malformed', 'inReplyTo');
  must(r.thread !== r.id || r.inReplyTo === null, 'malformed', 'an opening record has no inReplyTo');
  must(isAddress(r.source), 'malformed', 'source');
  must(isHttpsUri(r.type, { fragment: true }), 'malformed', 'type');
  must(!Object.hasOwn(r, 'subject') || isText(r.subject, 200), 'malformed', 'subject');
  const time = instant(r.time);
  must(Number.isFinite(time), 'malformed', 'time');
  must(Array.isArray(r.to) && r.to.length >= 1 && r.to.length <= 32 && distinct(r.to) &&
    r.to.every(isAddress) && !r.to.includes(r.source), 'malformed', 'to');
  must(isObj(r.ext) && Object.keys(r.ext).every(k => isHttpsUri(k, { fragment: false })), 'malformed', 'ext');
  must(Array.isArray(r.required) && r.required.length <= 32 && distinct(r.required) &&
    r.required.every(k => isHttpsUri(k, { fragment: false })), 'malformed', 'required');
  must(isObj(r.data), 'malformed', 'data');

  const kind = typ === typs.receipt ? 'receipt' : typ === typs.rejection ? 'rejection' : 'event';
  must(kind === 'event' ? r.type !== receiptType && r.type !== rejectionType : r.type === coreExtension + '#' + kind,
    'malformed', 'type does not match typ');
  if (kind === 'receipt') must(!Object.hasOwn(r, 'expires'), 'malformed', 'a receipt has no expires');
  else {
    const exp = instant(r.expires);
    must(Number.isFinite(exp) && exp > time && exp - time <= maxWindow, 'malformed', 'expires');
  }
  if (kind === 'event') {
    must(isObj(r.grant) && Object.keys(r.grant).length === 2 && isText(r.grant.id, 200) &&
      (r.grant.actor === 'owner' || r.grant.actor === 'agent'), 'malformed', 'grant');
  } else {
    must(!Object.hasOwn(r, 'grant'), 'malformed', 'provider records carry no grant');
    must(r.inReplyTo !== null && r.to.length === 1, 'malformed', 'a receipt or rejection answers one record');
  }
  if (kind === 'receipt') {
    must(Object.keys(r.ext).length === 0 && r.required.length === 0 && !Object.hasOwn(r, 'subject'),
      'malformed', 'a receipt carries no ext, required or subject');
    must(Object.keys(r.data).length === 2 && typeof r.data.sha256 === 'string' && /^[0-9a-f]{64}$/.test(r.data.sha256) &&
      Number.isFinite(instant(r.data.storedAt)), 'malformed', 'receipt data');
  }
  if (kind === 'rejection') {
    must(Object.keys(r.data).every(k => k === 'code' || k === 'detail') && typeof r.data.code === 'string' &&
      ((r.data.code.length >= 1 && r.data.code.length <= 64 && !/[^a-z0-9-]/.test(r.data.code)) || isHttpsUri(r.data.code, { fragment: true })) &&
      (!Object.hasOwn(r.data, 'detail') || isText(r.data.detail, 1000)), 'malformed', 'rejection data');
  }
}

// ---------- §5: identity documents ----------

const jwkMembers = 'crv,kty,x,y';
export function publicKeyOf(jwk) {
  return createPublicKey({ key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, format: 'jwk' });
}

// P-0 for one document: §5.1 shape and §5.2 purposes. Cross-document rules (TA-4) belong to the pin store.
export function validateDocument(d) {
  const fail = why => { throw new RecordRejection('malformed', 'identity document: ' + why); };
  if (!isObj(d) || d.darep !== darepVersion || !isHttpsUri(d.id, { fragment: false, query: false, max: 2048 })) fail('id');
  if (!Array.isArray(d.addresses) || !d.addresses.length || !d.addresses.every(isAddress) || !distinct(d.addresses)) fail('addresses');
  if (!Number.isFinite(instant(d.updated))) fail('updated');
  if (!Array.isArray(d.keys) || !d.keys.length) fail('keys');
  const ids = new Set();
  for (const k of d.keys) {
    if (!isObj(k) || typeof k.id !== 'string' || !k.id.startsWith(d.id + '#') ||
      !/^[A-Za-z0-9._-]{1,64}$/.test(k.id.slice(d.id.length + 1)) || ids.has(k.id)) fail('key id');
    ids.add(k.id);
    const j = k.publicKeyJwk;
    if (!isObj(j) || Object.keys(j).sort().join() !== jwkMembers || j.kty !== 'EC' || j.crv !== 'P-256' ||
      ![j.x, j.y].every(v => typeof v === 'string' && v.length === 43 && /^[A-Za-z0-9_-]+$/.test(v) &&
        Buffer.from(v, 'base64url').length === 32 && Buffer.from(v, 'base64url').toString('base64url') === v)) fail('publicKeyJwk ' + k.id);
    try { publicKeyOf(j); } catch { fail('publicKeyJwk is not a P-256 point ' + k.id); }
    const p = k.purpose;
    if (!Array.isArray(p) || !p.length || !distinct(p) || !p.every(x => purposes.includes(x)) ||
      (p.length > 1 && p.some(x => reservedPurposes.includes(x)))) fail('purpose ' + k.id);
    const from = instant(k.validFrom);
    if (!Number.isFinite(from) || (Object.hasOwn(k, 'validUntil') && !(instant(k.validUntil) > from)) ||
      (Object.hasOwn(k, 'revoked') && !Number.isFinite(instant(k.revoked)))) fail('validity ' + k.id);
  }
  return d;
}

// §5.5: a newer snapshot the owner may accept as a routine rotation, with no new trust decision.
export function isMonotonicUpdate(old, next) {
  if (old.id !== next.id || !old.addresses.every(a => next.addresses.includes(a))) return false;
  const earlierOrSame = (was, now) => was === undefined ? true : now !== undefined && instant(now) <= instant(was);
  return old.keys.every(k => {
    const n = next.keys.find(x => x.id === k.id);
    return n && JSON.stringify(n.publicKeyJwk, ['crv', 'kty', 'x', 'y']) === JSON.stringify(k.publicKeyJwk, ['crv', 'kty', 'x', 'y']) &&
      JSON.stringify(n.purpose) === JSON.stringify(k.purpose) && n.validFrom === k.validFrom &&
      earlierOrSame(k.validUntil, n.validUntil) && earlierOrSame(k.revoked, n.revoked);
  });
}

// The recommended document URL for an address (records.md §5.1): https://<domain>/.well-known/darep/<name>.
export function documentIdFor(address) {
  const [, name, domain] = /^acct:([^@]+)@(.+)$/.exec(address);
  const id = 'https://' + domain + '/.well-known/darep/' + name;
  if (!isHttpsUri(id, { fragment: false, max: 2048 })) throw new Error('Address has no normalized document URL');
  return id;
}
// RFC 7638 thumbprint, used to name a key's fragment deterministically.
export function thumbprint(jwk) {
  return createHash('sha256').update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })).digest('base64url');
}
// A one-key identity document, like the test identity Carol: one key with both active purposes.
export function makeIdentityDocument(address, publicKey, validFrom = new Date()) {
  const key = publicKey?.type === 'public' ? publicKey : createPublicKey(publicKey);
  const { kty, crv, x, y } = key.export({ format: 'jwk' });
  const id = documentIdFor(address);
  const from = new Date(Math.floor(validFrom.getTime() / 1000) * 1000).toISOString().replace('.000Z', 'Z');
  return validateDocument({
    darep: darepVersion, id, addresses: [address], updated: from,
    keys: [{ id: id + '#key-' + thumbprint({ kty, crv, x, y }).slice(0, 16), purpose: ['record', 'provider'],
      publicKeyJwk: { kty, crv, x, y }, validFrom: from }],
  });
}

// ---------- signing ----------

const b64 = s => Buffer.from(s).toString('base64url');

// Low-level compact JWS signing over exact bytes. The header carries only alg, kid and typ (H-4).
export function signCompact(payload, signer, typ) {
  const key = signer.key.type === 'private' ? signer.key : createPrivateKey(signer.key);
  const input = b64(JSON.stringify({ alg: 'ES256', kid: signer.kid, typ })) + '.' + b64(payload);
  const signature = nodeSign('sha256', Buffer.from(input, 'ascii'), { key, dsaEncoding: 'ieee-p1363' });
  return input + '.' + signature.toString('base64url');
}

// Sign a record body exactly as given. A conformant signer emits only records a verifier accepts,
// so the envelope is checked first; the body is never re-serialized.
export function signRecord(body, signer, typ) {
  must(purposeFor[typ], 'bad-header', 'unknown typ');
  const { value } = strictJson(Buffer.from(body, 'utf8'));
  must(isObj(value) && value.darep === darepVersion, 'unsupported-version', 'not a Wire v2 record');
  checkEnvelope(value, typ);
  return signCompact(body, signer, typ);
}

// ---------- §8: verification ----------

// Decode a compact JWS payload without verifying it. Only for routing hints and pairing codes whose
// key travels inside the payload; never a substitute for verifyRecord.
export function unverifiedPayload(token) {
  must(typeof token === 'string', 'malformed', 'not a string');
  const parts = token.split('.');
  must(parts.length === 3 && canonicalSegment(parts[1]) && parts[1], 'malformed', 'not compact JWS');
  return strictJson(Buffer.from(parts[1], 'base64url')).value;
}

// Steps 1–7: framing, header, alg, typ/crit/b64/kid, key resolution, signature, strict payload JSON.
// resolve(documentId) returns a pinned, P-0-validated document or null.
export function verifyCompact(token, expectedTyp, resolve) {
  // 1. Exactly three canonical base64url segments; header and payload non-empty.
  must(typeof token === 'string', 'malformed', 'not a string');
  const parts = token.split('.');
  must(parts.length === 3 && parts.every(canonicalSegment) && parts[0] && parts[1], 'malformed', 'not canonical compact JWS');
  // 2. Strict JSON header.
  const header = strictJson(Buffer.from(parts[0], 'base64url')).value;
  must(isObj(header), 'malformed', 'header is not an object');
  // 3. Allow-list, before any key lookup (A-2).
  must(algorithms.includes(header.alg), 'unsupported-alg', 'alg');
  // 4. typ from context, no crit, no b64, kid is a normalized https URL with a fragment.
  must([].concat(expectedTyp).includes(header.typ), 'bad-header', 'typ');
  must(!Object.hasOwn(header, 'crit') && !Object.hasOwn(header, 'b64'), 'bad-header', 'crit or b64');
  must(isHttpsUri(header.kid, { fragment: true, max: 2048 }), 'bad-header', 'kid');
  // 5. Resolve against pinned snapshots only (TA-3, P-2). Header jwk/jku/x5* are never consulted (H-3).
  const documentId = header.kid.slice(0, header.kid.indexOf('#'));
  const document = resolve(documentId);
  const key = document && document.id === documentId ? document.keys.find(k => k.id === header.kid) : undefined;
  must(key, 'unknown-key', 'kid');
  // 6. 64-byte R||S over the exact ASCII signing input (A-1, C-2).
  const signature = Buffer.from(parts[2], 'base64url');
  must(signature.length === 64 && nodeVerify('sha256', Buffer.from(parts[0] + '.' + parts[1], 'ascii'),
    { key: publicKeyOf(key.publicKeyJwk), dsaEncoding: 'ieee-p1363' }, signature), 'bad-signature', 'signature');
  // 7. Strict JSON payload.
  const payload = Buffer.from(parts[1], 'base64url');
  const { value, text } = strictJson(payload);
  must(isObj(value), 'malformed', 'payload is not an object');
  return { header, kid: header.kid, document, key, payload, body: text, value };
}

function answeredRecord(answered) {
  const parts = typeof answered === 'string' ? answered.split('.') : [];
  if (parts.length !== 3) throw new Error('context.answered must be the compact JWS of the answered record');
  const payload = Buffer.from(parts[1], 'base64url');
  return { record: strictJson(payload).value, payload };
}

// The full records.md §8 procedure. context:
//   typ         expected typ or array of typs (§3.2)
//   mode        'admission' (default) or 'evidence' (§7.3: skips steps 12–14)
//   now         verifier clock in ms (admission)
//   receiver    the recipient address of this delivery (admission)
//   hosted      false when the receiver does not host that address (step 12)
//   understood  extension URIs the receiver implements (admission)
//   answered    compact JWS of the record a receipt or rejection answers (step 15)
//   dedupe      optional (record, payload) => prior result; runs between steps 12 and 13 (delivery.md §3.1).
//               A truthy result ends verification with { duplicate } so a late retry still gets its receipt.
// Returns { header, kid, document, key, payload, body, record, duplicate? } or throws RecordRejection.
export function verifyRecord(token, context, resolve) {
  const verified = verifyCompact(token, context.typ, resolve);
  const { header, document, key, value: record } = verified;
  // 8. Version first (E-1).
  must(record.darep === darepVersion, 'unsupported-version', 'darep');
  // 9. Envelope for this typ.
  checkEnvelope(record, header.typ);
  // 10. The key's document lists the source (TA-4).
  must(document.addresses.includes(record.source), 'signer-mismatch', 'source');
  // 11. Purpose, revocation, validity at the record's own time, no skew (R-3, R-4).
  const t = instant(record.time);
  must(key.purpose.includes(purposeFor[header.typ]), 'key-not-valid', 'purpose');
  must(!Object.hasOwn(key, 'revoked'), 'key-not-valid', 'revoked');
  must(instant(key.validFrom) <= t && (!Object.hasOwn(key, 'validUntil') || t < instant(key.validUntil)), 'key-not-valid', 'validity');
  const result = { ...verified, record };
  const admission = (context.mode ?? 'admission') === 'admission';
  if (admission) {
    if (!Number.isFinite(context.now) || typeof context.receiver !== 'string') throw new Error('Admission mode needs now and receiver');
    // 12. This delivery's recipient is in to[] and hosted here.
    must(context.hosted !== false && record.to.includes(context.receiver), 'wrong-recipient', 'recipient');
    if (context.dedupe) {
      const duplicate = context.dedupe(record, verified.payload);
      if (duplicate) return { ...result, duplicate };
    }
    // 13. Clock. A receipt has no expires; its lower bound comes from the answered record (step 15).
    must(t <= context.now + skew, 'not-yet-valid', 'time');
    if (header.typ !== typs.receipt) must(context.now < instant(record.expires) + skew, 'expired', 'expires');
    // 14. Required extensions.
    const understood = context.understood ?? [];
    for (const uri of record.required) must(understood.includes(uri), 'unsupported-extension', uri);
  }
  // 15. Correlation with the answered record R (RC-1, TM-4a).
  if (context.answered && header.typ !== typs.event) {
    const { record: R, payload } = answeredRecord(context.answered);
    must(Array.isArray(R.to) && R.to.includes(record.source) && record.to.length === 1 && record.to[0] === R.source &&
      record.inReplyTo === R.id && record.thread === R.thread, 'receipt-mismatch', 'correlation');
    must(t >= instant(R.time) - skew, 'receipt-mismatch', 'answer predates the answered record');
    // RC-1 includes the digest, and step 15 runs all of RC-1 before the delivery-window check.
    if (header.typ === typs.receipt) must(record.data.sha256 === sha256(payload), 'receipt-mismatch', 'digest');
    if (header.typ === typs.receipt && admission) {
      must(context.now < instant(R.expires) + skew, 'expired', 'delivery window of the answered record has closed');
    }
  }
  return result;
}

// ---------- record builders ----------

const isoNow = now => new Date(now).toISOString();

// An event (§4.3). `type` is an extension URI plus '#' plus the type name.
export function makeEventRecord({ source, to, type, thread, inReplyTo = null, data, grant, now = Date.now(),
  lifetime = defaultLifetime, required = [type.slice(0, type.indexOf('#'))], ext = {}, id = randomUUID() }) {
  return { darep: darepVersion, id, source, type, time: isoNow(now), to: [].concat(to), thread: thread ?? id,
    inReplyTo, expires: isoNow(now + lifetime), ext, required, grant, data };
}
// A storage receipt (§4.4) for a received record, from the recipient address of that delivery.
export function makeReceiptRecord(source, record, { sha256: digest, storedAt }, now = Date.now()) {
  return { darep: darepVersion, id: randomUUID(), source, type: receiptType, time: isoNow(now), to: [record.source],
    thread: record.thread, inReplyTo: record.id, ext: {}, required: [], data: { sha256: digest, storedAt } };
}
