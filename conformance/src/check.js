// The kit judges every signed object the implementation produces with the spec's own reference verifier.
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';
import { vectorsRoot } from './repo.js';

const reference = await import(pathToFileURL(join(vectorsRoot, 'records', 'check.mjs')).href);

export const TYP = { event: 'darep-event+jws', receipt: 'darep-receipt+jws', rejection: 'darep-rejection+jws' };
export const CORE = 'https://darep.org/ext/core/v2';
export const MESSAGE = CORE + '#message';
export const RECEIPT = CORE + '#receipt';
export const REJECTION = CORE + '#rejection';
export const SKEW_MS = 300_000;

// Returns { ok: true, record, header, payload } or { ok: false, code, why }.
export function referenceVerify(jws, context, documents) {
  try {
    const out = reference.verifyRecord(jws, context, documents);
    return { ok: true, record: out.record, header: out.header, payload: out.payload };
  } catch (error) {
    if (error.code) return { ok: false, code: error.code, why: error.message };
    throw error;
  }
}
export function validPins(documents) {
  try { reference.validatePins(documents); return true; } catch { return false; }
}
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export const payloadOf = jws => Buffer.from(String(jws).split('.')[1] ?? '', 'base64url');
export const headerOf = jws => JSON.parse(Buffer.from(String(jws).split('.')[0] ?? '', 'base64url').toString('utf8'));
export const dotted = (object, path) => path.split('.').reduce((o, k) => (o == null ? undefined : o[k]), object);
export const sameJson = (a, b) => JSON.stringify(a) === JSON.stringify(b);
// Deep equality independent of member order.
export function deepEqual(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null || typeof a !== 'object') return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const ka = Object.keys(a), kb = Object.keys(b);
  return ka.length === kb.length && ka.every(k => Object.hasOwn(b, k) && deepEqual(a[k], b[k]));
}
