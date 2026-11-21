import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { validatePins, verifyRecord } from '../../vectors/v2/records/check.mjs';

// Offline Wire v2 check: the spec's reference verifier (records.md §8) accepts a Python-signed handoff and the
// receipt the Python receive pipeline issued for it. Regenerate with reference/python/make_vector.py.
const vector = JSON.parse(await readFile(new URL('./vectors/handoff-v2.json', import.meta.url), 'utf8'));
validatePins(vector.identities);
const event = verifyRecord(vector.event.jws, vector.event.context, vector.identities);
assert.equal(event.payload.toString('utf8'), vector.event.payloadUtf8);
const sha = createHash('sha256').update(event.payload).digest('hex');
assert.equal(sha, vector.event.payloadSha256);
const receipt = verifyRecord(vector.receipt.jws, vector.receipt.context, vector.identities);
assert.equal(receipt.record.data.sha256, sha);
assert.equal(receipt.record.inReplyTo, event.record.id);
console.log('Node reference verifier accepted the Python-signed record and the Python receipt:', sha);
