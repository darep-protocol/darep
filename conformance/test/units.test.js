// Unit tests for rules that the reference implementations never break, so the end-to-end runs cannot show them.
import assert from 'node:assert/strict';
import test from 'node:test';
import { checkProblem } from '../src/problem.js';
import { Failure, Report } from '../src/report.js';
import { recordKey, requestBody } from '../src/offline/delivery.js';
import { rawHead, rawOctets } from '../src/http.js';

test('harness helpers: source-qualified keys, strict base64 bodies and raw octets', () => {
  const v = { records: { a: { envelope: { id: 'x', source: 'acct:a@t.test' } }, b: { envelope: { id: 'x', source: 'acct:b@t.test' } },
    c: { envelope: { id: 'y', source: 'acct:a@t.test' } } } };
  assert.throws(() => recordKey(v, 'x'), Failure);
  assert.deepEqual(recordKey(v, 'x', 'acct:b@t.test'), { source: 'acct:b@t.test', id: 'x' });
  assert.deepEqual(recordKey(v, 'y'), { source: 'acct:a@t.test', id: 'y' });
  assert.deepEqual(recordKey(v, { source: 's', id: 'x' }), { source: 's', id: 'x' });
  assert.deepEqual([...requestBody({ bodyBase64: '//4=' })], [0xff, 0xfe]);
  assert.throws(() => requestBody({ bodyBase64: '//4' }), /invalid base64/);
  const raw = { segments: [{ text: 'HTTP/1.1 503 Busy\r\nRetry-After: 7\r\n\r\n' }, { base64: '/w==' }, { fill: { octet: 'a', length: 2 } }], end: 'reset' };
  assert.deepEqual(rawOctets(raw), Buffer.concat([Buffer.from('HTTP/1.1 503 Busy\r\nRetry-After: 7\r\n\r\n'), Buffer.from([0xff]), Buffer.from('aa')]));
  assert.deepEqual(rawHead(raw), { status: 503, headers: { 'retry-after': '7' } });
  assert.equal(rawHead({ segments: [{ text: 'HTTP/1.1 200 OK\r\n' }] }).status, null);
  assert.throws(() => rawOctets({ segments: [], end: 'rst' }), /raw.end/);
  assert.throws(() => rawOctets({ segments: [{ fill: { octet: 'ab', length: 1 } }] }), /one octet/);
});

const response = (status, problem, headers = {}) => ({ status, headers: { 'content-type': 'application/problem+json', ...headers },
  body: Buffer.from(JSON.stringify(problem)) });
const base = code => ({ type: 'https://darep.org/problems/' + code, title: code, status: 0, code });

test('a problem may not echo "record" before the signature is verified', () => {
  const p = { ...base('bad-signature'), status: 400, record: '4c4e56c6-f183-4faf-8ef5-5f74dd79d8a1' };
  assert.throws(() => checkProblem(response(400, p), { code: 'bad-signature', status: 400 }), Failure);
  const late = { ...base('id-conflict'), status: 409, record: 'r1' };
  assert.doesNotThrow(() => checkProblem(response(409, late), { code: 'id-conflict', status: 409, recordId: 'r1' }));
  assert.throws(() => checkProblem(response(409, late), { code: 'id-conflict', status: 409, recordId: 'r2' }), Failure);
});

test('problem members, detail length and Allow are checked', () => {
  assert.throws(() => checkProblem(response(400, { ...base('malformed'), status: 400, extra: 1 }), { code: 'malformed', status: 400 }), Failure);
  assert.throws(() => checkProblem(response(400, { ...base('malformed'), status: 400, detail: 'x'.repeat(1001) }), { code: 'malformed', status: 400 }), Failure);
  assert.throws(() => checkProblem(response(405, { ...base('method-not-allowed'), status: 405 }), { code: 'method-not-allowed', status: 405 }), Failure);
  assert.doesNotThrow(() => checkProblem(response(405, { ...base('method-not-allowed'), status: 405 }, { allow: 'POST' }), { code: 'method-not-allowed', status: 405 }));
});

test('a declared role whose cases were all skipped is not in the scope of a pass', () => {
  const report = new Report({ adapterCommand: 'x', modes: ['offline'] });
  report.role('verifier', true);
  report.role('sender', true);
  report.add({ id: 'a', mode: 'offline', role: 'verifier', status: 'pass', refs: ['records.md §8'] });
  report.add({ id: 'b', mode: 'offline', role: 'sender', status: 'skip', refs: ['delivery.md §7'] });
  const s = report.summary();
  assert.equal(s.passes, true);
  assert.deepEqual(s.tested, ['verifier']);
});

test('nothing executed means no pass', () => {
  const report = new Report({ adapterCommand: 'x', modes: ['offline'] });
  report.role('verifier', true);
  report.add({ id: 'a', mode: 'offline', role: 'verifier', status: 'skip', refs: ['records.md §8'] });
  assert.equal(report.summary().passes, false);
});

test('every case must cite a spec clause', () => {
  const report = new Report({ adapterCommand: 'x', modes: ['offline'] });
  assert.throws(() => report.add({ id: 'a', mode: 'offline', role: 'verifier', status: 'pass' }));
});

test('a skipped required case takes its role out of scope; an optional one does not', () => {
  const report = new Report({ adapterCommand: 'x', modes: ['offline'] });
  report.role('receiver', true);
  report.role('sender', true);
  report.add({ id: 'r1', mode: 'offline', role: 'receiver', status: 'pass', refs: ['delivery.md §3'] });
  report.add({ id: 'r2', mode: 'offline', role: 'receiver', status: 'skip', optional: true, refs: ['delivery.md §3.1 C3'] });
  report.add({ id: 's1', mode: 'offline', role: 'sender', status: 'pass', refs: ['delivery.md §7'] });
  report.add({ id: 's2', mode: 'offline', role: 'sender', status: 'skip', refs: ['delivery.md §7.4'] });
  const s = report.summary();
  assert.deepEqual(s.tested, ['receiver']);
  assert.deepEqual(s.partial, ['sender']);
});
