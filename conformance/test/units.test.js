// Unit tests for rules that the reference implementations never break, so the end-to-end runs cannot show them.
import assert from 'node:assert/strict';
import test from 'node:test';
import { checkProblem } from '../src/problem.js';
import { Failure, Report } from '../src/report.js';

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
