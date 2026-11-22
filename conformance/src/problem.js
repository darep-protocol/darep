// https-binding.md §2.3: the shape of a pre-store problem response, shared by offline and live checks.
import { check } from './report.js';

const MEMBERS = new Set(['type', 'title', 'status', 'code', 'detail', 'record']);
// `record` may only echo an identifier once the signature verified and the envelope is valid (check R10 or later).
// wrong-recipient can be raised at C1 or R12, so it is allowed there; every earlier code must not carry it.
const BEFORE_R10 = new Set(['method-not-allowed', 'unsupported-media-type', 'too-large', 'malformed', 'unsupported-alg',
  'bad-header', 'unknown-key', 'bad-signature', 'unsupported-version']);

export function checkProblem(res, { code, status, recordId = null, at = '' }) {
  const p = at ? `${at}: ` : '';
  const text = res.body.toString('utf8');
  check(res.status === status, `${p}HTTP ${res.status} ${text.slice(0, 200)}; expected ${status} ${code}`);
  check((res.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase() === 'application/problem+json', `${p}content-type ${res.headers['content-type']}`);
  let problem;
  try { problem = JSON.parse(text); } catch { check(false, `${p}problem body is not JSON`); }
  check(problem && typeof problem === 'object' && !Array.isArray(problem), `${p}problem body is not an object`);
  check(problem.code === code, `${p}problem code ${problem.code}; expected ${code}`);
  check(problem.type === 'https://darep.org/problems/' + code, `${p}problem type ${problem.type}`);
  check(problem.status === status, `${p}problem status ${problem.status}`);
  check(typeof problem.title === 'string', `${p}problem title`);
  check(Object.keys(problem).every(k => MEMBERS.has(k)), `${p}problem members outside https-binding §2.3: ${Object.keys(problem).join(', ')}`);
  if ('detail' in problem) check(typeof problem.detail === 'string' && [...problem.detail].length <= 1000, `${p}problem detail must be a string of at most 1,000 code points`);
  if ('record' in problem) {
    check(!BEFORE_R10.has(code), `${p}problem echoes "record" for ${code}, which is raised before the signature and envelope are verified`);
    if (recordId) check(problem.record === recordId, `${p}problem record ${problem.record}; expected ${recordId}`);
  }
  if (code === 'method-not-allowed') check(/\bPOST\b/.test(res.headers.allow ?? ''), `${p}Allow header ${res.headers.allow}`);
  return problem;
}
