// Offline mode, verifier and signer roles: the records vectors through the adapter.
import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { loadJson, vectorsRoot } from '../repo.js';
import { check } from '../report.js';
import { Unsupported } from '../adapter.js';
import { deepEqual, headerOf, payloadOf, referenceVerify, sha256 } from '../check.js';

const REFS = ['records.md §8'];

// Numbers reach the kit through the adapter's JSON line, so the kit always holds them as binary64 values; deepEqual
// therefore compares them in binary64 in either mode. expected.numbers is still validated, so a vector asking for a
// mode the kit does not know fails loudly instead of passing.
function recordMatches(got, exp) {
  check(['exact', 'binary64'].includes(exp.numbers ?? 'exact'), `unknown expected.numbers mode ${exp.numbers}`);
  return deepEqual(got, exp.record);
}

// selftest: run the harness self-test fixtures (records/selftest/) instead of the conformance vectors.
export async function verifierCases(adapter, report, { selftest = false } = {}) {
  const meta = (id, refs = REFS) => ({ id, mode: 'offline', role: 'verifier', subset: 'core', refs });
  const { documents } = loadJson('records', 'identities.json');
  const vectors = selftest
    ? readdirSync(join(vectorsRoot, 'records', 'selftest')).filter(f => f.endsWith('.json') && f !== 'pin-updates.json')
      .sort().map(f => ({ name: 'selftest/' + f.slice(0, -5) }))
    : loadJson('records', 'index.json').vectors;
  if (selftest) return recordCases(adapter, report, meta, documents, vectors);
  for (const document of documents) {
    await report.run(meta('identities/valid/' + document.id.split('/').pop(), ['records.md §5.1', '§5.3 P-0']), async () => {
      const out = await adapter.call('validateIdentity', { document });
      check(out.verdict === 'accept', `rejected a valid pinned identity document (${out.code ?? 'no code'})`);
    });
  }
  for (const c of loadJson('records', 'invalid-identities.json').cases) {
    await report.run(meta('identities/invalid/' + c.name, ['records.md §5.1', '§5.3 P-0']), async () => {
      const out = await adapter.call('validateIdentity', { document: c.document });
      check(out.verdict === 'reject', 'accepted an invalid identity document as a pin');
    });
  }
  await recordCases(adapter, report, meta, documents, vectors);
}

async function recordCases(adapter, report, meta, documents, vectors) {
  for (const { name } of vectors) {
    const v = loadJson('records', name + '.json');
    await report.run(meta('records/' + name, [v.spec, 'records.md §8'].filter(Boolean)), async () => {
      const c = v.context;
      const out = await adapter.call('verify', {
        jws: v.jws, identities: documents,
        context: { typ: [].concat(c.typ), mode: c.mode, now: c.now, receiver: c.receiver ?? null,
          understood: c.understood ?? [], answered: c.answered ?? null },
      });
      const exp = v.expected;
      if (exp.verdict === 'reject') {
        check(out.verdict === 'reject', `accepted; expected reject with ${exp.code}`);
        check(out.code === exp.code, `rejected with ${out.code}; expected ${exp.code}`);
        return `reject ${out.code}`;
      }
      check(out.verdict === 'accept', `rejected with ${out.code}; expected accept`);
      check(out.kid === exp.kid, `kid ${out.kid}; expected ${exp.kid}`);
      check(recordMatches(out.record, exp), 'parsed record differs from the vector');
      check(out.payloadSha256 === v.payloadSha256, 'payload digest differs (bytes re-serialized? NC1)');
      return 'accept';
    });
  }
}

// Pin updates (records.md §5.5) through the optional checkUpdate operation. An owner-decision expectation is a MUST;
// routine is a SHOULD, reported as advisory. Runs records/pin-updates.json when the vectors have it, or the self-test
// fixture with selftest.
export async function pinUpdateCases(adapter, report, { selftest = false } = {}) {
  const file = selftest ? ['selftest', 'pin-updates.json'] : ['pin-updates.json'];
  if (!existsSync(join(vectorsRoot, 'records', ...file))) return;
  for (const c of loadJson('records', ...file).cases) {
    const meta = { id: `pin-update/${selftest ? 'selftest/' : ''}${c.name}`, mode: 'offline', role: 'verifier', subset: 'core',
      refs: ['records.md ' + c.spec], optional: true, level: c.level };
    let result;
    try {
      ({ result } = await adapter.call('checkUpdate', { old: c.old, new: c.new }));
    } catch (error) {
      if (error instanceof Unsupported) { report.add({ ...meta, status: 'skip', detail: 'the adapter has no checkUpdate operation' }); continue; }
      report.add({ ...meta, status: 'fail', detail: error.message });
      continue;
    }
    const detail = `${c.description} Expected ${c.expected}; got ${result}.`;
    if (!['routine', 'owner-decision'].includes(result)) report.add({ ...meta, status: 'fail', detail: `checkUpdate returned ${JSON.stringify(result)}` });
    else if (c.level === 'SHOULD') report.advisory(meta, result === c.expected, detail);
    else report.add({ ...meta, status: result === c.expected ? 'pass' : 'fail', detail });
  }
}

// Each positive records vector is re-signed by the implementation and judged by the reference verifier.
// receipt-signing-before-stored-at is left out: it deliberately breaks an issuer obligation (delivery.md §4.1).
export async function signerCases(adapter, report) {
  const { documents } = loadJson('records', 'identities.json');
  const keys = Object.fromEntries(Object.values(loadJson('records', 'keys.json').keys)
    .filter(k => k.kid).map(k => [k.kid, k.privateJwk]));
  for (const { name, verdict } of loadJson('records', 'index.json').vectors) {
    if (verdict !== 'accept' || name === 'positive/receipt-signing-before-stored-at') continue;
    const v = loadJson('records', name + '.json');
    const typ = headerOf(v.jws).typ;
    const kid = v.expected.kid;
    await report.run({ id: 'sign/' + name, mode: 'offline', role: 'signer', subset: 'core',
      refs: ['records.md §2–§4, §11', 'NC1'] }, async () => {
      const envelope = v.expected.record;
      const { jws } = await adapter.call('sign', { payload: envelope, typ, kid, privateJwk: keys[kid] });
      check(typeof jws === 'string' && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(jws), 'not a compact JWS');
      const header = headerOf(jws);
      check(header.alg === 'ES256' && header.typ === typ && header.kid === kid, `header ${JSON.stringify(header)}`);
      // records.md §11: a conformant signer produces records a conformant verifier accepts; judge them in the vector's own context.
      const got = referenceVerify(jws, { ...v.context, typ }, documents);
      check(got.ok, `the reference verifier rejects it: ${got.code} (${got.why})`);
      check(deepEqual(got.record, envelope), 'signed payload does not carry the requested envelope');
      check(Buffer.byteLength(jws) <= 65_536, 'record exceeds 64 KiB');
      return `${Buffer.byteLength(jws)} octets, payload sha256 ${sha256(payloadOf(jws)).slice(0, 12)}…`;
    });
  }
}
