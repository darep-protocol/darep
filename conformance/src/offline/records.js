// Offline mode, verifier and signer roles: the records vectors through the adapter.
import { loadJson } from '../repo.js';
import { check } from '../report.js';
import { deepEqual, headerOf, payloadOf, referenceVerify, sha256 } from '../check.js';

const REFS = ['records.md §8'];

export async function verifierCases(adapter, report) {
  const meta = (id, refs = REFS) => ({ id, mode: 'offline', role: 'verifier', subset: 'core', refs });
  const { documents } = loadJson('records', 'identities.json');
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
  for (const { name } of loadJson('records', 'index.json').vectors) {
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
      check(deepEqual(out.record, exp.record), 'parsed record differs from the vector');
      check(out.payloadSha256 === v.payloadSha256, 'payload digest differs (bytes re-serialized? NC1)');
      return 'accept';
    });
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
