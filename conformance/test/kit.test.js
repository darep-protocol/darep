// Self-test of the kit: a clean run passes, and each deliberate defect is caught by the cases that should catch it.
import assert from 'node:assert/strict';
import test from 'node:test';
import { execFile } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const kit = fileURLToPath(new URL('../bin/darep-conformance.js', import.meta.url));
const mutant = fileURLToPath(new URL('./mutant-adapter.js', import.meta.url));

function run(adapter, env = {}, args = [], mode = 'offline') {
  const out = mkdtempSync(join(tmpdir(), 'darep-kit-test-'));
  return new Promise(resolve => {
    execFile(process.execPath, [kit, mode, '--adapter', adapter, '--out', out, ...args], { env: { ...process.env, ...env } },
      (error, stdout) => {
        const report = JSON.parse(readFileSync(join(out, 'report.json'), 'utf8'));
        rmSync(out, { recursive: true, force: true });
        resolve({ code: error?.code ?? 0, stdout, report });
      });
  });
}
const failed = report => report.cases.filter(c => c.status === 'fail').map(c => c.id);

test('the Node reference adapter passes offline, with the claim wording and scope', async () => {
  const { code, report } = await run('node-reference');
  assert.equal(code, 0, failed(report).join(', '));
  assert.equal(report.result.passes, true);
  assert.equal(report.claimWording, 'passes the DAREP v0.1 conformance kit (verification aid, not certification)');
  assert.deepEqual(report.result.scope.roles, ['verifier', 'signer', 'receiver', 'sender']);
  assert.ok(report.notCovered.length > 5);
  assert.ok(report.cases.filter(c => c.subset === 'experimental').every(c => c.status === 'skip' && c.basis === 'vector-only'));
  assert.ok(report.cases.every(c => c.refs.length > 0 && ['normative', 'vector-only'].includes(c.basis)), 'every case is traceable');
});

const defects = {
  'verify-accepts-everything': ids => ids.includes('records/negative/tampered-payload') && ids.every(id => id.startsWith('records/negative/')),
  'sign-bad-signature': ids => ids.length === 14 && ids.every(id => id.startsWith('sign/')),
  'no-dedupe': ids => ids.includes('delivery/receiver/duplicate-delivery') && ids.includes('delivery/receiver/reject-id-conflict'),
  'sender-resigns': ids => ids.includes('delivery/sender/retry-same-bytes') && ids.every(id => id.startsWith('delivery/sender/')),
};
for (const [name, expected] of Object.entries(defects)) {
  test(`defect "${name}" is caught`, async () => {
    const { code, report } = await run(`"${process.execPath}" "${mutant}"`, { DAREP_MUTANT: name });
    assert.equal(code, 1);
    assert.equal(report.result.passes, false);
    assert.ok(expected(failed(report)), failed(report).join(', '));
  });
}

test('the harness self-test fixtures pass on the Node reference adapter, and are not a conformance result', async () => {
  const { code, report } = await run('node-reference', {}, ['--selftest']);
  assert.equal(code, 0, failed(report).join(', '));
  assert.equal(report.selftest, true);
  assert.equal(report.claimWording, null);
  assert.match(report.result.statement, /Not a conformance result/);
  assert.ok(report.cases.every(c => c.id.includes('selftest/')), 'only self-test fixtures run');
  assert.ok(report.cases.some(c => c.id === 'pin-update/selftest/key-removed' && c.status === 'pass'));
});

const selftestDefects = {
  'outcome-by-id': ['delivery/selftest/receiver/same-id-two-sources'],
  'lenient-body': ['delivery/selftest/receiver/binary-body'],
  'naive-http-client': ['delivery/selftest/sender/raw-framing'],
  'verify-binary32': ['records/selftest/numbers-binary64'],
  'update-always-routine': ['pin-update/selftest/key-removed', 'pin-update/selftest/address-removed', 'pin-update/selftest/valid-until-later'],
};
for (const [name, expected] of Object.entries(selftestDefects)) {
  test(`harness defect "${name}" is caught by the self-test fixtures`, async () => {
    const { code, report } = await run(`"${process.execPath}" "${mutant}"`, { DAREP_MUTANT: name }, ['--selftest']);
    assert.equal(code, 1);
    const ids = failed(report);
    for (const id of expected) assert.ok(ids.includes(id), `${id} not caught: ${ids.join(', ')}`);
  });
}

test('roles the adapter does not declare are reported as not tested', async () => {
  const { report } = await run('node-reference', {}, ['--roles', 'verifier']);
  assert.equal(report.roles.verifier.tested, true);
  assert.equal(report.roles.sender.tested, false);
  assert.ok(report.cases.every(c => c.role === 'verifier'));
});

test('live mode catches a receiver without deduplication and a sender that re-signs', { timeout: 180_000 }, async () => {
  const { code, report } = await run(`"${process.execPath}" "${mutant}"`, { DAREP_MUTANT: 'no-dedupe,sender-resigns' }, [], 'live');
  assert.equal(code, 1);
  const ids = failed(report);
  for (const id of ['live/receiver/duplicate-same-bytes', 'live/receiver/duplicate-resigned', 'live/receiver/dropped-ack-restart',
    'live/sender/dropped-ack-restart']) assert.ok(ids.includes(id), `${id} not caught: ${ids.join(', ')}`);
  assert.ok(report.cases.some(c => c.id === 'live/receiver/happy-path' && c.status === 'pass'));
});
