// Test-only: the Node reference adapter with deliberate defects, chosen by DAREP_MUTANT (comma-separated).
// The kit's self-test runs these to show that each check can fail.
import { ops, serve } from '../adapters/node/adapter.js';
import { Store } from '../../reference/node/src/store.js';
import { signRecord } from '../../reference/node/src/records.js';

const mutants = (process.env.DAREP_MUTANT ?? '').split(',');
const table = { ...ops };
if (mutants.includes('verify-accepts-everything')) {
  table.verify = async params => {
    const out = await ops.verify(params);
    return out.verdict === 'reject' ? { verdict: 'accept', kid: null, record: null, payloadSha256: null } : out;
  };
}
if (mutants.includes('sign-bad-signature')) {
  // Corrupts the signature of everything it signs.
  table.sign = async params => {
    const { jws } = await ops.sign(params);
    const [h, p, sig] = jws.split('.');
    const bytes = Buffer.from(sig, 'base64url');
    bytes[0] ^= 1;
    return { jws: `${h}.${p}.${bytes.toString('base64url')}` };
  };
}
if (mutants.includes('no-dedupe')) {
  // Treats every resend as new: a duplicate gets a fresh receipt instead of the stored one.
  Store.prototype.prior = () => null;
}
if (mutants.includes('sender-resigns')) {
  // Signs again on every attempt instead of resending the stored bytes.
  const original = Store.prototype.signed;
  Store.prototype.signed = function (row) {
    const token = original.call(this, row);
    const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64url'));
    return this.config.signer ? signRecord(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'), this.config.signer, header.typ) : token;
  };
}
serve(table);
