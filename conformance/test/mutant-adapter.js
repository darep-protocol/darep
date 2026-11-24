// Test-only: the Node reference adapter with deliberate defects, chosen by DAREP_MUTANT (comma-separated).
// The kit's self-test runs these to show that each check can fail.
import { createServer, request } from 'node:http';
import { connect } from 'node:net';
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
// Harness self-test defects (run with --selftest): each needs one of the runner capabilities to be caught.
if (mutants.includes('outcome-by-id')) {
  // Writes an outcome to every stored record with the same id, whatever its source.
  const original = Store.prototype.outcome;
  Store.prototype.outcome = function (row, outcome, code) {
    const result = original.call(this, row, outcome, code);
    this.db.prepare('UPDATE events SET outcome=? WHERE event_id=? AND direction=?').run(outcome, row.event_id, row.direction);
    return result;
  };
}
if (mutants.includes('lenient-body')) {
  // A front end that drops request octets it cannot decode instead of refusing the body.
  table.reset = async params => {
    const out = await ops.reset(params);
    if (!out.inbox) return out;
    const target = new URL(out.inbox);
    const front = createServer(async (req, res) => {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const kept = Buffer.from([...Buffer.concat(chunks)].filter(b => b < 0x80));
      const forward = request({ host: target.hostname, port: target.port, path: target.pathname, method: req.method,
        headers: { ...req.headers, 'content-length': String(kept.length) } }, answer => {
        res.writeHead(answer.statusCode, answer.headers);
        answer.pipe(res);
      });
      forward.end(kept);
    });
    await new Promise(resolve => front.listen(0, '127.0.0.1', resolve));
    return { inbox: `http://127.0.0.1:${front.address().port}${target.pathname}` };
  };
}
if (mutants.includes('naive-http-client')) {
  // A sender HTTP client that reads to EOF and keeps the transfer coding in the body.
  globalThis.fetch = (url, options) => new Promise((resolve, reject) => {
    const target = new URL(url);
    const chunks = [];
    const socket = connect(target.port, target.hostname, () => {
      const head = [`POST ${target.pathname} HTTP/1.1`, `host: ${target.host}`, `content-length: ${Buffer.byteLength(options.body)}`,
        'connection: close', ...Object.entries(options.headers).map(([k, v]) => `${k}: ${v}`)].join('\r\n');
      socket.write(head + '\r\n\r\n' + options.body);
    });
    socket.on('data', c => chunks.push(c));
    socket.on('error', reject);
    socket.on('end', () => {
      const data = Buffer.concat(chunks);
      const split = data.indexOf('\r\n\r\n');
      const lines = data.subarray(0, split).toString('latin1').split('\r\n');
      const headers = new Headers(lines.slice(1).map(l => [l.slice(0, l.indexOf(':')), l.slice(l.indexOf(':') + 1).trim()])
        .filter(([k]) => k.toLowerCase() !== 'transfer-encoding'));
      resolve(new Response(data.subarray(split + 4), { status: Number(lines[0].split(' ')[1]), headers }));
    });
  });
}
if (mutants.includes('verify-binary32')) {
  // Keeps the numbers of a verified record at binary32 precision.
  const fround = v => typeof v === 'number' ? Math.fround(v) : Array.isArray(v) ? v.map(fround)
    : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, fround(x)])) : v;
  table.verify = async params => {
    const out = await ops.verify(params);
    return out.record ? { ...out, record: fround(out.record) } : out;
  };
}
if (mutants.includes('update-always-routine')) {
  // Treats every re-pinned identity document as a routine rotation.
  table.checkUpdate = () => ({ result: 'routine' });
}
serve(table);
