// The kit's own DAREP peer for live mode: the Node reference provider (reference/node) on loopback,
// with a fresh test identity per run. It sends and receives through the same code paths as the reference.
import { generateKeyPairSync } from 'node:crypto';
import { createServer } from 'node:http';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { repoRoot } from '../repo.js';

const ref = file => pathToFileURL(join(repoRoot, 'reference', 'node', 'src', file)).href;
export const KIT_ADDRESS = 'acct:kit@kit.conformance.test';
export const STRANGER_ADDRESS = 'acct:stranger@kit.conformance.test';

export async function loadReference() {
  if (!existsSync(join(repoRoot, 'reference', 'node', 'node_modules'))) {
    throw new Error('live mode runs the Node reference provider as the kit peer: run `npm ci` in reference/node first');
  }
  const [store, records, provider, protocol] = await Promise.all(['store.js', 'records.js', 'provider.js', 'protocol.js'].map(f => import(ref(f))));
  return { ...store, ...records, ...provider, ...protocol };
}

// Keys are valid from 60 days ago, so the kit can sign back-dated records for the expiry cases.
function identity(R, address) {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const document = R.makeIdentityDocument(address, publicKey, new Date(Date.now() - 60 * 86400_000));
  return { address, document, signer: { key: privateKey, kid: document.keys[0].id } };
}

export async function startKitPeer() {
  const R = await loadReference();
  const me = identity(R, KIT_ADDRESS);
  const stranger = identity(R, STRANGER_ADDRESS);
  const dir = mkdtempSync(join(tmpdir(), 'darep-kit-peer-'));
  const config = { card: { id: me.address, document: me.document }, signer: me.signer, providerSigner: me.signer };
  const store = new R.Store(dir, me.address, { config });
  const runtime = { config, store, extensions: [R.coreExtension] };
  const server = createServer((req, res) => {
    R.handleProviderEndpoint(req, res, () => { throw new R.Problem(404, 'Not found'); },
      recipient => (recipient === me.address ? runtime : null)).then(handled => {
      if (!handled) { res.writeHead(404); res.end(); }
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const inbox = `http://127.0.0.1:${server.address().port}/darep/v2/inbox`;
  const outbox = row => store.db.prepare('SELECT * FROM outbox WHERE event_row=?').get(row.row_id);
  return {
    R, ...me, stranger, inbox, store,
    pin: card => store.trust(card),
    // Sign once, store once, then deliver with the reference sender (delivery.md §7.1).
    queue(jws) { return store.transaction(() => store.queueSigned(jws)); },
    async deliver(row) {
      await R.send(row, config, store);
      const attempts = store.db.prepare('SELECT * FROM attempts WHERE event_row=? ORDER BY id').all(row.row_id);
      return { outbox: outbox(row), last: attempts.at(-1) };
    },
    sign(envelope, typ = R.typs.event, who = me) { return R.signRecord(JSON.stringify(envelope), who.signer, typ); },
    resign(jws) {
      const header = JSON.parse(Buffer.from(jws.split('.')[0], 'base64url'));
      return R.signCompact(Buffer.from(jws.split('.')[1], 'base64url').toString('utf8'), me.signer, header.typ);
    },
    async close() {
      await new Promise(resolve => { server.closeAllConnections(); server.close(resolve); });
      store.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}
