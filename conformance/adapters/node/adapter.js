// Conformance-kit adapter for the Node.js reference provider (reference/node).
// It speaks the adapter contract in ../../ADAPTER.md: one JSON request per line on stdin, one answer per line on stdout.
// It maps the contract onto the provider's own API and reads its SQLite store for inspection, so that the kit itself
// never depends on Node internals.
import { createInterface } from 'node:readline';
import { createPrivateKey } from 'node:crypto';
import { createServer } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { Store } from '../../../reference/node/src/store.js';
import { initialize } from '../../../reference/node/src/config.js';
import { advance, ownerGrant, parseAction, publicCard, Problem } from '../../../reference/node/src/protocol.js';
import { makeEventRecord, RecordRejection, sha256, signRecord, typs, validateDocument, verifyRecord } from '../../../reference/node/src/records.js';
import { handleProviderEndpoint, send, startProvider } from '../../../reference/node/src/provider.js';

const pkg = { name: 'darep-reference-node', version: '0.1.0' };
const realRandom = Math.random;
let offline = null; // { dir, store, config, runtime, server, applied }
let live = null;    // { dir, port, address, provider, store }

export class Unsupported extends Error {}
const signerFor = (document, privateKeys, purpose) => {
  const entry = document.keys.find(k => k.purpose.includes(purpose) && privateKeys[k.id]);
  return entry && { kid: entry.id, key: createPrivateKey({ key: privateKeys[entry.id], format: 'jwk' }) };
};
const current = () => {
  const store = live?.store ?? offline?.store;
  if (!store) throw new Error('call reset or liveStart first');
  return store;
};
const listen = (server, port = 0) => new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(port, '127.0.0.1', () => resolve(server.address().port));
});

async function closeAll() {
  Math.random = realRandom;
  if (offline) {
    if (offline.server) await new Promise(resolve => { offline.server.closeAllConnections(); offline.server.close(resolve); });
    offline.store.close();
    rmSync(offline.dir, { recursive: true, force: true });
    offline = null;
  }
  if (live) {
    await live.provider?.close();
    live.store.close();
    rmSync(live.dir, { recursive: true, force: true });
    live = null;
  }
}

export const ops = {
  describe: () => ({ name: pkg.name, version: pkg.version, roles: ['verifier', 'signer', 'receiver', 'sender'], live: true,
    extensions: ['https://darep.org/ext/core/v2', 'https://darep.org/ext/work/v2', 'https://darep.org/ext/reschedule/v2'] }),

  // ---------- verifier and signer ----------
  verify({ jws, context, identities }) {
    try {
      const out = verifyRecord(jws, { typ: context.typ, mode: context.mode, now: Date.parse(context.now),
        receiver: context.receiver ?? undefined, understood: context.understood ?? [], answered: context.answered ?? undefined },
      id => identities.find(d => d.id === id) ?? null);
      return { verdict: 'accept', kid: out.kid, record: out.record, payloadSha256: sha256(out.payload) };
    } catch (error) {
      if (error instanceof RecordRejection) return { verdict: 'reject', code: error.code };
      throw error;
    }
  },
  validateIdentity({ document }) {
    try { validateDocument(document); return { verdict: 'accept' }; } catch { return { verdict: 'reject' }; }
  },
  sign({ payload, typ, kid, privateJwk }) {
    return { jws: signRecord(JSON.stringify(payload), { kid, key: createPrivateKey({ key: privateJwk, format: 'jwk' }) }, typ) };
  },

  // ---------- offline receiver and sender, with an injected clock ----------
  async reset({ role, address, document, privateKeys, pins, extensions, jitter, now }) {
    await closeAll();
    const dir = mkdtempSync(join(tmpdir(), 'darep-node-adapter-'));
    let clock = Date.parse(now);
    const config = { card: { id: address, document }, signer: signerFor(document, privateKeys, 'record'),
      providerSigner: signerFor(document, privateKeys, 'provider') };
    const store = new Store(dir, address, { config, now: () => clock });
    store.setClock = t => { clock = t; };
    for (const pin of pins) store.trust(pin);
    if (jitter === false) Math.random = () => 0;
    const applied = [];
    const setOutcome = store.outcome.bind(store);
    store.outcome = (row, outcome, code) => {
      const result = setOutcome(row, outcome, code);
      if (outcome === 'applied' && row.typ === typs.event && row.direction === 'in') applied.push({ thread: row.topic, id: row.event_id });
      return result;
    };
    const runtime = { config, store, extensions };
    offline = { dir, store, config, runtime, applied };
    if (role !== 'receiver') return {};
    offline.server = createServer((req, res) => {
      handleProviderEndpoint(req, res, () => { throw new Problem(404, 'Not found'); }, () => runtime).then(handled => {
        if (!handled) { res.writeHead(404); res.end(); }
      });
    });
    const port = await listen(offline.server);
    return { inbox: `http://127.0.0.1:${port}/darep/v2/inbox` };
  },
  setClock({ now }) {
    if (!offline) throw new Unsupported('setClock is for offline mode');
    offline.store.setClock(Date.parse(now));
    return {};
  },
  fault({ kind }) {
    const store = offline.store;
    if (kind === 'rate-limited') store.capacity = () => 'rate-limited';
    else if (kind === 'unavailable') store.db.exec("CREATE TRIGGER fail_store BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT, 'Injected storage failure'); END");
    else throw new Unsupported('unknown fault ' + kind);
    return {};
  },
  seedOutgoing({ recordBytes }) {
    const store = offline.store;
    const envelope = JSON.parse(Buffer.from(recordBytes.split('.')[1], 'base64url'));
    store.transaction(() => {
      const row = store.queueSigned(recordBytes);
      const state = advance(store.state(envelope.thread), envelope, parseAction(envelope));
      store.db.prepare('INSERT OR REPLACE INTO threads VALUES (?,?,?)').run(state.threadId, JSON.stringify(state), row.row_id);
    });
    offline.applied.push({ thread: envelope.thread, id: envelope.id });
    return {};
  },
  tick() { current().applyReady(); return {}; },
  stats() {
    const db = current().db;
    return {
      incoming: db.prepare("SELECT count(*) AS n FROM events WHERE direction='in'").get().n,
      rejections: db.prepare("SELECT count(DISTINCT event_id) AS n FROM events WHERE direction='out' AND typ=?").get(typs.rejection).n,
    };
  },
  inspectIncoming({ source, id }) {
    const db = current().db;
    const row = db.prepare("SELECT * FROM events WHERE direction='in' AND actor=? AND event_id=?").get(source, id);
    if (!row) return { found: false };
    let rejection = null;
    if (row.rejection_row) {
      const first = db.prepare('SELECT * FROM events WHERE row_id=?').get(row.rejection_row);
      const all = db.prepare("SELECT recipient FROM events WHERE direction='out' AND event_id=?").all(first.event_id);
      rejection = { recordBytes: first.jws, deliverTo: all.map(r => r.recipient) };
    }
    return { found: true, recordBytes: row.jws, receipt: row.receipt, outcome: row.outcome ?? null,
      applyCount: row.apply_count, storedAt: row.stored_at, rejection };
  },
  inspectThread({ thread }) {
    if (!offline) throw new Unsupported('inspectThread is for offline mode');
    return { head: offline.store.state(thread)?.head ?? null,
      applyOrder: offline.applied.filter(a => a.thread === thread).map(a => a.id) };
  },
  queueSigned({ recordBytes }) {
    offline.store.transaction(() => offline.store.queueSigned(recordBytes));
    return {};
  },
  async attempt({ id, recipient }) {
    const { store, config } = offline;
    const row = store.db.prepare("SELECT * FROM events WHERE direction='out' AND event_id=? AND recipient=?").get(id, recipient);
    if (!row) throw new Error('no such outgoing delivery');
    const before = store.db.prepare('SELECT count(*) AS n FROM attempts WHERE event_row=?').get(row.row_id).n;
    await send(row, config, store);
    const attempts = store.db.prepare('SELECT * FROM attempts WHERE event_row=? ORDER BY id').all(row.row_id);
    if (attempts.length > before) return { result: attempts.at(-1).result };
    return { result: store.db.prepare('SELECT status FROM outbox WHERE event_row=?').get(row.row_id).status };
  },
  inspectOutgoing({ id, recipient }) {
    const db = current().db;
    const row = db.prepare(`SELECT e.row_id,e.jws,o.* FROM events e JOIN outbox o ON o.event_row=e.row_id
      WHERE e.direction='out' AND e.event_id=? AND e.recipient=?`).get(id, recipient);
    if (!row) return { found: false };
    const attempts = db.prepare('SELECT * FROM attempts WHERE event_row=? ORDER BY id').all(row.row_id).map(a => ({
      at: a.at, result: a.result, code: a.code, status: a.status, headers: a.headers ? JSON.parse(a.headers) : {},
      body: a.body ?? null }));
    return { found: true, status: row.status, recordBytes: row.jws, receipt: row.receipt ?? null, attempts,
      backoffMs: row.backoff_ms, nextAttemptAt: new Date(row.next_at).toISOString(),
      refusal: row.refused_code ? { code: row.refused_code } : null };
  },
  due() {
    return { deliveries: offline.store.due().map(r => ({ id: r.event_id, recipient: r.recipient })) };
  },

  // ---------- live: a real provider on loopback with the real clock and its own delivery worker ----------
  async liveStart({ addressHint, kitCard }) {
    await closeAll();
    const dir = mkdtempSync(join(tmpdir(), 'darep-node-live-'));
    const probe = createServer();
    const port = await listen(probe);
    await new Promise(resolve => probe.close(resolve));
    const address = addressHint ?? 'acct:impl@impl.conformance.test';
    const card = initialize(dir, address, `http://127.0.0.1:${port}`);
    const store = new Store(dir, address);
    store.trust(kitCard);
    const provider = await startProvider({ dir, port, host: '127.0.0.1' });
    live = { dir, port, address, provider, store };
    return { card: publicCard(card) };
  },
  send({ to, type, data }) {
    if (!live) throw new Unsupported('send is for live mode');
    const { store } = live;
    const record = makeEventRecord({ source: live.address, to, type, data, grant: ownerGrant() });
    const jws = signRecord(JSON.stringify(record), store.config.signer, typs.event);
    store.transaction(() => store.queueSigned(jws));
    return { id: record.id };
  },
  async restart() {
    if (!live) throw new Unsupported('restart is for live mode');
    await live.provider.close();
    live.provider = await startProvider({ dir: live.dir, port: live.port, host: '127.0.0.1' });
    return { inbox: `http://127.0.0.1:${live.port}/darep/v2/inbox` };
  },
  async stop() { await closeAll(); return {}; },
};

// The contract's transport: answer each request line in order.
export function serve(table = ops) {
  const out = message => process.stdout.write(JSON.stringify(message) + '\n');
  const lines = createInterface({ input: process.stdin });
  let queue = Promise.resolve();
  lines.on('line', line => {
    queue = queue.then(async () => {
      let request;
      try { request = JSON.parse(line); } catch { return; }
      const op = table[request.op];
      if (!op) return out({ id: request.id, error: { code: 'unsupported', message: 'unknown op ' + request.op } });
      try { out({ id: request.id, result: await op(request.params ?? {}) }); }
      catch (error) {
        out({ id: request.id, error: { code: error instanceof Unsupported ? 'unsupported' : 'failed', message: error.message } });
      }
    });
  });
  lines.on('close', () => { queue.then(closeAll).then(() => process.exit(0)); });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) serve();
