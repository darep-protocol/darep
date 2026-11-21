import { randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import { mkdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { loadConfig, writeNewJson } from './config.js';
import { handoffType, parse, Problem, requireThat, respondInput } from './protocol.js';
import { Store } from './store.js';
import { fingerprint, Pairing } from './operator-pairing.js';

const cli = fileURLToPath(new URL('./cli.js', import.meta.url));
const assets = new Map([
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ['/app.js', ['app.js', 'text/javascript; charset=utf-8']],
  ['/app.css', ['app.css', 'text/css; charset=utf-8']],
]);
const onlyCode = z.strictObject({ code: z.string().min(1).max(4096) });
const checkedCode = onlyCode.extend({ fingerprint: z.string().max(100) });
const grantInput = z.strictObject({ confirmation: z.boolean(), handoff: z.boolean().optional() });
const revokeInput = z.strictObject({ id: z.uuidv4() });
const confirmInput = z.strictObject({ threadId: z.uuidv4(), expectedHead: z.uuidv4(), slot: z.string().max(64) });
const pageInput = z.strictObject({ workflow: z.enum(['reschedule', 'handoff']), before: z.number().int().safe().positive() });
function grantInfo(id, file, expires, scopes) {
  if (!file) return { id, file: null, expires, scopes, connectionName: null, instructions: null };
  const connectionName = 'reschedule-' + id;
  const config = { command: process.execPath, args: [cli, 'stdio', '--grant', file] };
  // A generic MCP stdio server entry that any MCP-capable agent host can load.
  const instructions = JSON.stringify({ mcpServers: { [connectionName]: config } }, null, 2);
  return { id, file, expires, scopes, connectionName, instructions };
}
function createActions(dir, store, config, now) {
  const pairing = new Pairing(store, config, now);
  store.db.exec('CREATE TABLE IF NOT EXISTS operator_clients(id TEXT PRIMARY KEY REFERENCES grants(id) ON DELETE CASCADE, file TEXT NOT NULL)');
  function approvals(before) {
    const page = store.authorizedHandoffs(before);
    return { approvals: page.approvals.map(({ peer, threadId, action }) => ({ peer, threadId: threadId ?? null, action })),
      nextBefore: page.nextBefore };
  }
  return {
    state: () => {
      const schedule = store.list();
      const handoff = store.list(undefined, handoffType);
      const pending = approvals();
      return {
        owner: config.card.id,
        timeZone: store.timeZone?.() ?? 'UTC',
        fingerprint: fingerprint(config.card),
        pendingInvites: pairing.openInvites(),
        handoffs: typeof store.allowHandoff === 'function',
        handoffApprovals: pending.approvals,
        nextApprovalPage: pending.nextBefore,
        contacts: store.db.prepare('SELECT card FROM contacts ORDER BY id').all().map(row => {
          const card = JSON.parse(row.card);
          return { id: card.id, fingerprint: fingerprint(card) };
        }),
        grants: store.db.prepare('SELECT g.id,g.expires,g.scopes,c.file FROM grants g LEFT JOIN operator_clients c ON g.id=c.id WHERE g.closed_at IS NULL AND g.expires>? ORDER BY g.expires DESC')
          .all(now()).map(row => grantInfo(row.id, row.file, new Date(row.expires).toISOString(), JSON.parse(row.scopes))),
        threads: [...schedule.threads, ...handoff.threads],
        nextPages: { reschedule: schedule.nextBefore, handoff: handoff.nextBefore },
      };
    },
    records: data => store.records(parse(z.strictObject({ before: z.number().int().positive().optional() }), data).before),
    threads: data => {
      const { before, workflow } = parse(pageInput, data);
      return store.list(before, workflow === 'handoff' ? handoffType : undefined);
    },
    'set-zone': data => {
      const { zone } = parse(z.strictObject({ zone: z.string().min(1).max(100) }), data);
      requireThat(typeof store.setTimeZone === 'function', 501, 'This provider does not support time zone settings');
      store.setTimeZone(zone);
      return { timeZone: store.timeZone() };
    },
    invite: () => pairing.invite(),
    'cancel-invite': data => pairing.cancel(parse(z.strictObject({ nonce: z.uuidv4() }), data).nonce),
    inspect: data => pairing.inspect(parse(onlyCode, data).code),
    approve: data => {
      const { code, fingerprint } = parse(checkedCode, data);
      return pairing.approve(code, fingerprint);
    },
    allow: data => { store.allowTimes(data); return { saved: true }; },
    'allow-handoff': data => {
      requireThat(typeof store.allowHandoff === 'function', 501, 'Project handoffs are unavailable');
      store.allowHandoff(data);
      return { saved: true };
    },
    'handoff-approvals': data => approvals(parse(pageInput.omit({ workflow: true }), data).before),
    'withdraw-handoff': data => {
      const { removed } = store.allowHandoff(data, { withdraw: true });
      return { approved: false, removed: Boolean(removed) };
    },
    grant: data => {
      const { confirmation, handoff } = parse(grantInput, data);
      const scopes = ['read', 'coordinate'];
      if (confirmation) scopes.push('confirm');
      if (handoff) scopes.push('handoff');
      const clients = join(dir, 'clients');
      mkdirSync(clients, { recursive: true, mode: 0o700 });
      const grant = store.issue(scopes, 168);
      const file = join(clients, grant.id + '.json');
      try {
        writeNewJson(file, { ...grant, url: config.card.origin + '/mcp' });
        store.db.prepare('INSERT INTO operator_clients VALUES(?,?)').run(grant.id, file);
      } catch (error) { store.revoke(grant.id); throw error; }
      return grantInfo(grant.id, file, grant.expires, scopes);
    },
    revoke: data => ({ revoked: store.revoke(parse(revokeInput, data).id) }),
    'retry-delivery': data => {
      const { threadId, expectedEventId } = parse(z.strictObject({ threadId: z.uuidv4(), expectedEventId: z.uuidv4() }), data);
      return store.retryDelivery(threadId, expectedEventId);
    },
    decline: data => {
      const { threadId, expectedHead } = parse(confirmInput.omit({ slot: true }), data);
      const reply = store.respond(parse(respondInput, { threadId, expectedHead, action: { kind: 'decline' } }));
      return { status: reply.status };
    },
    confirm: data => {
      const { threadId, expectedHead, slot } = parse(confirmInput, data);
      const reply = store.respond(parse(respondInput, { threadId, expectedHead, action: { kind: 'confirm', slot } }));
      return { status: reply.status };
    },
  };
}

async function readForm(req) {
  const limit = 16 * 1024;
  requireThat(Number(req.headers['content-length'] ?? 0) <= limit, 413, 'Request too large');
  let total = 0;
  const chunks = [];
  for await (const part of req) {
    total += part.length;
    requireThat(total <= limit, 413, 'Request too large');
    chunks.push(part);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { throw new Problem(400, 'Invalid JSON format'); }
}
export async function startOperator({ dir, port = 0, now = Date.now }) {
  const config = loadConfig(dir);
  const store = new Store(dir, config.card.id);
  const actions = createActions(resolve(dir), store, config, now);
  const key = randomBytes(32).toString('base64url');
  const expected = Buffer.from('Bearer ' + key);
  let origin;
  const server = createServer({ requestTimeout: 15_000, headersTimeout: 10_000 }, async (req, res) => {
    res.setHeader('cache-control', 'no-store');
    res.setHeader('x-content-type-options', 'nosniff');
    res.setHeader('referrer-policy', 'no-referrer');
    res.setHeader('x-frame-options', 'DENY');
    res.setHeader('content-security-policy', "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'none'; base-uri 'none'");
    function send(status, body, media = 'application/json; charset=utf-8') {
      res.writeHead(status, { 'content-type': media });
      res.end(body);
    }
    try {
      requireThat(origin && 'http://' + req.headers.host === origin, 403, 'Unexpected local Host header');
      if (req.method === 'GET' && assets.has(req.url)) {
        const [name, media] = assets.get(req.url);
        return send(200, readFileSync(new URL('./operator/' + name, import.meta.url)), media);
      }
      requireThat(req.method === 'POST' && req.url.startsWith('/api/'), 404, 'Unknown action');
      requireThat(req.headers.origin === origin, 403, 'Submit through the local workspace');
      const received = Buffer.from(req.headers.authorization ?? '');
      requireThat(received.length === expected.length && timingSafeEqual(received, expected), 401, 'Open the local workspace link shown in the terminal');
      const action = req.url.slice(5);
      requireThat(Object.hasOwn(actions, action), 404, 'Unknown action');
      requireThat(req.headers['content-type']?.split(';')[0].trim() === 'application/json', 415, 'JSON required');
      const data = await readForm(req);
      const result = await actions[action](data);
      send(200, JSON.stringify(result));
    } catch (error) {
      if (res.destroyed || res.headersSent) return;
      send(error instanceof Problem ? error.status : 500,
        JSON.stringify({ error: error instanceof Problem ? error.message : 'The action could not be completed. Check your local settings.' }));
    }
  });
  try { await new Promise((ok, fail) => { server.once('error', fail); server.listen(port, '127.0.0.1', ok); }); }
  catch (error) { store.close(); throw error; }
  origin = 'http://127.0.0.1:' + server.address().port;
  return { origin, url: origin + '/#key=' + key, async close() {
    const done = new Promise(ok => server.close(ok));
    server.closeIdleConnections();
    await done;
    store.close();
  } };
}
