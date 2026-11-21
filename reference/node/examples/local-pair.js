import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { initialize, writeNewJson } from '../src/config.js';
import { Store } from '../src/store.js';

export const cli = fileURLToPath(new URL('../src/cli.js', import.meta.url));
export async function until(check, timeout = 12_000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    const result = await check();
    if (result) return result;
    await delay(50);
  }
  throw new Error('Timed out waiting for the local provider');
}
async function reservePort() {
  const socket = createServer();
  socket.listen(0, '127.0.0.1');
  await once(socket, 'listening');
  return socket;
}
function participant(root, name, port) {
  const dir = join(root, name);
  const card = initialize(dir, 'acct:' + name + '@' + name + '.test', 'http://127.0.0.1:' + port);
  const store = new Store(dir, card.id);
  let grant;
  try { grant = { ...store.issue(['read', 'coordinate', 'confirm'], 1), url: card.origin + '/mcp' }; }
  finally { store.close(); }
  const grantFile = join(dir, 'client.json');
  writeNewJson(grantFile, grant);
  let child;
  return { dir, card, grant, grantFile,
    async start() {
      let log = '';
      child = spawn(process.execPath, [cli, 'serve', '--dir', dir], { stdio: ['ignore', 'pipe', 'pipe'] });
      child.stdout.on('data', data => { log += data; });
      child.stderr.on('data', data => { log += data; });
      await until(async () => {
        if (child.exitCode !== null) throw new Error('Provider exited: ' + log);
        if (!log.includes('Provider ready:')) return false;
        return (await fetch(card.origin + '/health')).ok;
      });
    },
    async stop(signal = 'SIGTERM') {
      if (!child || child.exitCode !== null || child.signalCode) return;
      const done = once(child, 'exit');
      child.kill(signal);
      await done;
    },
    trust(otherCard) {
      const storage = new Store(dir, card.id);
      try { storage.trust(otherCard); } finally { storage.close(); }
    },
    allow(rule) {
      const storage = new Store(dir, card.id);
      try { storage.allowTimes(rule); } finally { storage.close(); }
    },
  };
}

export async function localNetwork(names) {
  const root = await mkdtemp(join(tmpdir(), 'darep-demo-'));
  const participants = [];
  const sockets = [];
  async function close() {
    try { await Promise.all(participants.map(p => p.stop())); }
    finally { await rm(root, { recursive: true, force: true }); }
  }
  try {
    for (const name of names) {
      const socket = await reservePort();
      sockets.push(socket);
      participants.push(participant(root, name, socket.address().port));
    }
    return { root, ...Object.fromEntries(participants.map((p,i) => [names[i], p])), close };
  } catch (error) { await close(); throw error; }
  finally { await Promise.all(sockets.map(s => new Promise(resolve => s.close(resolve)))); }
}

export async function localPair() {
  const network = await localNetwork(['alice', 'bob']);
  const {alice,bob} = network;
  try {
    for (const [owner, peer] of [[alice, bob], [bob, alice]]) {
      owner.trust(peer.card);
      const { requestKey, ...rule } = sample(peer.card.id);
      owner.allow({ ...rule, slots: [...rule.slots, '2030-04-07T18:00:00Z'] });
    }
    return network;
  } catch (error) { await network.close(); throw error; }
}

export async function call(client, name, args = {}) {
  const result = await client.callTool({ name, arguments: args });
  if (result.isError) throw new Error(result.content[0].text);
  return JSON.parse(result.content[0].text);
}
export const sample = peer => ({
  requestKey: 'weekly-padel-example', peer, activity: 'Weekly padel',
  originalStart: '2030-04-06T10:00:00+01:00', durationMinutes: 60,
  slots: ['2030-04-07T14:00:00+01:00', '2030-04-07T16:00:00+01:00'],
});
