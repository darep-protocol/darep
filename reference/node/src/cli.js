import { parseArgs } from 'node:util';
import { resolve } from 'node:path';
import { readFileSync } from 'node:fs';
import { initialize, loadConfig, readJson, writeNewJson } from './config.js';
import { publicCard } from './protocol.js';
import { Store } from './store.js';
import { connectClient, serveStdio } from './mcp.js';
import { startProvider } from './provider.js';

process.umask(0o077);
const usage = [
  'node src/cli.js init --dir DIR --id acct:alice@example.test --origin https://your-provider.example',
  'node src/cli.js card --dir DIR',
  'node src/cli.js trust --dir DIR --card PEER_PUBLIC_CARD.json',
  'node src/cli.js allow-times --dir DIR --file SHARING_RULE.json',
  'node src/cli.js allow-handoff --dir DIR --file HANDOFF_RULE.json',
  'node src/cli.js withdraw-handoff --dir DIR --file HANDOFF_RULE.json',
  'node src/cli.js grant --dir DIR --output CLIENT.json [--verbs read,send,commit] [--hours 168]',
  'node src/cli.js revoke --dir DIR --id GRANT_ID',
  'node src/cli.js serve --dir DIR [--host 127.0.0.1] [--port 3100] [--tls-cert FILE --tls-key FILE]',
  'node src/cli.js operator --dir DIR [--id acct:alice@example.test --origin http://127.0.0.1:4711] [--port 4711] [--ui-port 0] [--mode attach] [--host 127.0.0.1] [--tls-cert FILE --tls-key FILE]',
  'node src/cli.js tools --grant CLIENT.json',
  'node src/cli.js call --grant CLIENT.json --tool TOOL --json JSON',
  'node src/cli.js stdio --grant CLIENT.json',
].join('\n');
const print = value => console.log(JSON.stringify(value, null, 2));

async function main() {
  const [command, ...args] = process.argv.slice(2);
  if (!command || command === '--help') return console.log(usage);
  const commands = { init: ['dir', 'id', 'origin'], card: ['dir'], trust: ['dir', 'card'], 'allow-times': ['dir', 'file'],
    'allow-handoff': ['dir', 'file'], 'withdraw-handoff': ['dir', 'file'], operator: ['dir', 'id', 'origin', 'port', 'ui-port', 'mode', 'host', 'tls-cert', 'tls-key'],
    grant: ['dir', 'output', 'scopes', 'verbs', 'hours'], revoke: ['dir', 'id'], serve: ['dir', 'host', 'port', 'tls-cert', 'tls-key'],
    tools: ['grant'], call: ['grant', 'tool', 'json'], stdio: ['grant'] };
  if (!Object.hasOwn(commands, command)) throw new Error(usage);
  const options = Object.fromEntries(commands[command].map(k => [k, { type: 'string' }]));
  const { values } = parseArgs({ args, options });
  function required(name) {
    if (!values[name]) throw new Error('Missing --' + name);
    return values[name];
  }
  if (['tools', 'call', 'stdio'].includes(command)) {
    const grant = readJson(required('grant'));
    if (command === 'stdio') return serveStdio(grant);
    const client = await connectClient(grant);
    try {
      if (command === 'tools') return print((await client.listTools()).tools);
      const result = await client.callTool({ name: required('tool'), arguments: JSON.parse(required('json')) });
      const value = result.content[0]?.text;
      if (result.isError) throw new Error(value ?? 'Tool call failed');
      print(JSON.parse(value));
    } finally { await client.close(); }
    return;
  }
  const dir = resolve(required('dir'));
  function readTls() {
    if (!values['tls-cert'] && !values['tls-key']) return undefined;
    const certPath = required('tls-cert'), keyPath = required('tls-key');
    return { cert: readFileSync(certPath), key: readFileSync(keyPath) };
  }
  if (command === 'init') return print(publicCard(initialize(dir, required('id'), required('origin'))));
  if (command === 'operator') {
    const { runOwnerConsole } = await import('./operator-command.js');
    return runOwnerConsole(dir, values, readTls());
  }
  const { card } = loadConfig(dir);
  if (command === 'card') return print(publicCard(card));
  if (command === 'serve') {
    const origin = new URL(card.origin);
    const port = Number(values.port ?? (origin.port || 3100));
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid port');
    const host = values.host ?? '127.0.0.1';
    const provider = await startProvider({ dir, port, host, tls: readTls() });
    console.log('Provider ready: ' + card.id + ' at ' + host + ':' + provider.port);
    let stopping = false;
    const stop = async () => {
      if (stopping) return;
      stopping = true;
      await provider.close();
    };
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
    return;
  }
  const store = new Store(dir, card.id);
  try {
    if (command === 'trust') return print({ trusted: store.trust(readJson(required('card'))) });
    if (command === 'allow-times') {
      store.allowTimes(readJson(required('file')));
      return print({ saved: true });
    }
    if (command === 'allow-handoff') {
      store.allowHandoff(readJson(required('file')));
      return print({ saved: true });
    }
    if (command === 'withdraw-handoff') {
      const { removed } = store.allowHandoff(readJson(required('file')), { withdraw: true });
      return print({ approved: false, removed: Boolean(removed) });
    }
    if (command === 'revoke') return print({ revoked: store.revoke(required('id')) });
    const output = resolve(required('output'));
    const verbs = values.verbs?.split(',');
    if (verbs && (!verbs.includes('read') || verbs.some(v => !['read', 'send', 'commit'].includes(v)))) throw new Error('Invalid grant verbs');
    const permissions = verbs ? [...new Set(verbs.flatMap(v => v === 'read' ? ['read'] : v === 'send' ? ['coordinate', 'handoff'] : ['confirm', 'handoff']))] : (values.scopes ?? 'read,coordinate').split(',');
    const grant = store.issue(permissions, Number(values.hours ?? 168), undefined, verbs ? { verbs } : {});
    try { writeNewJson(output, { ...grant, url: card.origin + '/mcp' }); }
    catch (error) { store.revoke(grant.id); throw error; }
    print({ grantId: grant.id, scopes: grant.scopes, expires: grant.expires, output });
  } finally { store.close(); }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
