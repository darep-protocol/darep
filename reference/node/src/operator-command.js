import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { initialize, loadConfig } from './config.js';
import { serviceOrigin } from './protocol.js';
import { startProvider } from './provider.js';
import { startOperator } from './operator.js';

function port(value, allowAutomatic = false) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < (allowAutomatic ? 0 : 1) || n > 65535) throw new Error('Invalid port');
  return n;
}
export async function runOwnerConsole(dir, values, tls) {
  if (values.mode && !['serve', 'attach'].includes(values.mode)) throw new Error('Expected --mode serve or attach');
  const uiPort = port(values['ui-port'] ?? 0, true);
  let card;
  if (existsSync(join(dir, 'provider.json'))) {
    card = loadConfig(dir).card;
    if ((values.id && values.id !== card.id) || (values.origin && serviceOrigin(values.origin) !== card.origin)) {
      throw new Error('The supplied identity or origin does not match the provider in this directory');
    }
  } else {
    if (values.mode === 'attach' || !values.id) throw new Error('For first-time setup supply --id acct:name@example.test');
    const defaultOrigin = 'http://127.0.0.1:' + port(values.port ?? 3100);
    card = initialize(dir, values.id, values.origin ?? defaultOrigin);
  }
  const backendPort = port(values.port ?? (new URL(card.origin).port || 3100));
  const provider = values.mode === 'attach' ? null : await startProvider({ dir, port: backendPort, host: values.host, tls });
  let panel;
  try { panel = await startOperator({ dir, port: uiPort }); }
  catch (error) { await provider?.close(); throw error; }
  console.log('Open this link in your local browser. It grants owner access. Keep it private.');
  console.log(panel.url);
  let stopping = false;
  const stop = async () => {
    if (stopping) return;
    stopping = true;
    await Promise.all([panel.close(), provider?.close()]);
  };
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
}
