#!/usr/bin/env node
// DAREP conformance kit. A local verification aid, not certification. See ../README.md.
import { parseArgs } from 'node:util';
import { resolve, join } from 'node:path';
import { createWriteStream, mkdirSync } from 'node:fs';
import { Adapter } from '../src/adapter.js';
import { Report, ROLES } from '../src/report.js';
import { builtinAdapters, kit } from '../src/repo.js';

const usage = `Usage: darep-conformance <offline|live|all> --adapter <command|node-reference|python-reference> [options]

Modes
  offline   Records and delivery vectors through the adapter, with an injected clock.
  live      Real HTTP deliveries on loopback between a local reference peer and your implementation,
            in both directions, through a fault-injecting proxy (core/v2#message only).
  all       offline, then live.

Options
  --adapter CMD        Command that starts your adapter (see conformance/ADAPTER.md), or a built-in name.
  --roles LIST         Comma-separated subset of ${ROLES.join(',')} (default: every role the adapter declares).
  --experimental       Also run the experimental work/v2 delivery scenarios (reported separately).
  --out DIR            Report directory (default: ./darep-conformance-report).
  --version            Print the kit version.

Exit status: 0 passes, 1 does not pass, 2 usage or setup error.
Result wording: "passes the DAREP v0.1 conformance kit (verification aid, not certification)".`;

// Node 22 warns that node:sqlite (used by the reference peer in live mode) is experimental; keep the output clean.
process.removeAllListeners('warning');
process.on('warning', w => { if (w.name !== 'ExperimentalWarning') console.warn(`${w.name}: ${w.message}`); });

async function main() {
  const { values, positionals } = parseArgs({ allowPositionals: true, options: {
    adapter: { type: 'string' }, roles: { type: 'string' }, experimental: { type: 'boolean' },
    out: { type: 'string' }, help: { type: 'boolean' }, version: { type: 'boolean' },
  } });
  if (values.version) { console.log(`${kit.name} ${kit.version}`); return 0; }
  const mode = positionals[0];
  if (values.help || !['offline', 'live', 'all'].includes(mode) || !values.adapter) { console.log(usage); return values.help ? 0 : 2; }
  const command = builtinAdapters[values.adapter] ?? values.adapter;
  const outDir = resolve(values.out ?? 'darep-conformance-report');
  mkdirSync(outDir, { recursive: true });
  const logFile = createWriteStream(join(outDir, 'adapter.log'));
  const modes = mode === 'all' ? ['offline', 'live'] : [mode];
  // Name a built-in adapter rather than its local path, so a published report does not carry local paths.
  const report = new Report({ adapterCommand: builtinAdapters[values.adapter] ? `${values.adapter} (built-in)` : command, modes });
  const adapter = new Adapter(command, { cwd: process.cwd(), log: chunk => logFile.write(chunk) });
  try {
    let described;
    try { described = await adapter.call('describe', {}, { timeoutMs: 60_000 }); }
    catch (error) {
      console.error(`The adapter did not answer "describe": ${error.message}\nSee ${join(outDir, 'adapter.log')} for its output.`);
      return 2;
    }
    report.implementation = { name: described.name, version: described.version };
    const declared = described.roles ?? [];
    const requested = values.roles ? values.roles.split(',').map(r => r.trim()) : ROLES;
    const unknown = requested.filter(r => !ROLES.includes(r));
    if (unknown.length) { console.error('Unknown role: ' + unknown.join(', ')); return 2; }
    const roles = requested.filter(r => declared.includes(r));
    for (const role of ROLES) {
      report.role(role, roles.includes(role), roles.includes(role) ? null
        : !requested.includes(role) ? 'not requested' : 'not declared by the adapter');
    }
    console.log(`${kit.name} ${kit.version}: testing ${described.name} ${described.version ?? ''} (${modes.join(', ')}; roles ${roles.join(', ') || 'none'})`);
    if (modes.includes('offline')) {
      const { verifierCases, signerCases } = await import('../src/offline/records.js');
      const { deliveryCases } = await import('../src/offline/delivery.js');
      if (roles.includes('verifier')) await verifierCases(adapter, report);
      if (roles.includes('signer')) await signerCases(adapter, report);
      await deliveryCases(adapter, report, { roles, experimental: Boolean(values.experimental) });
    }
    if (modes.includes('live')) {
      const { liveCases } = await import('../src/live/cases.js');
      await liveCases(adapter, report, { roles, outDir });
    }
  } finally {
    await adapter.close();
    logFile.end();
  }
  const json = report.write(outDir);
  for (const row of json.summary) {
    console.log(`  ${row.subset.padEnd(12)} ${row.role.padEnd(9)} pass ${row.pass}  fail ${row.fail}  skip ${row.skip}  advisory ${row.advisory}`);
  }
  for (const c of json.cases.filter(c => c.status === 'fail')) console.log(`  FAIL ${c.id}: ${c.detail}`);
  console.log(json.result.statement);
  console.log(`Report: ${join(outDir, 'report.md')} and report.json`);
  return json.result.passes ? 0 : 1;
}

main().then(code => { process.exitCode = code; }, error => { console.error(error); process.exitCode = 2; });
