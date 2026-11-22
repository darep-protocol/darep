// Collects case results and writes the JSON and Markdown reports.
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { CLAIM, kit, specRevision } from './repo.js';
import { notCovered } from './coverage.js';

export const ROLES = ['verifier', 'signer', 'receiver', 'sender'];

export class Failure extends Error {}
export const check = (condition, why) => { if (!condition) throw new Failure(why); };

export class Report {
  constructor({ adapterCommand, modes }) {
    this.startedAt = new Date().toISOString();
    this.adapterCommand = adapterCommand;
    this.modes = modes;
    this.implementation = null;
    this.roles = {};          // role -> { tested: bool, reason }
    this.cases = [];
    this.notes = [];
  }
  role(role, tested, reason = null) { this.roles[role] = { tested, reason }; }
  // status: pass | fail | skip | advisory (a SHOULD that was not met; never a failure)
  // basis: 'normative' when the cited spec text states the requirement; 'vector-only' when only a vector implies it.
  add({ id, title, mode, role, subset = 'core', level = 'MUST', status, refs = [], detail = '', basis = 'normative', basisNote = null }) {
    if (!refs.length) throw new Error(`case ${id} has no spec reference`);
    this.cases.push({ id, title: title ?? id, mode, role, subset, level, basis, basisNote, status, refs, detail });
  }
  // Run fn as one case. fn returns an optional detail string; Failure means fail, Unsupported means skip.
  async run(meta, fn) {
    try {
      const detail = await fn();
      this.add({ ...meta, status: 'pass', detail: detail ?? '' });
    } catch (error) {
      if (error?.constructor?.name === 'Unsupported') this.add({ ...meta, status: 'skip', detail: error.message });
      else if (error instanceof Failure) this.add({ ...meta, status: 'fail', detail: error.message });
      else this.add({ ...meta, status: 'fail', detail: `${error?.name ?? 'Error'}: ${error?.message ?? error}` });
    }
  }
  advisory(meta, met, detail) {
    this.add({ ...meta, level: 'SHOULD', status: met ? 'pass' : 'advisory', detail });
  }
  summary() {
    const rows = [];
    for (const subset of ['core', 'experimental']) {
      for (const role of ROLES) {
        const list = this.cases.filter(c => c.subset === subset && c.role === role);
        if (!list.length) continue;
        const g = Object.groupBy(list, c => c.status);
        rows.push({ subset, role, pass: g.pass?.length ?? 0, fail: g.fail?.length ?? 0, skip: g.skip?.length ?? 0,
          advisory: g.advisory?.length ?? 0 });
      }
    }
    const core = this.cases.filter(c => c.subset === 'core');
    const coreFailures = core.filter(c => c.status === 'fail').length;
    const coreRun = core.filter(c => c.status !== 'skip').length;
    // A role is in the result's scope only if at least one of its core cases actually ran.
    const tested = ROLES.filter(r => this.roles[r]?.tested && core.some(c => c.role === r && c.status !== 'skip'));
    const passes = coreFailures === 0 && coreRun > 0 && tested.length > 0;
    return { rows, coreFailures, coreRun, tested, passes,
      statement: passes ? `Passes the DAREP v0.1 conformance kit (verification aid, not certification).`
        : `Does not pass the DAREP v0.1 conformance kit (verification aid, not certification).` };
  }
  toJSON() {
    const summary = this.summary();
    return {
      report: 'darep-conformance',
      claimWording: CLAIM,
      result: { passes: summary.passes, statement: summary.statement, coreFailures: summary.coreFailures,
        scope: { roles: summary.tested, modes: this.modes, subset: 'core' } },
      kit: { name: kit.name, version: kit.version },
      spec: specRevision(),
      implementation: this.implementation,
      adapter: this.adapterCommand,
      startedAt: this.startedAt,
      finishedAt: new Date().toISOString(),
      roles: this.roles,
      summary: summary.rows,
      cases: this.cases,
      notCovered,
      notes: this.notes,
      traceability: 'Every case lists the spec clauses it checks (refs). basis "vector-only" marks a check that only a vector implies.',
      disclaimer: 'A verification aid, not certification. Conformance means meeting all applicable normative ' +
        'requirements of DAREP Wire v2; this kit tests a subset of them (see notCovered). Experimental extensions ' +
        '(work/v2, reschedule/v2) are reported separately and do not affect the core result.',
    };
  }
  write(dir) {
    mkdirSync(dir, { recursive: true });
    const json = this.toJSON();
    writeFileSync(join(dir, 'report.json'), JSON.stringify(json, null, 2) + '\n');
    writeFileSync(join(dir, 'report.md'), markdown(json));
    return json;
  }
}

const esc = s => String(s ?? '').replaceAll('|', '\\|').replaceAll('\n', ' ');
function markdown(r) {
  const out = [];
  const impl = r.implementation ? `${r.implementation.name} ${r.implementation.version ?? ''}`.trim() : 'unknown';
  out.push('# DAREP conformance kit report', '');
  out.push(`**${r.result.statement}**`, '');
  if (r.result.passes) {
    out.push(`Scope of this result: roles ${r.result.scope.roles.join(', ')}; core subset; ${r.result.scope.modes.join(' and ')} mode. ` +
      'Quote it only together with this scope, the kit version and the spec revision below.', '');
  }
  out.push('| | |', '|---|---|');
  out.push(`| Implementation | ${esc(impl)} |`);
  out.push(`| Adapter | \`${esc(r.adapter)}\` |`);
  out.push(`| Kit | ${r.kit.name} ${r.kit.version} |`);
  out.push(`| Specification | ${r.spec.label}; tag \`${r.spec.tag}\`, \`${r.spec.describe}\`, commit \`${r.spec.commit}\`${r.spec.modified ? ' (spec or vectors modified locally)' : ''} |`);
  out.push(`| Modes | ${r.result.scope.modes.join(', ')} |`);
  out.push(`| Roles tested | ${Object.entries(r.roles).map(([k, v]) => r.result.scope.roles.includes(k) ? k
    : `${k}: not tested (${v.tested ? 'every case skipped' : v.reason})`).join('; ')} |`);
  out.push(`| Run | ${r.startedAt} to ${r.finishedAt} |`, '');
  out.push('## Summary', '', '| Subset | Role | Pass | Fail | Skip | Advisory (SHOULD not met) |', '|---|---|---|---|---|---|');
  for (const row of r.summary) out.push(`| ${row.subset} | ${row.role} | ${row.pass} | ${row.fail} | ${row.skip} | ${row.advisory} |`);
  out.push('', 'Only the core subset decides the result. Experimental `work/v2` scenarios are shown separately (D8). ' +
    'SHOULD-level findings are advisory and never fail a run.', '');
  const section = (title, list, empty) => {
    out.push(`## ${title}`, '');
    if (!list.length) { out.push(empty, ''); return; }
    out.push('| Case | Subset | Role | Level | Spec | Detail |', '|---|---|---|---|---|---|');
    for (const c of list) out.push(`| \`${esc(c.id)}\` | ${c.subset} | ${c.role} | ${c.level} | ${esc(c.refs.join(', '))} | ${esc(c.detail)} |`);
    out.push('');
  };
  section('Failures', r.cases.filter(c => c.status === 'fail'), 'None.');
  section('Advisory findings (SHOULD)', r.cases.filter(c => c.status === 'advisory'), 'None.');
  section('Skipped', r.cases.filter(c => c.status === 'skip'), 'None.');
  const vectorOnly = r.cases.filter(c => c.basis === 'vector-only');
  out.push('## Checks with no normative text behind them', '',
    'Every case cites the clauses it checks. These cases exist only because a vector implies them; no published normative text states the rule, so their result says nothing about conformance.', '');
  if (!vectorOnly.length) out.push('None in this run.', '');
  else { for (const c of vectorOnly) out.push(`- \`${esc(c.id)}\` (${c.status}): ${esc(c.basisNote)}`); out.push(''); }
  out.push('## Requirements not covered by this kit', '',
    'Passing the kit does not show that these requirements are met. Check them by review or with your own tests.', '');
  for (const item of r.notCovered) out.push(`- **${item.ref}**: ${item.requirement} *${item.why}*`);
  out.push('');
  if (r.notes.length) { out.push('## Notes', ''); for (const n of r.notes) out.push(`- ${n}`); out.push(''); }
  out.push('## All cases', '', '| Status | Case | Subset | Role | Level | Basis | Spec |', '|---|---|---|---|---|---|---|');
  for (const c of r.cases) out.push(`| ${c.status} | \`${esc(c.id)}\` | ${c.subset} | ${c.role} | ${c.level} | ${c.basis} | ${esc(c.refs.join(', '))} |`);
  out.push('', '## What this report means', '', r.disclaimer, '');
  return out.join('\n');
}
