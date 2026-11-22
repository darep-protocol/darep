// Locations inside the DAREP repository, and the spec revision the kit runs against.
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

export const kitRoot = fileURLToPath(new URL('../', import.meta.url));
export const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
export const vectorsRoot = join(repoRoot, 'vectors', 'v2');
export const kit = JSON.parse(readFileSync(join(kitRoot, 'package.json'), 'utf8'));
export const SPEC_LABEL = 'DAREP Wire v2 (spec v0.1)';
export const CLAIM = 'passes the DAREP v0.1 conformance kit (verification aid, not certification)';

export const loadJson = (...parts) => JSON.parse(readFileSync(join(vectorsRoot, ...parts), 'utf8'));

function git(...args) {
  try { return execFileSync('git', ['-C', repoRoot, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); }
  catch { return null; }
}
export function specRevision() {
  const commit = git('rev-parse', 'HEAD');
  return {
    label: SPEC_LABEL,
    tag: git('describe', '--tags', '--abbrev=0') ?? 'unknown',
    describe: git('describe', '--tags', '--always', '--dirty') ?? 'unknown (not a git checkout)',
    commit: commit ?? 'unknown',
    // Local edits under spec/ or vectors/ mean the run is not against the published revision.
    modified: commit ? Boolean(git('status', '--porcelain', '--', 'spec', 'vectors')) : null,
  };
}

// Built-in adapters for the two reference implementations in this repository.
export const builtinAdapters = {
  'node-reference': `node "${join(kitRoot, 'adapters', 'node', 'adapter.js')}"`,
  'python-reference': `"${join(repoRoot, 'reference', 'python', '.venv', 'bin', 'python')}" "${join(kitRoot, 'adapters', 'python', 'adapter.py')}"`,
};
