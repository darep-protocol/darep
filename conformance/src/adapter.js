// Client side of the adapter contract (ADAPTER.md): one JSON object per line on the adapter's stdin and stdout.
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';

export class Unsupported extends Error {
  constructor(op, message) { super(message ?? `adapter does not support "${op}"`); this.op = op; }
}
export class AdapterError extends Error {
  constructor(op, message) { super(`adapter op "${op}" failed: ${message}`); this.op = op; }
}

export class Adapter {
  constructor(command, { cwd, log = () => {}, timeoutMs = 30_000 } = {}) {
    this.command = command;
    this.timeoutMs = timeoutMs;
    this.pending = new Map();
    this.nextId = 1;
    this.exited = null;
    // A user-supplied command string runs through the shell, as typed; a built-in is an argv array with no shell.
    this.child = Array.isArray(command)
      ? spawn(command[0], command.slice(1), { cwd, stdio: ['pipe', 'pipe', 'pipe'] })
      : spawn(command, { cwd, shell: true, stdio: ['pipe', 'pipe', 'pipe'] });
    this.child.stderr.setEncoding('utf8');
    this.child.stderr.on('data', chunk => log(chunk));
    this.child.on('exit', (code, signal) => {
      this.exited = { code, signal };
      for (const { reject, op } of this.pending.values()) reject(new AdapterError(op, `adapter exited (${signal ?? code})`));
      this.pending.clear();
    });
    this.child.on('error', error => { this.exited = { error }; });
    createInterface({ input: this.child.stdout }).on('line', line => this.receive(line, log));
  }
  receive(line, log) {
    let message;
    try { message = JSON.parse(line); } catch { log(`[adapter stdout, not JSON] ${line}\n`); return; }
    const waiter = this.pending.get(message?.id);
    if (!waiter) { log(`[adapter stdout, unknown id] ${line}\n`); return; }
    this.pending.delete(message.id);
    clearTimeout(waiter.timer);
    if (message.error) {
      const { code, message: text } = message.error;
      waiter.reject(code === 'unsupported' ? new Unsupported(waiter.op, text) : new AdapterError(waiter.op, text ?? code));
    } else waiter.resolve(message.result ?? {});
  }
  call(op, params = {}, { timeoutMs = this.timeoutMs } = {}) {
    if (this.exited) return Promise.reject(new AdapterError(op, 'adapter is not running'));
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new AdapterError(op, `no answer within ${timeoutMs} ms`));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer, op });
      this.child.stdin.write(JSON.stringify({ id, op, params }) + '\n');
    });
  }
  // Like call(), but an unsupported op resolves to null instead of throwing.
  async optional(op, params) {
    try { return await this.call(op, params); } catch (error) { if (error instanceof Unsupported) return null; throw error; }
  }
  async close() {
    if (this.exited) return;
    try { await this.call('stop', {}, { timeoutMs: 10_000 }); } catch { /* best effort */ }
    this.child.stdin.end();
    await new Promise(resolve => {
      if (this.exited) return resolve();
      const timer = setTimeout(() => { this.child.kill('SIGKILL'); resolve(); }, 5_000);
      this.child.once('exit', () => { clearTimeout(timer); resolve(); });
    });
  }
}
