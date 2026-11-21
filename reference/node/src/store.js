import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { loadConfig } from './config.js';
import { makeEventRecord, makeReceiptRecord, signRecord, typs, coreExtension, rejectionType, skew, verifyRecord } from './records.js';
import { parseAction, workflowOf, supportedType } from './protocol.js';
import { timeZone } from './time-display.js';
import { actionOf, advance, hash, makeEvent, ownerGrant, parse, Problem, RecordRejection, requireThat, samePin,
  sharingRule, validateContact, eventType, handoffType, handoffApproval, uuid } from './protocol.js';

const migrations = [
  { version: 1, sql: readFileSync(new URL('./schema.sql', import.meta.url), 'utf8') },
  { version: 2, sql: readFileSync(new URL('./migration-002.sql', import.meta.url), 'utf8') },
];
export const scopes = ['read', 'coordinate', 'confirm', 'handoff'];
const pageSize = 25;

export class Store {
  constructor(dir, owner, options = {}) {
    this.owner = owner;
    this.now = options.now ?? Date.now;
    this.config = options.config ?? loadConfig(dir);
    this.capacity = options.capacity ?? (() => null);
    this.db = new DatabaseSync(join(dir, 'provider.sqlite'));
    this.db.exec('PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON');
    this.transaction(() => {
      const version = this.db.prepare('PRAGMA user_version').get().user_version;
      requireThat(version <= migrations.at(-1).version, 409, 'Database schema is newer than this provider');
      if (version === 0) {
        const legacy = this.db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='events'").get();
        requireThat(!legacy, 409, 'Wire v2 requires a fresh provider database');
      }
      for (const migration of migrations.filter(m => m.version > version)) {
        this.db.exec(migration.sql);
        this.db.exec('PRAGMA user_version=' + migration.version);
      }
    });
    this.db.prepare('INSERT OR IGNORE INTO owner VALUES (1, ?)').run(owner);
    requireThat(this.db.prepare('SELECT identity FROM owner').get().identity === owner,
      409, 'Database belongs to another identity');
  }
  transaction(fn) {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const result = fn();
      this.db.exec('COMMIT');
      return result;
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }
  trust(input) {
    const card = validateContact(input);
    requireThat(card.id !== this.owner, 400, 'Contact must belong to a peer');
    const pin = () => {
      this.checkPin(card);
      this.db.prepare('INSERT INTO contacts VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET card=excluded.card')
        .run(card.id, JSON.stringify(card));
    };
    if (this.db.isTransaction) pin();
    else this.transaction(pin);
    return card.id;
  }
  // records.md TA-4, P-0 and §5.5: one pinned document per address and per document id. A changed
  // snapshot is accepted only as a monotonic rotation; anything else is a new owner trust decision.
  checkPin(card) {
    const existing = this.contact(card.id);
    requireThat(!existing || samePin(existing, card), 409,
      'Identity already has a different pinned identity document. Remove the old pin before trusting a new one.');
    const other = this.db.prepare("SELECT id FROM contacts WHERE id != ? AND json_extract(card,'$.document.id') = ?")
      .get(card.id, card.document.id);
    requireThat(!other, 409, 'Another contact already uses this identity document');
  }
  contact(id) {
    const row = this.db.prepare('SELECT card FROM contacts WHERE id = ?').get(id);
    if (!row) return null;
    const card = JSON.parse(row.card);
    // A1 is a breaking change with a data wipe: a Wire v1 contact card cannot verify v2 records.
    requireThat(card.document, 409, 'This database holds Wire v1 contacts. Wire v2 needs a new provider directory.');
    return card;
  }
  // Pinned snapshot lookup by identity-document id (records.md P-2). Never fetched (P-3).
  document(documentId) {
    const row = this.db.prepare("SELECT card FROM contacts WHERE json_extract(card,'$.document.id') = ?").get(documentId);
    return row ? JSON.parse(row.card).document : null;
  }
  timeZone() {
    return this.db.prepare('SELECT time_zone FROM owner_preferences WHERE singleton=1').get()?.time_zone ?? 'UTC';
  }
  setTimeZone(zone) {
    const valid = parse(timeZone,zone);
    this.db.prepare('INSERT OR REPLACE INTO owner_preferences VALUES (1,?)').run(valid);
    return valid;
  }
  allowTimes(input) {
    const { peer, activity, originalStart, durationMinutes, slots } = parse(sharingRule, input);
    requireThat(this.contact(peer), 404, 'Pair the contact before authorizing an occurrence');
    this.transaction(() => {
      this.db.prepare("UPDATE sharing_rules SET closed_at=?,close_reason='withdrawn' WHERE peer=? AND activity=? AND original_start=? AND duration=? AND closed_at IS NULL")
        .run(this.stamp(), peer, activity, originalStart, durationMinutes);
      this.db.prepare('INSERT INTO sharing_rules(peer,activity,original_start,duration,slots) VALUES (?,?,?,?,?)')
        .run(peer, activity, originalStart, durationMinutes, JSON.stringify([...new Set(slots)]));
    });
  }
  checkTimes(peer, occurrence, proposed) {
    const row = this.db.prepare(
      'SELECT slots FROM sharing_rules WHERE peer=? AND activity=? AND original_start=? AND duration=? AND closed_at IS NULL'
    ).get(peer, occurrence.activity, occurrence.originalStart, occurrence.durationMinutes);
    const allowed = row ? JSON.parse(row.slots) : [];
    requireThat(proposed.every(slot => allowed.includes(slot)), 403, 'Owner has not authorized these times for this occurrence and contact');
  }
  authorizedOccurrences(before = Number.MAX_SAFE_INTEGER) {
    const rows = this.db.prepare(
      "SELECT rowid AS cursor, * FROM sharing_rules WHERE closed_at IS NULL AND rowid < ? AND slots != '[]' ORDER BY rowid DESC LIMIT ?"
    ).all(before, pageSize + 1);
    const page = rows.slice(0, pageSize);
    return { owner: this.owner, occurrences: page.map(row => ({
      peer: row.peer, activity: row.activity, originalStart: row.original_start,
      durationMinutes: row.duration, slots: JSON.parse(row.slots),
    })), nextBefore: rows.length > pageSize ? page.at(-1).cursor : null };
  }
  allowHandoff(input, { withdraw = false } = {}) {
    const { peer, threadId = '', action } = parse(handoffApproval, input);
    const serialized = JSON.stringify(action);
    return this.transaction(() => {
      if (withdraw) {
        const removed = this.db.prepare("UPDATE handoff_approvals SET closed_at=?,close_reason='withdrawn' WHERE peer=? AND topic=? AND action=? AND closed_at IS NULL")
          .run(this.stamp(), peer, threadId, serialized).changes;
        return { approved: false, removed: Number(removed) };
      }
      requireThat(this.contact(peer), 404, 'Pair the contact first');
      if (threadId) {
        const state = this.state(threadId);
        requireThat(state?.workflow === handoffType && state.participants[0] === peer &&
          state.turn === this.owner, 409, 'Expected an open incoming handoff from this contact');
      }
      this.db.prepare('INSERT OR IGNORE INTO handoff_approvals(peer,topic,action,request_key,created_at) VALUES (?,?,?,?,?)')
        .run(peer, threadId, serialized, 'approval-' + randomUUID(), this.stamp());
      return { approved: true };
    });
  }
  authorizedHandoffs(before = Number.MAX_SAFE_INTEGER) {
    const rows = this.db.prepare('SELECT rowid AS cursor,* FROM handoff_approvals WHERE closed_at IS NULL AND rowid<? ORDER BY rowid DESC LIMIT ?')
      .all(before, pageSize + 1);
    const page = rows.slice(0, pageSize);
    return { owner: this.owner, approvals: page.map(row => {
      const action = JSON.parse(row.action);
      if (!row.topic) {
        const {kind, ...brief} = action;
        return { peer: row.peer, action, nextTool: 'request_handoff',
          readyArguments: { requestKey: row.request_key, peer: row.peer, ...brief } };
      }
      const state = this.state(row.topic);
      return { peer: row.peer, threadId: row.topic, action, status: state.status, nextTool: 'respond_handoff',
        readyArguments: { threadId: row.topic, expectedHead: state.head, action } };
    }),
      nextBefore: rows.length > pageSize ? page.at(-1).cursor : null };
  }
  useHandoffApproval(peer, topic, action, recordId) {
    const consumed = this.db.prepare("UPDATE handoff_approvals SET closed_at=?,close_reason='used',used_by=? WHERE peer=? AND topic=? AND action=? AND closed_at IS NULL")
      .run(this.stamp(), recordId, peer, topic, JSON.stringify(action));
    requireThat(consumed.changes === 1, 403, 'Owner approval is required for this exact shared content');
  }
  issue(permissions, hours, requested, authority = {}) {
    requireThat(permissions.includes('read') && permissions.every(s => scopes.includes(s)), 400, 'Include read and use known scopes only');
    requireThat(Number.isInteger(hours) && hours > 0 && hours <= 720, 400, 'Grant duration must be 1–720 hours');
    const token = requested ? requested.token : randomBytes(32).toString('base64url');
    const id = requested ? parse(uuid, requested.id) : randomUUID();
    const expires = requested ? Date.parse(requested.expires) : Date.now() + hours * 3600_000;
    requireThat(typeof token === 'string' && /^[\w-]{43}$/.test(token) && expires > Date.now() &&
      expires <= Date.now() + hours * 3600_000, 400, 'Invalid grant credential or expiry');
    const digest = hash(token), encoded = JSON.stringify(permissions);
    if (requested) {
      // A caller that supplies its own credential may retry a committed approval after a lost response.
      const prior = this.db.prepare('SELECT token_hash,scopes,expires,closed_at FROM grants WHERE id=?').get(id);
      if (prior) {
        requireThat(!prior.closed_at && prior.token_hash === digest && prior.scopes === encoded && prior.expires === expires, 409, 'Grant already exists with different terms');
        return { id, token, expires: new Date(expires).toISOString(), scopes: permissions };
      }
    }
    const verbs = authority.verbs ?? [...new Set(['read', ...(permissions.some(p => ['coordinate','handoff'].includes(p)) ? ['send'] : []), ...(permissions.some(p => ['confirm','handoff'].includes(p)) ? ['commit'] : [])])];
    const types = authority.types ?? [ ...(permissions.some(p => ['coordinate','confirm'].includes(p)) ? [eventType] : []), ...(permissions.includes('handoff') ? [handoffType] : []) ];
    requireThat(verbs.every(v => ['read','send','commit'].includes(v)), 400, 'Invalid grant verbs');
    this.db.prepare('INSERT INTO grants(id,token_hash,scopes,expires,created_at,verbs,types,peers) VALUES (?,?,?,?,?,?,?,?)')
      .run(id, digest, encoded, expires, this.stamp(), JSON.stringify(verbs), JSON.stringify(types), authority.peers ? JSON.stringify(authority.peers) : null);
    return { id, token, expires: new Date(expires).toISOString(), scopes: permissions };
  }
  revoke(id) {
    return this.db.prepare("UPDATE grants SET closed_at=?,close_reason='revoked' WHERE id=? AND closed_at IS NULL").run(this.stamp(), id).changes === 1;
  }
  authorize(authorization) {
    const match = /^Bearer ([a-zA-Z0-9_-]{43})$/.exec(authorization ?? '');
    const grant = match && this.db.prepare('SELECT scopes FROM grants WHERE token_hash = ? AND expires > ? AND closed_at IS NULL')
      .get(hash(match[1]), Date.now());
    if (!grant) throw new Problem(401, 'A valid provider grant is required');
    return JSON.parse(grant.scopes);
  }
  // The signed reference to the authority an agent acted under (records.md §4.3, D5). Opaque, never the token.
  agentGrant(authorization) {
    this.authorize(authorization);
    const match = /^Bearer ([a-zA-Z0-9_-]{43})$/.exec(authorization);
    return { id: this.db.prepare('SELECT id FROM grants WHERE token_hash = ?').get(hash(match[1])).id, actor: 'agent' };
  }
  state(id) {
    const row = this.db.prepare('SELECT state FROM threads WHERE id = ?').get(id);
    return row ? JSON.parse(row.state) : null;
  }
  deliverySummary(threadId, head) {
    const row = this.db.prepare(
      "SELECT MAX(CASE WHEN e.event_id=? THEN COALESCE(o.status,'received') END) AS headDelivery," +
      " MAX(CASE WHEN e.event_id=? THEN o.receipt END) AS receipt," +
      " MAX(CASE WHEN e.event_id=? AND o.event_row IS NULL THEN e.stored_at END) AS incomingAt," +
      " COUNT(CASE WHEN o.status='queued' THEN 1 END) AS pending, COUNT(CASE WHEN o.status='failed' THEN 1 END) AS failed" +
      ", COUNT(CASE WHEN o.status='failed' AND o.refused_code IS NULL THEN 1 END) AS retryableFailed" +
      " FROM events e LEFT JOIN outbox o ON o.event_row=e.row_id WHERE e.topic=?"
    ).get(head,head,head,threadId);
    const {headDelivery,pending,failed,retryableFailed} = row;
    const deliveredAt = row.receipt ? JSON.parse(Buffer.from(row.receipt.split('.')[1], 'base64url')).data.storedAt : row.incomingAt;
    const summary = {headDelivery,deliveredAt,pending,failed,retryableFailed,firstFailed: null};
    if (retryableFailed) {
      const first = this.db.prepare(
        "SELECT e.event_id AS eventId,e.stored_at AS storedAt,json_extract(e.body,'$.expires') AS expires,o.refused_code AS refusal,o.error FROM outbox o JOIN events e ON e.row_id=o.event_row" +
        " WHERE e.topic=? AND o.status='failed' AND o.refused_code IS NULL ORDER BY e.row_id LIMIT 1"
      ).get(threadId);
      summary.firstFailed = first ? { ...first, canRetry: this.now() < Date.parse(first.expires) } : null;
    }
    return summary;
  }
  relatedReschedules(peer, occurrence) {
    // The local database belongs to one owner. Match the other participant as well as the occurrence.
    const rows = this.db.prepare(
      "SELECT state FROM threads WHERE json_extract(state,'$.activity')=? AND json_extract(state,'$.originalStart')=?" +
      " AND json_extract(state,'$.durationMinutes')=? AND json_extract(state,'$.status')!='declined'" +
      " AND (json_extract(state,'$.participants[0]')=? OR json_extract(state,'$.participants[1]')=?) ORDER BY id"
    ).all(occurrence.activity, occurrence.originalStart, occurrence.durationMinutes, peer, peer);
    return rows.map(row => JSON.parse(row.state)).filter(s =>
      s.confirmedBy.length || !this.deliverySummary(s.threadId,s.head).failed);
  }
  withDelivery(state) {
    const result = { ...state, transport: this.deliverySummary(state.threadId,state.head) };
    if (state.workflow !== handoffType && state.status !== 'declined') {
      const related = this.relatedReschedules(state.participants.find(p => p !== this.owner),state);
      if (related.length > 1) {
        const threads = related.map(({threadId,status,selectedSlot,turn}) => ({threadId,status,selectedSlot,turn}));
        result.occurrenceConflict = { needsOwnerDecision: true, threads, threadIds: threads.map(t=>t.threadId),
          confirmedSlots: [...new Set(threads.filter(t=>t.status==='confirmed').map(t=>t.selectedSlot))] };
      }
    }
    return result;
  }
  list(before = Number.MAX_SAFE_INTEGER, workflow = eventType) {
    const rows = this.db.prepare("SELECT state,last_row FROM threads WHERE last_row < ? AND COALESCE(json_extract(state,'$.workflow'),?)=? ORDER BY last_row DESC LIMIT ?")
      .all(before, eventType, workflow, pageSize + 1);
    const page = rows.slice(0, pageSize);
    return { owner: this.owner, threads: page.map(row => this.withDelivery(JSON.parse(row.state))),
      nextBefore: rows.length > pageSize ? page.at(-1).last_row : null };
  }
  view(id, before = Number.MAX_SAFE_INTEGER, workflow = eventType) {
    const state = this.state(id);
    if (!state || (state.workflow ?? eventType) !== workflow) throw new Problem(404, 'Unknown thread');
    const rows = this.db.prepare(
      'SELECT e.row_id, e.body, e.stored_at, e.outcome, e.outcome_code, o.refused_code, o.status, o.receipt, o.attempts, o.error, o.next_at FROM events e ' +
      'LEFT JOIN outbox o ON o.event_row = e.row_id WHERE e.topic = ? AND e.row_id < ? ORDER BY e.row_id DESC LIMIT ?'
    ).all(id, before, pageSize + 1);
    const page = rows.slice(0, pageSize);
    const nextBefore = rows.length > pageSize ? page.at(-1).row_id : null;
    const history = page.reverse().map(row => {
      // Outgoing receipts are verified before persistence. Their timestamp belongs to the recipient.
      const receipt = row.receipt ? JSON.parse(Buffer.from(row.receipt.split('.')[1], 'base64url').toString('utf8')) : null;
      const event = JSON.parse(row.body);
      return { event, record: event, kind: actionOf(event).kind, action: actionOf(event), receiptStoredAt: receipt?.data.storedAt ?? null,
        outcome: row.outcome, outcomeCode: row.outcome_code, refusal: row.refused_code, storedAt: row.stored_at, delivery: row.status ?? 'received',
        deliveredAt: row.status ? receipt?.data.storedAt ?? null : row.stored_at,
        attempts: row.attempts, deliveryError: row.error,
        nextAttemptAt: row.status === 'queued' && row.next_at > 0 ? new Date(row.next_at).toISOString() : null };
    });
    return { ...this.withDelivery(state), history, nextBefore };
  }
  records(before = Number.MAX_SAFE_INTEGER) {
    const rows = this.db.prepare('SELECT * FROM events WHERE row_id<? ORDER BY row_id DESC LIMIT ?').all(before, pageSize + 1);
    return { owner: this.owner, records: rows.slice(0, pageSize).map(row => ({
      record: JSON.parse(row.body), signedBytes: row.jws, receipt: row.receipt, storedAt: row.stored_at,
      outcome: row.outcome, outcomeCode: row.outcome_code, outcomeAt: row.outcome_at,
      direction: row.direction, grantClaimVerified: row.direction === 'out',
    })), nextBefore: rows.length > pageSize ? rows[pageSize - 1].row_id : null };
  }
  // The caller owns the transaction. Outgoing intents are signed durably before their first attempt.
  append(event, body, state, outgoing, action = actionOf(event)) {
    const used = this.db.prepare('SELECT 1 FROM events WHERE topic = ? AND event_id = ?').get(event.thread, event.id);
    requireThat(!used, 409, 'Event ID already used in this thread');
    const next = advance(state, event, action);
    const row = this.insertRecord(event, body, { direction: outgoing ? 'out' : 'in', outcome: 'applied' });
    const storedAt = row.stored_at, digest = row.digest;
    row.lastInsertRowid = row.row_id;
    this.db.prepare('INSERT OR REPLACE INTO threads VALUES (?, ?, ?)').run(event.thread, JSON.stringify(next), row.lastInsertRowid);
    if (next.workflow === handoffType && next.turn === null) {
      this.db.prepare("UPDATE handoff_approvals SET closed_at=?,close_reason='thread-closed' WHERE topic=? AND closed_at IS NULL").run(this.stamp(), event.thread);
    }
    if (outgoing) this.db.prepare('INSERT INTO outbox(event_row) VALUES (?)').run(row.lastInsertRowid);
    return { sha256: digest, storedAt };
  }
  start(input, workflow = eventType, grant = ownerGrant()) {
    const { requestKey, peer, ...occurrence } = input;
    return this.transaction(() => {
      const params = JSON.stringify(workflow === handoffType ? [workflow, peer, occurrence] : [peer, occurrence]);
      const prior = this.db.prepare('SELECT params, topic FROM request_keys WHERE id = ?').get(requestKey);
      if (prior) {
        requireThat(prior.params === params, 409, 'Request key already used for a different request');
        return this.view(prior.topic, undefined, workflow);
      }
      requireThat(this.contact(peer), 404, 'Unknown contact; exchange public contact cards first');
      const action = { kind: workflow === handoffType ? 'handoff' : 'request', ...occurrence };
      if (workflow !== handoffType) {
        this.checkTimes(peer, occurrence, occurrence.slots);
        const existing = this.relatedReschedules(peer,occurrence);
        requireThat(!existing.length, 409, 'This occurrence already has an active or confirmed thread. Resume: ' +
          existing.map(s=>s.threadId).join(', '));
      }
      const event = makeEvent(this.owner, peer, action, null, workflow, grant);
      if (workflow === handoffType) this.useHandoffApproval(peer, '', action, event.id);
      this.append(event, JSON.stringify(event), null, true, action);
      this.db.prepare('INSERT INTO request_keys VALUES (?, ?, ?)').run(requestKey, params, event.thread);
      return this.view(event.thread, undefined, workflow);
    });
  }
  respond({ threadId, expectedHead, action }, workflow = eventType, grant = ownerGrant()) {
    return this.transaction(() => {
      const state = this.state(threadId);
      if (!state || (state.workflow ?? eventType) !== workflow) throw new Problem(404, 'Unknown thread');
      const prior = this.db.prepare('SELECT body FROM events WHERE topic = ? AND parent = ? AND actor = ?')
        .get(threadId, expectedHead, this.owner);
      if (prior && JSON.stringify(actionOf(JSON.parse(prior.body))) === JSON.stringify(action)) return this.view(threadId, undefined, workflow);
      requireThat(expectedHead === state.head, 409, 'Thread changed; read it again');
      const failed = this.db.prepare("SELECT 1 FROM outbox o JOIN events e ON e.row_id=o.event_row WHERE topic=? AND status='failed' LIMIT 1").get(threadId);
      requireThat(!failed, 409, 'Thread has a failed delivery; inspect history before starting a fresh request');
      const peer = state.participants.find(id => id !== this.owner);
      const event = makeEvent(this.owner, peer, action, state, undefined, grant);
      if (action.kind === 'counter') this.checkTimes(peer, state, action.slots);
      if (action.kind === 'confirm') {
        this.checkTimes(peer, state, [action.slot]);
        const competing = this.relatedReschedules(peer,state).filter(s => s.threadId !== threadId);
        requireThat(!competing.length, 409, 'Another thread concerns the same occurrence. Ask the owners which thread to keep; decline the other open proposal before confirming. Related: ' +
          competing.map(s=>s.threadId).join(', '));
      }
      if (action.kind === 'complete') this.useHandoffApproval(peer, threadId, action, event.id);
      this.append(event, JSON.stringify(event), state, true, action);
      return this.view(threadId, undefined, workflow);
    });
  }
  stamp() { return new Date(this.now()).toISOString(); }
  insertRecord(event, body, { direction, jws = null, typ = typs.event, outcome = null, receipt = null, storedAt = this.stamp() }) {
    const retainUntil = new Date(Math.max(Date.parse(storedAt) + 30 * 86400_000, Date.parse(event.expires) + skew)).toISOString();
    const result = this.db.prepare(`INSERT INTO events(actor,recipient,event_id,topic,parent,body,digest,stored_at,
      direction,jws,typ,grant_id,grant_actor,receipt,outcome,outcome_at,apply_count,retain_until)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(event.source, direction === 'in' ? this.owner : event.to[0],
      event.id, event.thread, event.inReplyTo, body, hash(body), storedAt, direction, jws, typ,
      event.grant?.id ?? null, event.grant?.actor ?? null, receipt, outcome, outcome ? storedAt : null, outcome ? 1 : 0, retainUntil);
    return this.db.prepare('SELECT * FROM events WHERE row_id=?').get(result.lastInsertRowid);
  }
  prior(event, digest) {
    const row = this.db.prepare("SELECT * FROM events WHERE direction='in' AND actor=? AND recipient=? AND event_id=?")
      .get(event.source, this.owner, event.id);
    if (!row) return null;
    if (row.digest !== digest) throw new RecordRejection('id-conflict');
    return { sha256: row.digest, storedAt: row.stored_at, receipt: row.receipt };
  }
  // Provider records need a usable local key now, not just a configured kid.
  signProvider(record, typ) {
    const at = Date.parse(record.time), document = this.config.card.document;
    for (const signer of [this.config.providerSigner, this.config.signer]) {
      const entry = signer && document.keys.find(key => key.id === signer.kid);
      if (!entry || !entry.purpose.includes('provider') || entry.revoked ||
          !(Date.parse(entry.validFrom) <= at) || (entry.validUntil && !(at < Date.parse(entry.validUntil)))) continue;
      try {
        const token = signRecord(JSON.stringify(record), signer, typ);
        verifyRecord(token, { typ, mode: 'evidence' }, id => id === document.id ? document : null);
        return token;
      } catch { /* Another configured signer may still be usable. */ }
    }
    throw new RecordRejection('unavailable');
  }
  // Record and receipt share a FULL synchronous commit. No workflow logic runs in this transaction.
  receive(event, body, jws, typ = typs.event) {
    return this.transaction(() => {
      const prior = this.prior(event, hash(body));
      if (prior) return prior;
      const capacity = this.capacity(event.source);
      if (capacity) throw new RecordRejection(capacity);
      const saved = { sha256: hash(body), storedAt: this.stamp() };
      saved.receipt = this.signProvider(makeReceiptRecord(this.owner, event, saved, this.now()), typs.receipt);
      this.insertRecord(event, body, { direction: 'in', jws, typ, receipt: saved.receipt, storedAt: saved.storedAt });
      return saved;
    });
  }
  // Used for restored signed records and provider rejections: exact bytes, before any network attempt.
  queueSigned(jws, typ = typs.event, outcome = 'applied') {
    const body = Buffer.from(jws.split('.')[1], 'base64url').toString('utf8');
    const event = JSON.parse(body);
    let first;
    for (const recipient of event.to) {
      const row = this.insertRecord({ ...event, to: [recipient] }, body, { direction: 'out', jws, typ, outcome });
      this.db.prepare('INSERT INTO outbox(event_row) VALUES (?)').run(row.row_id);
      first ??= row;
    }
    return first;
  }
  signed(row) {
    return this.transaction(() => {
      const current = this.db.prepare('SELECT * FROM events WHERE row_id=?').get(row.row_id);
      if (current.jws) return current.jws;
      if (current.grant_actor === 'agent') {
        const grant = this.db.prepare('SELECT * FROM grants WHERE id=? AND closed_at IS NULL AND expires>?')
          .get(current.grant_id, this.now());
        requireThat(grant, 403, 'Grant closed before first signature');
        const event = JSON.parse(current.body), kind = actionOf(event).kind, extension = workflowOf(event);
        const verb = !supportedType(event.type) ? 'commit' : extension === handoffType ? (['handoff','decline'].includes(kind) ? 'send' : 'commit') :
          extension === eventType ? (kind === 'confirm' ? 'commit' : 'send') : 'commit';
        const types = JSON.parse(grant.types), peers = grant.peers ? JSON.parse(grant.peers) : null;
        requireThat(JSON.parse(grant.verbs).includes(verb) && (types.includes(event.type) || types.includes(extension)) &&
          (!peers || event.to.every(to => peers.includes(to))), 403, 'Grant does not authorize this record');
      }
      const token = signRecord(current.body, this.config.signer, current.typ);
      requireThat(Buffer.byteLength(token) <= 65536, 413, 'Record too large');
      verifyRecord(token, { typ: current.typ, mode: 'evidence' }, id => id === this.config.card.document.id ? this.config.card.document : null);
      this.db.prepare('UPDATE events SET jws=? WHERE row_id=?').run(token, row.row_id);
      this.db.prepare('UPDATE outbox SET next_at=0 WHERE event_row=?').run(row.row_id);
      return token;
    });
  }
  outcome(row, outcome, code = null) {
    let rejection = null;
    if (outcome === 'refused') {
      const event = JSON.parse(row.body);
      const record = makeEventRecord({ source: this.owner, to: event.source, type: rejectionType,
        thread: event.thread, inReplyTo: event.id, data: { code }, now: this.now(), required: [] });
      const jws = this.signProvider(record, typs.rejection);
      rejection = this.queueSigned(jws, typs.rejection).row_id;
    }
    this.db.prepare(`UPDATE events SET outcome=?,outcome_code=?,outcome_at=?,rejection_row=?,
      apply_count=apply_count+? WHERE row_id=?`).run(outcome, code, this.stamp(), rejection, outcome === 'pending' ? 0 : 1, row.row_id);
    return outcome;
  }
  applyOne(row) {
    const event = JSON.parse(row.body);
    if (row.typ === typs.rejection) {
      const outgoing = this.db.prepare("SELECT * FROM events WHERE direction='out' AND event_id=? AND recipient=? AND typ=?")
        .get(event.inReplyTo, event.source, typs.event);
      if (outgoing?.jws) {
        try {
          verifyRecord(row.jws, { typ: typs.rejection, mode: 'evidence', answered: outgoing.jws }, id => this.document(id));
          this.db.prepare(`UPDATE outbox SET refused_code=?,refusal_row=?,
            status=CASE WHEN status='queued' THEN 'refused' ELSE status END WHERE event_row=? AND refusal_row IS NULL`)
            .run(event.data.code, row.row_id, outgoing.row_id);
        } catch (error) { if (!(error instanceof RecordRejection)) throw error; }
      }
      return this.outcome(row, 'applied');
    }
    if (event.inReplyTo) {
      const parent = this.db.prepare(`SELECT * FROM events WHERE event_id=? AND
        (direction='out' OR recipient=?) ORDER BY topic=? DESC,row_id LIMIT 1`).get(event.inReplyTo, this.owner, event.thread);
      const waiting = !parent || !parent.outcome || parent.outcome === 'pending';
      if (waiting || row.outcome === 'pending') {
        const expires = Date.parse(event.expires), hold = Date.parse(row.stored_at) + 7 * 86400_000;
        if (this.now() >= Math.min(expires, hold)) return this.outcome(row, 'refused', expires < hold ? 'expired-before-apply' : 'missing-predecessor');
      }
      if (waiting) return row.outcome === 'pending' ? 'pending' : this.outcome(row, 'pending');
    }
    if (event.type === coreExtension + '#message') {
      const valid = Object.keys(event.data).length === 1 && typeof event.data.text === 'string' && event.data.text.length > 0;
      return valid ? this.outcome(row, 'applied') : this.outcome(row, 'refused', 'invalid-data');
    }
    if (!supportedType(event.type)) return this.outcome(row, 'unsupported');
    let action;
    try { action = parseAction(event); }
    catch { return this.outcome(row, 'refused', 'invalid-data'); }
    const state = this.state(event.thread);
    if (state && event.inReplyTo !== state.head) return this.outcome(row, 'refused', 'stale-head');
    if (state && event.source !== state.turn) return this.outcome(row, 'refused', 'wrong-turn');
    let next;
    try { next = advance(state, event, action); }
    catch (error) {
      if (!(error instanceof Problem)) throw error;
      return this.outcome(row, 'refused', 'invalid-transition');
    }
    this.db.prepare('INSERT OR REPLACE INTO threads VALUES (?,?,?)').run(event.thread, JSON.stringify(next), row.row_id);
    if (next.turn === null) this.db.prepare("UPDATE handoff_approvals SET closed_at=?,close_reason='thread-closed' WHERE topic=? AND closed_at IS NULL")
      .run(this.stamp(), event.thread);
    return this.outcome(row, 'applied');
  }
  applyReady() {
    this.transaction(() => {
      let progress = true;
      while (progress) {
        progress = false;
        for (const row of this.db.prepare("SELECT * FROM events WHERE direction='in' AND (outcome IS NULL OR outcome='pending') ORDER BY row_id").all()) {
          // Restart in storage order whenever a predecessor resolves, before later siblings can advance.
          if (this.applyOne(row) !== 'pending') { progress = true; break; }
        }
      }
      this.db.prepare("UPDATE grants SET closed_at=?,close_reason='expired' WHERE closed_at IS NULL AND expires<=?").run(this.stamp(), this.now());
      for (const row of this.db.prepare("SELECT e.* FROM events e JOIN outbox o ON o.event_row=e.row_id WHERE o.status='queued'").all()) {
        if (this.now() >= Date.parse(JSON.parse(row.body).expires) + skew) this.fail(row, 'expired');
      }
    });
  }
  due() {
    return this.db.prepare(`SELECT e.*,o.attempts,o.backoff_ms FROM outbox o JOIN events e ON e.row_id=o.event_row
      WHERE o.status='queued' AND o.refused_code IS NULL AND o.next_at<=? AND o.claim_until<=? AND NOT EXISTS
      (SELECT 1 FROM outbox p JOIN events pe ON pe.row_id=p.event_row WHERE pe.topic=e.topic
       AND pe.recipient=e.recipient AND pe.row_id<e.row_id AND p.status='queued') ORDER BY o.next_at,e.row_id LIMIT 8`).all(this.now(), this.now());
  }
  // due() owns retry scheduling; an explicit send still must acquire exclusive ownership.
  claim(row) {
    return this.transaction(() => {
      const token = randomUUID(), now = this.now();
      const claimed = this.db.prepare(`UPDATE outbox SET claim_token=?,claim_until=?
        WHERE event_row=? AND status='queued' AND refused_code IS NULL AND claim_until<=?`)
        .run(token, now + 60_000, row.row_id, now);
      if (!claimed.changes) return null;
      return { ...this.db.prepare('SELECT * FROM events WHERE row_id=?').get(row.row_id), claim_token: token };
    });
  }
  transmit(row, start) {
    // Serialize the final status check and transport initiation with other workers and refusals.
    // Only the synchronous start runs under the lock; never hold a DB transaction across an await.
    return this.transaction(() => {
      const current = this.db.prepare(`SELECT 1 FROM outbox WHERE event_row=? AND status='queued'
        AND refused_code IS NULL AND claim_token=? AND claim_until>?`).get(row.row_id, row.claim_token, this.now());
      if (!current) return null;
      if (this.now() >= Date.parse(JSON.parse(row.body).expires) + skew) { this.fail(row, 'expired'); return null; }
      return start();
    });
  }
  release(row) {
    this.db.prepare('UPDATE outbox SET claim_token=NULL,claim_until=0 WHERE event_row=? AND claim_token=?')
      .run(row.row_id, row.claim_token);
  }
  fail(row, code) {
    this.db.prepare("UPDATE outbox SET status='failed',error=? WHERE event_row=? AND status='queued'").run(code, row.row_id);
    const ids = new Set([row.event_id]);
    for (const later of this.db.prepare(`SELECT e.* FROM events e JOIN outbox o ON o.event_row=e.row_id
      WHERE e.topic=? AND e.recipient=? AND e.row_id>? AND o.status='queued' ORDER BY e.row_id`).all(row.topic, row.recipient, row.row_id)) {
      if (ids.has(later.parent)) {
        ids.add(later.event_id);
        this.db.prepare("UPDATE outbox SET status='failed',error='Earlier delivery failed' WHERE event_row=?").run(later.row_id);
      }
    }
  }
  attempt(row, result, { code = null, status = null, headers = {}, body = null, bodyBytes = null, retryAfter = 0 } = {}) {
    this.transaction(() => {
      const current = this.db.prepare('SELECT * FROM outbox WHERE event_row=?').get(row.row_id);
      this.db.prepare('INSERT INTO attempts(event_row,at,result,code,status,headers,body,body_bytes) VALUES (?,?,?,?,?,?,?,?)')
        .run(row.row_id, this.stamp(), result, code, status, JSON.stringify(headers), body, bodyBytes);
      if (row.claim_token && current.claim_token !== row.claim_token) return;
      if (current.status !== 'queued' && !(current.status === 'refused' && result === 'delivered')) return;
      if (this.now() >= Date.parse(JSON.parse(row.body).expires) + skew) { this.fail(row, 'expired'); return; }
      if (result === 'delivered') {
        this.db.prepare("UPDATE outbox SET status='delivered',attempts=attempts+1,receipt=?,error=NULL WHERE event_row=?").run(body, row.row_id);
      } else {
        const base = Math.min(1800_000, 1000 * 2 ** Math.min(current.attempts, 11));
        const delay = Math.max(current.backoff_ms, base + Math.floor(Math.random() * base * 0.2));
        this.db.prepare('UPDATE outbox SET attempts=attempts+1,error=?,next_at=?,backoff_ms=? WHERE event_row=?')
          .run(code ?? result, this.now() + Math.max(delay, retryAfter * 1000), delay, row.row_id);
        if (result === 'permanent') this.fail(row, code ?? 'permanent');
      }
    });
  }
  delivered(row, receipt) { this.attempt(row, 'delivered', { body: receipt }); }
  unsuccessful(row, error, permanent) { this.attempt(row, permanent ? 'permanent' : 'transient', { code: error }); }
  retryDelivery(threadId, expectedEventId) {
    return this.transaction(() => {
      const first = this.db.prepare(
        "SELECT e.row_id,e.event_id,e.stored_at,e.body,o.error,o.attempts FROM events e JOIN outbox o ON o.event_row=e.row_id" +
        " WHERE e.topic=? AND o.status='failed' AND o.refused_code IS NULL ORDER BY e.row_id LIMIT 1"
      ).get(threadId);
      requireThat(first && first.event_id === expectedEventId, 409, 'Read the current first failed delivery before retrying');
      requireThat(this.now() < Date.parse(JSON.parse(first.body).expires), 410, 'The original delivery window has expired');
      const state = this.state(threadId);
      if (first.event_id === threadId && state && state.workflow !== handoffType) {
        const peer = state.participants.find(p=>p!==this.owner);
        const others = this.relatedReschedules(peer,state).filter(s=>s.threadId!==threadId);
        requireThat(!others.length, 409, 'A newer thread exists for this occurrence. Inspect it before retrying the old opening: ' +
          others.map(s=>s.threadId).join(', '));
      }
      this.db.prepare('INSERT INTO redeliveries(event_row,requested_at,prior_error,prior_attempts) VALUES (?,?,?,?)')
        .run(first.row_id,this.stamp(),first.error,first.attempts);
      const changed = this.db.prepare(
        "UPDATE outbox SET status='queued', error=NULL, next_at=0 WHERE status='failed' AND refused_code IS NULL AND " +
        "(event_row=? OR (error='Earlier delivery failed' AND event_row IN (SELECT row_id FROM events WHERE topic=? AND row_id>?)))"
      ).run(first.row_id,threadId,first.row_id);
      return { eventId: first.event_id, queued: Number(changed.changes), attemptsSoFar: first.attempts };
    });
  }
  close() { this.db.close(); }
}
