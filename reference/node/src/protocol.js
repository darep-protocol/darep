import { createHash, randomUUID } from 'node:crypto';
import { z } from 'zod';
import { coreExtension, isMonotonicUpdate, makeEventRecord, typs, validateDocument } from './records.js';

export { RecordRejection } from './records.js';

export class Problem extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

export function requireThat(condition, status, message) {
  if (!condition) throw new Problem(status, message);
}

export function parse(schema, value) {
  const result = schema.safeParse(value);
  if (!result.success) throw new Problem(400, 'Invalid input: ' + result.error.issues[0].message);
  return result.data;
}

// Extension URIs (records.md §6.1). A record type is the extension URI plus '#' plus the action kind.
// Thread state stores the extension URI as its workflow; reschedule threads omit it.
export const eventType = 'https://darep.org/ext/reschedule/v2';
export const handoffType = 'https://darep.org/ext/work/v2';
export const understoodExtensions = Object.freeze([coreExtension, handoffType, eventType]);
export const eventMedia = typs.event;
export const receiptMedia = typs.receipt;
export const rejectionMedia = typs.rejection;
export const retryWindow = 7 * 24 * 60 * 60 * 1000;
// delivery.md §3.4: the only size limit in Wire v2.
export const maxBody = 64 * 1024;
export const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const label = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
export const identity = z.string().max(200).regex(new RegExp('^acct:[a-z0-9][a-z0-9._-]{0,62}@' + label + '(?:\\.' + label + ')+$'));
export const uuid = z.uuidv4();
const instant = z.iso.datetime({ offset: true, precision: 0 })
  .refine(s => Number.isFinite(Date.parse(s)), 'Expected a valid date and UTC offset')
  .transform(s => new Date(s).toISOString().replace('.000Z', 'Z'));
const slots = z.array(instant).min(1).max(8)
  .refine(values => new Set(values).size === values.length, 'Candidate times must be distinct');
const occurrence = {
  activity: z.string().trim().min(1).max(120),
  originalStart: instant,
  durationMinutes: z.number().int().min(1).max(1440),
  slots,
};
const request = z.strictObject({ kind: z.literal('request'), ...occurrence });
const accept = z.strictObject({ kind: z.literal('accept') });
const counter = z.strictObject({ kind: z.literal('counter'), slots });
const confirm = z.strictObject({ kind: z.literal('confirm'), slot: instant });
const decline = z.strictObject({ kind: z.literal('decline') });
// Use Unicode code points so independent implementations agree on the length of emoji.
const brief = z.string().trim().min(1).refine(s => s.isWellFormed(), 'Use valid Unicode text')
  .refine(s => [...s].length <= 1000, 'Maximum 1000 characters');
const handoffFields = { summary: brief, nextStep: brief, expectedResult: brief };
const handoff = z.strictObject({ kind: z.literal('handoff'), ...handoffFields });
const complete = z.strictObject({ kind: z.literal('complete'), result: brief });
export const response = z.discriminatedUnion('kind', [accept, counter, confirm, decline]);
export const startInput = z.strictObject({
  requestKey: z.string().regex(/^[a-zA-Z0-9._-]{1,100}$/),
  peer: identity, ...occurrence,
});
export const sharingRule = z.strictObject({
  peer: identity, ...occurrence, slots: z.array(instant).max(32),
});
export const respondInput = z.strictObject({ threadId: uuid, expectedHead: uuid, action: response });
export const startHandoffInput = startInput.pick({ requestKey: true, peer: true }).extend(handoffFields);
export const respondHandoffInput = respondInput.extend({ action: z.discriminatedUnion('kind', [accept, decline, complete]) });
export const handoffApproval = z.union([
  z.strictObject({ peer: identity, action: handoff }),
  z.strictObject({ peer: identity, threadId: uuid, action: complete }),
]);
export const listInput = z.strictObject({ before: z.number().int().positive().safe().optional() });
export const readInput = listInput.extend({ threadId: uuid });
// A Wire v2 contact is the owner's pin (records.md TA-2, P-1): an identity-document snapshot plus the
// binding configuration that says where to deliver. `id` is the contact's address and is the local key.
export const contactSchema = z.strictObject({
  id: identity, origin: z.string().max(2048), document: z.looseObject({}), inbox: z.string().max(2048).optional(),
});
export function serviceOrigin(value) {
  let url;
  try { url = new URL(value); } catch { throw new Problem(400, 'Invalid provider URL'); }
  const loopback = ['127.0.0.1', '[::1]', 'localhost'].includes(url.hostname);
  requireThat((url.protocol === 'https:' || (loopback && url.protocol === 'http:')) &&
    !url.username && !url.password && !url.search && !url.hash && url.pathname === '/',
    400, 'Provider origin requires HTTPS (HTTP is allowed on loopback)');
  return url.origin;
}
export function validateContact(value) {
  if (value?.identity && value?.inbox && Object.keys(value).every(k => ['identity', 'inbox'].includes(k))) {
    let url;
    try { url = new URL(value.inbox); } catch { throw new Problem(400, 'Invalid inbox URL'); }
    value = { id: value.identity.addresses?.[0], origin: url.origin, document: value.identity, inbox: value.inbox };
  }
  const card = parse(contactSchema, value);
  const origin = serviceOrigin(card.origin);
  let document;
  try { document = validateDocument(card.document); }
  catch (error) { throw new Problem(400, 'Invalid identity document: ' + error.message); }
  // A document may speak for several addresses. This provider keys pins by address, so it pins one per document.
  requireThat(document.addresses.length === 1 && document.addresses[0] === card.id, 400,
    'The identity document must list exactly the contact address');
  if (card.inbox) {
    const url = new URL(card.inbox);
    serviceOrigin(url.origin);
    requireThat(!url.username && !url.password && !url.hash, 400, 'Invalid inbox URL');
  }
  return { id: card.id, origin, document, ...(card.inbox ? { inbox: card.inbox } : {}) };
}
// §5.5: an unchanged or monotonic snapshot needs no new trust decision. Anything else does.
export const publicCard = card => ({ identity: card.document, inbox: card.inbox ?? card.origin + '/darep/v2/inbox' });
export function samePin(old, next) {
  return JSON.stringify(old.document) === JSON.stringify(next.document) || isMonotonicUpdate(old.document, next.document);
}

// Action payloads per record type. The v1 action.kind is the type fragment; the rest is data (records.md §6.1).
const rescheduleActions = z.discriminatedUnion('kind', [request, accept, counter, confirm, decline]);
const handoffActions = z.discriminatedUnion('kind', [handoff, accept, decline, complete]);
const actionsFor = { [eventType]: rescheduleActions, [handoffType]: handoffActions };
export const workflowOf = record => record.type.slice(0, record.type.indexOf('#'));
export const actionOf = record => ({ kind: record.type.slice(record.type.indexOf('#') + 1), ...record.data });
export const supportedType = type => {
  const split = type.indexOf('#'), extension = type.slice(0, split), kind = type.slice(split + 1);
  return (extension === handoffType ? ['handoff', 'accept', 'decline', 'complete'] :
    extension === eventType ? ['request', 'accept', 'counter', 'confirm', 'decline'] : []).includes(kind);
};
// Type data is checked only by the post-ack applier.
export function parseAction(record) {
  const schema = actionsFor[workflowOf(record)];
  requireThat(schema, 422, 'This provider does not apply record type ' + record.type);
  requireThat(!Object.hasOwn(record.data, 'kind') && record.to.length === 1, 422, 'Invalid record data for ' + record.type);
  return parse(schema, actionOf(record));
}
export const ownerGrant = () => ({ id: 'owner-' + randomUUID(), actor: 'owner' });
export function makeEvent(from, to, action, state = null, type = state?.workflow ?? eventType, grant = ownerGrant()) {
  const { kind, ...data } = action;
  return makeEventRecord({ source: from, to, type: type + '#' + kind, thread: state?.threadId,
    inReplyTo: state?.head ?? null, data, grant });
}

export function advance(state, event, action = actionOf(event)) {
  const { source, thread: subject, id, inReplyTo: previous } = event;
  const workflow = workflowOf(event);
  requireThat(event.to.length === 1, 400, 'Two-party threads have exactly one recipient');
  const to = event.to[0];
  requireThat(source !== to, 400, 'Choose a different participant');
  if (!state) {
    requireThat(action.kind === (workflow === handoffType ? 'handoff' : 'request'), 425, 'The opening request has not arrived');
    requireThat(subject === id && previous === null, 400, 'Invalid opening event');
    if (workflow === handoffType) return {
      workflow: handoffType, threadId: subject, head: id, participants: [source, to], turn: to, status: 'requested',
      summary: action.summary, nextStep: action.nextStep, expectedResult: action.expectedResult, result: null,
    };
    return {
      threadId: subject, head: id, participants: [source, to], turn: to, status: 'requested',
      activity: action.activity, originalStart: action.originalStart, durationMinutes: action.durationMinutes,
      slots: action.slots, selectedSlot: null, confirmedBy: [],
    };
  }
  requireThat(state.participants.includes(source) && state.participants.includes(to), 403, 'Wrong participants');
  requireThat(workflow === (state.workflow ?? eventType), 409, 'Thread uses a different event type');
  requireThat(subject === state.threadId && previous === state.head, 409, 'Thread changed; read it again');
  requireThat(source === state.turn, 409, 'It is not your turn or the thread is closed');
  const next = { ...state, head: id };
  if (workflow === handoffType) {
    if (action.kind === 'complete') {
      requireThat(state.status === 'accepted', 409, 'Accept the handoff before reporting a result');
      return { ...next, status: 'completed', result: action.result, turn: null };
    }
    if (action.kind === 'decline') return { ...next, status: 'declined', turn: null };
    requireThat(action.kind === 'accept' && state.status === 'requested', 409, 'Invalid handoff transition');
    return { ...next, status: 'accepted' };
  }
  if (action.kind === 'decline') return { ...next, status: 'declined', turn: null, selectedSlot: null, confirmedBy: [] };
  if (action.kind === 'accept') {
    requireThat(state.status === 'requested', 409, 'Coordination already accepted');
    return { ...next, status: 'accepted' };
  }
  requireThat(['accepted', 'awaiting_confirmation'].includes(state.status), 409, 'Accept coordination first');
  if (action.kind === 'counter') {
    return { ...next, slots: action.slots, selectedSlot: null, confirmedBy: [], status: 'accepted', turn: to };
  }
  requireThat(action.kind === 'confirm' && state.slots.includes(action.slot), 409, 'Choose a current candidate');
  requireThat(!state.selectedSlot || action.slot === state.selectedSlot, 409, 'Counter before choosing another time');
  const confirmedBy = [...state.confirmedBy, source];
  const complete = confirmedBy.length === 2;
  return { ...next, selectedSlot: action.slot, confirmedBy,
    status: complete ? 'confirmed' : 'awaiting_confirmation', turn: complete ? null : to };
}

