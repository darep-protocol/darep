'use strict';
const el = id => document.getElementById(id);
const node = (tag, text, className) => {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (className) element.className = className;
  return element;
};
const identity = value => typeof value === 'string' ? value : value?.id || '';
const storageKey = 'darep-owner';
let key;
try { key = sessionStorage.getItem(storageKey); } catch { /* storage can be disabled */ }
function takeLaunchKey() {
  const supplied = new URLSearchParams(location.hash.slice(1)).get('key');
  if (location.hash) history.replaceState(null, '', location.pathname + location.search);
  if (!supplied) return false;
  key = supplied;
  try { sessionStorage.setItem(storageKey,key); } catch { /* use the in-memory capability */ }
  return true;
}
takeLaunchKey();
let state = { contacts: [], grants: [], threads: [] };
let preview = null;
let recentGrantId = null;
let outgoingInviteId = null;
let firstVisit = true;
let olderPagesLoaded = false;
let refreshNumber = 0;
const deviceZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
const timeFields = new WeakMap();
let timezone, formatter, wallClock;
function displayIn(zone) {
  if (zone === timezone) return;
  const fields = [...document.querySelectorAll('input[type=datetime-local]')];
  const previous = fields.map(input => {
    if (!timezone || !input.value) return null;
    try { return instant(input); } catch { return null; }
  });
  const options = { timeZone: zone, year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hourCycle: 'h23', calendar: 'iso8601', numberingSystem: 'latn' };
  const timeFormatter = new Intl.DateTimeFormat('en-GB', { ...options, timeZoneName: 'short' });
  const wallFormatter = new Intl.DateTimeFormat('en-GB', { ...options, second:'2-digit' });
  timezone = zone; formatter = timeFormatter; wallClock = wallFormatter;
  fields.forEach((input,index) => {
    if (input.value) input.value = previous[index] ? localValue(previous[index]) : '';
    input.setAttribute('aria-description', 'Time zone ' + zone);
    timeFields.get(input)?.update(previous[index]);
  });
  for (const box of el('suggested').querySelectorAll('input')) box.nextElementSibling.textContent = pretty(box.value);
  if (preview && !el('verify').hidden) el('pair-expiry').textContent = 'Expires ' + pretty(preview.expires);
  el('zone-summary').textContent = 'Time zone · ' + zone;
  el('owner-zone').value = zone;
  el('timezone').textContent = 'Times shown and entered in ' + zone;
}
function pretty(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Unknown time' : formatter.format(date);
}
function localValue(value) {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '';
  const parts = Object.fromEntries(wallClock.formatToParts(d).map(part => [part.type,part.value]));
  return parts.year.padStart(4,'0') + '-' + parts.month + '-' + parts.day + 'T' +
    parts.hour + ':' + parts.minute + ':' + parts.second;
}
function localInstants(value) {
  const normalized = value.length === 16 ? value + ':00' : value;
  const utc = Date.parse(normalized + 'Z');
  if (!value || !Number.isFinite(utc)) return [];
  // A clock change can skip a local time or map it to two different instants.
  const offsets = [-48, 0, 48].map(hours => {
    const sample = utc + hours * 3600_000;
    return Date.parse(localValue(sample) + 'Z') - sample;
  });
  return [...new Set(offsets)].map(offset => new Date(utc - offset))
    .filter(d => localValue(d) === normalized).map(d => d.toISOString().replace('.000Z','Z')).sort();
}
function addTimeChoice(input, container) {
  const select = node('select');
  select.setAttribute('aria-label', 'Choose the intended time during the clock change');
  container.append(select);
  function update(preferred) {
    const instants = localInstants(input.value);
    const ambiguous = instants.length > 1;
    select.hidden = !ambiguous; select.required = ambiguous;
    const previous = preferred || select.value;
    select.replaceChildren();
    if (!ambiguous) return;
    select.add(new Option('This time occurs twice. Choose one.',''));
    for (const time of instants) select.add(new Option(pretty(time) + ' · UTC ' + time.slice(11,16),time));
    if (instants.includes(previous)) select.value = previous;
  }
  input.addEventListener('input', () => update());
  input.addEventListener('change', () => update());
  timeFields.set(input, { select, update }); update();
}
function instant(input) {
  const options = localInstants(input.value);
  if (!options.length) throw new Error('Check the date and time. This local time does not exist in your time zone.');
  if (options.length === 1) return options[0];
  const selected = timeFields.get(input).select.value;
  if (!options.includes(selected)) throw new Error('This time occurs twice. Select which occurrence you want to share.');
  return selected;
}
function notice(message = '', isError = false) {
  el('notice').classList.toggle('error', isError);
  el('notice').textContent = message;
}
async function api(operation, input = {}) {
  if (!key) throw new Error('Open the workspace URL shown in your local terminal.');
  const response = await fetch('/api/' + operation, {
    method: 'POST', headers: { authorization: 'Bearer ' + key, 'content-type': 'application/json' },
    mode: 'same-origin', credentials: 'omit', cache: 'no-store', redirect: 'error', body: JSON.stringify(input),
  });
  const data = await response.json();
  if (!response.ok) {
    if (response.status === 401) throw new Error('Your workspace session has expired. Open the URL shown in your local terminal again.');
    throw new Error(typeof data.error === 'string' ? data.error : 'Refresh the workspace and try again.');
  }
  return data;
}
function action(button, fn) {
  if (button.disabled) return;
  button.disabled = true;
  button.setAttribute('aria-busy', 'true');
  notice();
  Promise.resolve().then(fn).catch(error => notice(error.message, true)).finally(() => {
    button.disabled = false;
    button.removeAttribute('aria-busy');
  });
}
function onSubmit(id, fn) {
  el(id).addEventListener('submit', event => {
    event.preventDefault();
    action(event.submitter || el(id).querySelector('button[type=submit]'), fn);
  });
}
function onClick(id, fn) {
  el(id).addEventListener('click', () => action(el(id), fn));
}
const tabs = [...document.querySelectorAll('[role=tab]')];
function activate(tab) {
  firstVisit = false;
  for (const entry of tabs) {
    const current = entry === tab;
    entry.setAttribute('aria-selected', String(current));
    entry.tabIndex = current ? 0 : -1;
    el(entry.getAttribute('aria-controls')).hidden = !current;
  }
}
tabs.forEach((tab, index) => {
  tab.addEventListener('click', () => activate(tab));
  tab.addEventListener('keydown', event => {
    const target = { ArrowRight: (index + 1) % tabs.length, ArrowLeft: (index + tabs.length - 1) % tabs.length,
      Home: 0, End: tabs.length - 1 }[event.key];
    if (target === undefined) return;
    event.preventDefault(); activate(tabs[target]); tabs[target].focus();
  });
});

const statuses = { requested: 'Awaiting acceptance', accepted: 'Accepted', awaiting_confirmation: 'Awaiting the other person’s confirmation',
  confirmed: 'Both participants confirmed', declined: 'Declined', completed: 'Result returned' };
const localStatus = { requested: 'Request recorded locally', accepted: 'Acceptance recorded locally', awaiting_confirmation: 'Time selection recorded locally',
  confirmed: 'Both confirmations recorded locally', declined: 'Decline recorded locally', completed: 'Result recorded locally' };
const scopeNames = { read: 'Read work', coordinate: 'Propose, accept or decline coordination', confirm: 'Confirm an approved time', handoff: 'Submit approved project handoffs' };
function other(thread) {
  return thread.participants?.find(id => id !== identity(state.owner)) || '';
}
function choices(select, options, placeholder) {
  const previous = select.value;
  select.replaceChildren();
  if (placeholder) select.add(new Option(placeholder, ''));
  for (const [label, value] of options) select.add(new Option(label, value));
  if (options.some(option => option[1] === previous)) select.value = previous;
  else if (options.length === 1) select.value = options[0][1];
}
function addSlot(value = '') {
  const entry = node('div');
  const row = node('div', undefined, 'slot-row');
  const input = node('input');
  input.type = 'datetime-local'; input.step = '1'; input.value = value;
  input.setAttribute('aria-label', 'Candidate times');
  input.setAttribute('aria-description', 'Time zone ' + timezone);
  const remove = node('button', 'Remove', 'subtle');
  remove.type = 'button'; remove.addEventListener('click', () => entry.remove());
  row.append(input, remove); entry.append(row); addTimeChoice(input,entry); el('slots').append(entry);
  return input;
}
function prefill(thread) {
  el('peer').value = other(thread); el('activity').value = thread.activity;
  el('original').value = localValue(thread.originalStart);
  timeFields.get(el('original')).update(new Date(thread.originalStart).toISOString().replace('.000Z','Z'));
  el('duration').value = thread.durationMinutes;
  el('slots').replaceChildren(); el('suggested').replaceChildren();
  for (const slot of thread.slots || []) {
    const label = node('label', undefined, 'check');
    const box = node('input'); box.type = 'checkbox'; box.value = slot;
    label.append(box, node('span', pretty(slot))); el('suggested').append(label);
  }
  activate(el('tab-threads')); el('sharing-card').scrollIntoView({ block: 'start' }); el('peer').focus();
}
function rule(selectedSlots) {
  if (!el('sharing').reportValidity()) throw new Error('Complete the activity and contact details first.');
  return { peer: el('peer').value, activity: el('activity').value.trim(), originalStart: instant(el('original')),
    durationMinutes: Number(el('duration').value), slots: selectedSlots };
}
function conflictDetails(thread) {
  const conflict = thread.occurrenceConflict;
  const section = node('section',undefined,'conflict-box');
  section.setAttribute('aria-label','Competing threads for the same activity');
  section.append(node('h4','Review the competing threads for this activity'));
  if (conflict.confirmedSlots?.length > 1) {
    section.append(node('p','These records contain different confirmed times. Check the intended time with your contact.'));
  } else {
    section.append(node('p','Review each thread. When it is your turn, decline the extra request before confirming a time.'));
  }
  const group = node('ul');
  for (const id of conflict.threadIds) {
    const record = conflict.threads?.find(t=>t.threadId === id) || state.threads.find(t=>t.threadId === id);
    const row = node('li');
    row.append(node('strong',id === thread.threadId ? 'This thread' : 'Related thread'),node('code',id));
    if (record) {
      const status = record.status === 'confirmed' ? 'Confirmed time in this thread' : statuses[record.status] || record.status;
      row.append(node('span',status + (record.selectedSlot ? ' · ' + pretty(record.selectedSlot) : '')));
      if (record.turn) row.append(node('span',record.turn === identity(state.owner) ? 'Your turn' : 'Waiting for ' + record.turn));
    }
    group.append(row);
  }
  section.append(group);
  return section;
}
function renderThreads() {
  const list = el('threads'); list.replaceChildren();
  if (!state.threads.length) list.append(node('p', 'Your inbox is empty.', 'empty'));
  for (const thread of state.threads) {
    const item = node('article', undefined, 'item');
    item.dataset.thread = thread.threadId;
    const transport = thread.transport;
    const conflict = thread.occurrenceConflict?.needsOwnerDecision === true;
    const awaitingReceipt = transport?.headDelivery === 'queued' || transport?.headDelivery === 'failed';
    const status = (awaitingReceipt ? localStatus : statuses)[thread.status] || thread.status;
    item.append(node('h3', thread.activity || thread.summary || 'Project handoff'),
      node('p', other(thread), 'meta'), node('p', conflict ? 'This thread · ' + status : status, 'meta'));
    if (conflict) item.append(conflictDetails(thread));
    if (transport) {
      const label = {
        received: 'Latest event saved in your inbox',
        delivered: 'The other provider signed a receipt for the latest event',
        queued: 'Waiting for the other provider’s receipt for the latest event',
        failed: 'Delivery stopped. Check whether the other provider received the latest event.',
      }[transport.headDelivery];
      if (label) {
        const time = transport.deliveredAt && ['received','delivered'].includes(transport.headDelivery) ? ' · ' + pretty(transport.deliveredAt) : '';
        item.append(node('p',label + time,awaitingReceipt ? 'meta attention' : 'meta'));
      }
      if (transport.failed > (transport.headDelivery === 'failed' ? 1 : 0)) item.append(node('p','Stopped deliveries: ' + transport.failed + '. Compare records with your contact.','meta attention'));
      if (transport.pending > (transport.headDelivery === 'queued' ? 1 : 0)) {
        item.append(node('p','Events awaiting receipts: ' + transport.pending + '.','meta attention'));
      }
      const failure = transport.firstFailed;
      if (failure) {
        const reason = [failure.storedAt ? 'Saved ' + pretty(failure.storedAt) : '',failure.error].filter(Boolean).join(' · ');
        if (reason) item.append(node('p','First stopped event · ' + reason,'meta attention'));
        if (failure.canRetry) {
          const retry = node('button','Retry original event','subtle'); retry.type = 'button';
          retry.addEventListener('click',() => action(retry,async () => {
            if (!window.confirm('Send the same event and content to the original recipient again? If it was already saved, the recipient will return the original receipt.')) return;
            await api('retry-delivery',{threadId:thread.threadId,expectedEventId:failure.eventId});
            await refresh(); notice('Original event queued again. Check back for the receipt.');
          }));
          item.append(retry);
        } else {
          item.append(node('p','The retry window has closed. Check what your contact received before deciding how to proceed.','meta attention'));
        }
      }
    }
    if (thread.originalStart) item.append(node('p', 'Originally ' + pretty(thread.originalStart), 'meta'));
    if (thread.selectedSlot && !conflict) item.append(node('p', 'Selected ' + pretty(thread.selectedSlot), 'meta'));
    if (thread.nextStep) item.append(node('p','Next step · ' + thread.nextStep,'meta'));
    if (thread.expectedResult) item.append(node('p','Expected result · ' + thread.expectedResult,'meta'));
    if (thread.result) item.append(node('p','Returned result · ' + thread.result,'meta'));
    if (thread.turn && !(transport?.failed > 0)) item.append(node('p', thread.turn === identity(state.owner) ? 'Your turn' : 'Waiting for your contact', 'meta'));
    const canRespond = !(transport?.failed > 0) && thread.turn === identity(state.owner);
    if (state.handoffs && !thread.originalStart && thread.status === 'accepted' && canRespond) {
      const approve = node('button','Approve a result','text-button');
      approve.type = 'button';
      approve.addEventListener('click', () => {
        activate(el('tab-grants')); el('handoff-box').open = true;
        el('handoff-kind').value = 'complete'; el('handoff-kind').dispatchEvent(new Event('change'));
        el('handoff-thread').value = thread.threadId; el('handoff-result').focus();
      });
      item.append(approve);
    }
    if (thread.originalStart && thread.turn) {
      const fill = node('button', 'Set availability for this activity', 'text-button');
      fill.type = 'button'; fill.addEventListener('click', () => prefill(thread)); item.append(fill);
    }
    if (canRespond && thread.originalStart && !conflict && ['accepted','awaiting_confirmation'].includes(thread.status)) {
      const form = node('form'); const label = node('label','Final start time');
      const slotInput = node('select');
      const available = thread.selectedSlot ? [thread.selectedSlot] : thread.slots || [];
      choices(slotInput, available.map(slot => [pretty(slot), slot]), 'Choose a time to confirm');
      slotInput.required = true; label.append(slotInput);
      const confirm = node('button','Confirm as owner'); confirm.type = 'submit';
      form.append(label, confirm); item.append(form);
      form.addEventListener('submit', event => {
        event.preventDefault();
        action(confirm, async () => {
          await api('confirm', { threadId: thread.threadId, expectedHead: thread.head, slot: slotInput.value });
          await refresh(); notice('Your confirmation was recorded.');
        });
      });
    }
    if (canRespond && thread.originalStart) {
      const decline = node('button','Decline this thread','text-button'); decline.type = 'button';
      decline.addEventListener('click', () => action(decline,async () => {
        if (!window.confirm('Decline this thread for “' + thread.activity + '”?\n' + thread.threadId)) return;
        await api('decline',{threadId:thread.threadId,expectedHead:thread.head});
        await refresh(); notice('This thread was declined.');
      }));
      item.append(decline);
    }
    list.append(item);
  }
}
function renderContacts() {
  const list = el('contacts'); list.replaceChildren();
  if (!state.contacts.length) list.append(node('p','No paired contacts yet.','empty'));
  for (const peer of state.contacts) {
    const item = node('article', undefined, 'item');
    item.append(node('strong', identity(peer))); const details = node('details');
    details.append(node('summary','Show public key fingerprint'), node('code',peer.fingerprint)); item.append(details); list.append(item);
  }
  const options = state.contacts.map(p => [identity(p),identity(p)]);
  choices(el('peer'), options, options.length ? 'Choose a contact' : 'Pair with a contact first');
  choices(el('handoff-peer'), options, 'Choose a contact');
  renderPendingInvites();
}
function renderPendingInvites() {
  const invites = state.pendingInvites || [];
  const list = el('pending-invites');
  list.replaceChildren();
  el('pending-box').hidden = !invites.length;
  if (outgoingInviteId && !invites.some(i => i.nonce === outgoingInviteId)) {
    outgoingInviteId = null; el('outgoing-box').hidden = true; el('outgoing').value = '';
  }
  for (const invite of invites) {
    const tag = invite.nonce.slice(0,8).toUpperCase();
    if (outgoingInviteId === invite.nonce) {
      el('outgoing-hint').textContent = 'Invitation ' + tag + '. Ask your contact to inspect it and send back a reply code. Expires ' + pretty(invite.expires);
    }
    const item = node('article',undefined,'item');
    item.append(node('strong','Invitation ' + tag),node('p','Expires ' + pretty(invite.expires),'meta'));
    const cancel = node('button','Withdraw invitation','text-button');
    cancel.type = 'button';
    cancel.addEventListener('click', () => action(cancel, async () => {
      if (!window.confirm('Withdraw invitation ' + tag + '? This stops pairing even if your contact already sent a reply.')) return;
      const result = await api('cancel-invite',{nonce:invite.nonce});
      await refresh();
      notice(result.cancelled ? 'Invitation withdrawn.' : 'This invitation was used or expired. Check the current contacts.');
    }));
    item.append(cancel); list.append(item);
  }
}
function renderGrants() {
  const list = el('grants'); list.replaceChildren();
  if (!state.grants.length) list.append(node('p','No active agent grants.','empty'));
  for (const grant of state.grants) {
    const item = node('article', undefined, 'item');
    item.append(node('strong',grant.connectionName || 'Existing grant ' + grant.id.slice(0,8)),
      node('p',grant.file || 'Grant file path unavailable · ' + grant.id,'meta'),
      node('p',grant.scopes.map(scope => scopeNames[scope] || scope).join('、'),'meta'),
      node('p','Expires ' + pretty(grant.expires),'meta'));
    if (typeof grant.instructions === 'string') {
      const details = node('details');
      details.append(node('summary','Show connection settings'),node('pre',grant.instructions)); item.append(details);
    }
    const revoke = node('button','Revoke grant','text-button');
    revoke.type = 'button'; item.append(revoke); list.append(item);
    revoke.addEventListener('click', () => action(revoke, async () => {
      if (!window.confirm('Revoke this grant? The agent will need a new authorization to connect.')) return;
      await api('revoke', { id: grant.id });
      if (recentGrantId === grant.id) {
        recentGrantId = null; el('grant-result').hidden = true; el('instructions').textContent = '';
      }
      await refresh(); notice('Agent grant revoked.');
    }));
  }
  if (recentGrantId && !state.grants.some(g => g.id === recentGrantId)) {
    recentGrantId = null; el('grant-result').hidden = true; el('instructions').textContent = '';
  }
}
function approvalKey(approval) {
  const {kind,summary,nextStep,expectedResult,result} = approval.action;
  return JSON.stringify([approval.peer,approval.threadId || '',kind,summary,nextStep,expectedResult,result]);
}
function renderHandoffApprovals() {
  const list = el('handoff-approvals');
  const approvals = state.handoffApprovals || [];
  list.replaceChildren();
  if (!approvals.length) list.append(node('p','No unused handoff approvals.','empty'));
  for (const approval of approvals) {
    const item = node('article',undefined,'item');
    const open = approval.action.kind === 'handoff';
    item.append(node('h4',open ? 'Start handoff' : 'Return result'),node('p',approval.peer,'meta'));
    if (open) {
      item.append(node('p','Summary · ' + approval.action.summary),node('p','Next step · ' + approval.action.nextStep),
        node('p','Expected result · ' + approval.action.expectedResult));
    } else {
      item.append(node('code',approval.threadId),node('p','Approved result · ' + approval.action.result));
    }
    const revoke = node('button','Withdraw this approval','text-button'); revoke.type = 'button';
    revoke.addEventListener('click',() => action(revoke,async () => {
      const description = open ? approval.action.summary : approval.action.result;
      if (!window.confirm('Withdraw this unused approval for ' + approval.peer + '?\n' + description)) return;
      const input = {peer:approval.peer,action:approval.action};
      if (approval.threadId) input.threadId = approval.threadId;
      const {removed} = await api('withdraw-handoff',input);
      await refresh();
      notice(removed ? 'Unused handoff approval withdrawn.' : 'This approval is no longer on the list. Check the thread to see whether it was already sent.');
    }));
    item.append(revoke); list.append(item);
  }
  el('older-approvals').hidden = !state.nextApprovalPage;
}
onClick('older-approvals',async () => {
  const initial = state, before = state.nextApprovalPage;
  if (!before) return;
  const page = await api('handoff-approvals',{before});
  if (state !== initial || state.nextApprovalPage !== before) return;
  const seen = new Set(state.handoffApprovals.map(approvalKey));
  const extra = page.approvals.filter(item => !seen.has(approvalKey(item)));
  state.handoffApprovals.push(...extra);
  state.nextApprovalPage = page.nextBefore;
  renderHandoffApprovals(); notice('Loaded ' + extra.length + ' earlier approvals.');
});
function renderThreadControls() {
  choices(el('handoff-thread'), state.threads.filter(t => !t.originalStart && t.status === 'accepted' &&
    t.turn === identity(state.owner) && !(t.transport?.failed > 0))
    .map(t => [(t.summary || 'Handoff') + ' · ' + other(t), t.threadId]), 'Choose an incoming handoff');
  for (const button of document.querySelectorAll('[data-load-workflow]')) {
    button.hidden = !state.nextPages?.[button.dataset.loadWorkflow];
  }
  el('pages-note').hidden = !olderPagesLoaded;
  renderThreads();
}
for (const button of document.querySelectorAll('[data-load-workflow]')) {
  button.addEventListener('click', () => action(button, async () => {
    const workflow = button.dataset.loadWorkflow;
    const initial = state, before = state.nextPages?.[workflow];
    if (!before) return;
    const page = await api('threads',{workflow,before});
    if (state !== initial || state.nextPages[workflow] !== before) return;
    const ids = new Set(state.threads.map(t => t.threadId));
    const extra = page.threads.filter(t => !ids.has(t.threadId));
    state.threads.push(...extra); state.nextPages[workflow] = page.nextBefore;
    olderPagesLoaded = true;
    renderThreadControls(); notice('Loaded ' + extra.length + ' earlier requests.');
  }));
}
async function refresh() {
  const current = ++refreshNumber;
  const updated = await api('state');
  if (current !== refreshNumber) return;
  state = updated;
  olderPagesLoaded = false;
  displayIn(state.timeZone || 'UTC');
  el('identity').textContent = identity(state.owner); el('fingerprint').textContent = state.fingerprint;
  el('tab-threads').textContent = state.handoffs ? 'Work' : 'Rescheduling';
  el('threads-heading').textContent = state.handoffs ? 'Work requests' : 'Rescheduling requests';
  el('handoff-box').hidden = !state.handoffs; el('grant-handoff-label').hidden = !state.handoffs;
  renderContacts(); renderThreadControls(); renderGrants(); renderHandoffApprovals();
  if (firstVisit) activate(state.contacts.length || state.threads.length ? el('tab-threads') : el('tab-contacts'));
}

function outgoing(code, title, hint, inviteId = null) {
  outgoingInviteId = inviteId;
  el('outgoing-box').hidden = false; el('outgoing').value = code;
  el('outgoing-title').textContent = title; el('outgoing-hint').textContent = hint;
}
onClick('invite', async () => {
  const result = await api('invite');
  outgoing(result.code, 'Send the invitation code to your contact', 'Invitation ' + result.nonce.slice(0,8).toUpperCase() +
    '. Ask your contact to inspect it and send back a reply code. Expires ' + pretty(result.expires),result.nonce);
  await refresh();
});
onClick('copy', async () => {
  try { await navigator.clipboard.writeText(el('outgoing').value); notice('Code copied.'); }
  catch { el('outgoing').focus(); el('outgoing').select(); notice('Code selected. Use your copy shortcut.'); }
});
onClick('copy-command', async () => {
  try { await navigator.clipboard.writeText(el('instructions').textContent); notice('Connection settings copied.'); }
  catch {
    const range = document.createRange(); range.selectNodeContents(el('instructions'));
    const selection = window.getSelection(); selection.removeAllRanges(); selection.addRange(range);
    notice('Commands selected. Use your copy shortcut.');
  }
});
function clearPreview() {
  preview = null; el('verify').hidden = true; el('verified').checked = false;
}
el('incoming').addEventListener('input', clearPreview);
onSubmit('inspect', async () => {
  clearPreview(); const code = el('incoming').value.trim();
  const result = await api('inspect', { code });
  if (code !== el('incoming').value.trim()) return;
  preview = { ...result, code }; el('verify').hidden = false;
  el('outgoing-box').hidden = true;
  el('pair-peer').textContent = identity(result.peer);
  el('pair-fingerprint').textContent = result.fingerprint;
  el('pair-expiry').textContent = 'Expires ' + pretty(result.expires);
  const finish = result.kind === 'finish';
  el('verify-title').textContent = finish ? 'Confirm the verified identity' : 'Verify contact identity';
  el('verify-check').hidden = finish; el('verified').required = !finish;
  el('approve').textContent = finish ? 'Finish pairing' : 'Verify and generate reply';
  (finish ? el('approve') : el('verified')).focus();
});
onSubmit('verify', async () => {
  if (!preview || preview.code !== el('incoming').value.trim() ||
      (preview.kind !== 'finish' && !el('verified').checked)) throw new Error('Inspect and verify this code first.');
  const result = await api('approve', { code: preview.code, fingerprint: preview.fingerprint });
  clearPreview(); el('incoming').value = '';
  if (result.phase === 'answer') outgoing(result.code, 'Send the reply code to the inviter', 'After the inviter verifies your identity, paste their final code above.');
  else if (result.phase === 'finish') outgoing(result.code, 'Send the final code to your contact', 'Your contact has been saved. Ask them to import this code to finish pairing.');
  else { el('outgoing-box').hidden = true; el('outgoing').value = ''; }
  await refresh(); notice(result.phase === 'paired' ? 'Pairing complete on both sides.' : 'Identity verified. Share the code below.');
});
onSubmit('sharing', async () => {
  const typed = [...el('slots').querySelectorAll('input')].filter(input => input.value).map(instant);
  const checked = [...el('suggested').querySelectorAll('input:checked')].map(input => input.value);
  const selected = [...new Set([...checked,...typed])];
  if (!selected.length) throw new Error('Choose at least one candidate time to share.');
  await api('allow', rule(selected)); notice('Saved ' + selected.length + ' candidate times.');
});
onClick('clear-times', async () => {
  const data = rule([]);
  if (!window.confirm('Withdraw all candidate times for “' + data.activity + '” shared with ' + data.peer + '?')) return;
  await api('allow', data); el('suggested').replaceChildren(); el('slots').replaceChildren(); addSlot(); notice('Availability withdrawn for this activity.');
});
onSubmit('grant', async () => {
  const confirmation = document.querySelector('input[name=authority]:checked').value === 'agent';
  const input = { confirmation };
  if (state.handoffs && el('grant-handoff').checked) input.handoff = true;
  const result = await api('grant', input);
  recentGrantId = result.id;
  el('grant-result').hidden = false;
  el('instructions').textContent = Array.isArray(result.instructions) ? result.instructions.join('\n') : result.instructions || result.file;
  await refresh(); notice('Agent grant created.');
});
el('handoff-kind').addEventListener('change', () => {
  const complete = el('handoff-kind').value === 'complete';
  el('handoff-open').hidden = complete; el('handoff-reply').hidden = !complete;
});
onSubmit('handoff', async () => {
  const get = id => el(id).value.trim();
  let input;
  if (el('handoff-kind').value === 'handoff') {
    input = { peer: get('handoff-peer'), action: { kind: 'handoff', summary: get('handoff-summary'),
      nextStep: get('handoff-next'), expectedResult: get('handoff-expected') } };
    if ([input.peer,input.action.summary,input.action.nextStep,input.action.expectedResult].some(item => !item))
      throw new Error('Choose a contact and enter the three fields you approve for sharing.');
  } else {
    const thread = state.threads.find(t => t.threadId === get('handoff-thread'));
    if (!thread || !get('handoff-result')) throw new Error('Choose an incoming handoff and enter the result you approve for sharing.');
    input = { peer: other(thread), threadId: thread.threadId, action: { kind: 'complete', result: get('handoff-result') } };
  }
  await api('allow-handoff', input); await refresh(); notice('Handoff content approved.');
});
displayIn('UTC');
const zones = [...new Set(['UTC',deviceZone,...(Intl.supportedValuesOf?.('timeZone') || [])])].filter(Boolean);
for (const zone of zones) el('zone-names').append(new Option(zone,zone));
el('device-zone').textContent = 'Use device time zone · ' + (deviceZone || 'UTC');
el('device-zone').addEventListener('click', () => { el('owner-zone').value = deviceZone || 'UTC'; el('owner-zone').focus(); });
onSubmit('zone-setting',async () => {
  const zone = el('owner-zone').value.trim();
  try { new Intl.DateTimeFormat('en-GB',{timeZone:zone}); } catch { throw new Error('Enter a valid IANA time zone, such as Europe/London.'); }
  await api('set-zone',{zone}); await refresh(); notice('Time zone saved for display and entry.');
});
addTimeChoice(el('original'),el('original').parentElement);
el('add-slot').addEventListener('click', () => addSlot().focus());
onClick('refresh', async () => { await refresh(); notice('Workspace refreshed.'); });
addSlot();
window.addEventListener('hashchange', () => {
  if (takeLaunchKey()) refresh().then(() => notice('Connected to the local workspace.')).catch(error => notice(error.message,true));
});
refresh().catch(error => { el('identity').textContent = 'Disconnected'; notice(error.message, true); });
