import assert from 'node:assert/strict';
import test from 'node:test';
import { localPair, sample, call, until } from '../examples/local-pair.js';
import { Store } from '../src/store.js';
import { startInput, parse } from '../src/protocol.js';
import { connectClient } from '../src/mcp.js';

test('simultaneous opposite requests survive transport and require resolving the overlap before any final agreement', async () => {
  const net = await localPair();
  const {alice,bob} = net;
  const dbs = [], clients = [];
  try {
    function openBeforeNetwork(owner,other) {
      const store = new Store(owner.dir,owner.card.id);
      dbs.push(store);
      return store.start(parse(startInput,sample(other.card.id)));
    }
    const left = openBeforeNetwork(alice,bob), right = openBeforeNetwork(bob,alice);
    assert.notEqual(left.threadId,right.threadId);
    await Promise.all([alice.start(),bob.start()]);
    const [a,b] = await Promise.all([alice,bob].map(async p => { const client=await connectClient(p.grant);clients.push(client);return client; }));
    const read=(client,id)=>call(client,'get_reschedule',{threadId:id});
    const act=(client,s,action)=>call(client,'respond_reschedule',{threadId:s.threadId,expectedHead:s.head,action});
    for(const client of [a,b]) {
      const states=await until(async()=>{const {threads}=await call(client,'list_reschedules');return threads.length===2 && threads;});
      for(const s of states) assert.deepEqual([...s.occurrenceConflict.threadIds].sort(),[left.threadId,right.threadId].sort());
    }
    await assert.rejects(call(a,'request_reschedule',{...sample(bob.card.id),requestKey:'third-attempt'}),/409.*Resume/);
    const ongoing=await act(b,await read(b,left.threadId),{kind:'accept'});
    await assert.rejects(act(b,ongoing,{kind:'confirm',slot:ongoing.slots[0]}),/409.*Another thread/);
    // A explicitly declines Bob's competing proposal. Both retain its full terminal history.
    const closed=await act(a,await read(a,right.threadId),{kind:'decline'});
    await until(async()=>(await read(b,right.threadId)).head===closed.head);
    const accepted=await read(b,left.threadId);
    assert.equal(accepted.occurrenceConflict,undefined);
    const chosen=await act(b,accepted,{kind:'confirm',slot:accepted.slots[0]});
    await until(async()=>(await read(a,left.threadId)).head===chosen.head);
    const final=await act(a,chosen,{kind:'confirm',slot:chosen.selectedSlot});
    await until(async()=>(await read(b,left.threadId)).head===final.head);
    assert.equal((await read(b,left.threadId)).status,'confirmed');
    await assert.rejects(call(a,'request_reschedule',{...sample(bob.card.id),requestKey:'after-confirm'}),/409.*Resume/);
    assert.equal((await read(a,right.threadId)).status,'declined');
    // Model an older store with two completed threads. A new reader must not invent a unique outcome.
    const legacy = {...right,status:'confirmed',selectedSlot:ongoing.slots[1],confirmedBy:[alice.card.id,bob.card.id],turn:null};
    dbs[0].db.prepare('UPDATE threads SET state=? WHERE id=?').run(JSON.stringify(legacy),legacy.threadId);
    const clash=(await read(a,left.threadId)).occurrenceConflict;
    assert.equal(clash.needsOwnerDecision,true);
    assert.deepEqual([...clash.confirmedSlots].sort(),[chosen.selectedSlot,legacy.selectedSlot].sort());
  } finally { await Promise.allSettled(clients.map(c=>c.close())); for(const db of dbs)db.close();await net.close(); }
});

test('owner timezone survives a restart; explicit display-zone never changes the wire instant or sharing authorization', async () => {
  const net=await localPair();
  let client,store;
  try {
    const {alice,bob}=net;
    store=new Store(alice.dir,alice.card.id);
    assert.equal(store.timeZone(),'UTC');
    assert.throws(()=>store.setTimeZone('NoSuch/Place'));
    store.setTimeZone('Europe/London');
    const occurrence={peer:bob.card.id,activity:'DST fixture',originalStart:'2030-10-26T10:00:00Z',durationMinutes:60,
      slots:['2030-10-27T00:30:00Z','2030-10-27T01:30:00Z']};
    alice.allow(occurrence);
    await alice.start();client=await connectClient(alice.grant);
    const {occurrences}=await call(client,'list_authorized_occurrences');
    const local=occurrences.find(o=>o.activity===occurrence.activity);
    assert.equal(local.display.timeZone,'Europe/London');
    assert.notEqual(local.display.slots[0],local.display.slots[1]);
    assert.ok(local.display.slots.every(s=>s.includes('01:30')&&s.includes('Europe/London')));
    const view=await call(client,'request_reschedule',{...occurrence,requestKey:'dst',displayTimeZone:'Asia/Taipei'});
    assert.ok(view.display.slots[0].includes('08:30'));
    assert.deepEqual(view.slots,occurrence.slots);
    assert.ok(!JSON.stringify(view.history[0].event).includes('Taipei'));
    await alice.stop();await alice.start();
    assert.equal((await call(client,'get_reschedule',{threadId:view.threadId})).display.timeZone,'Europe/London');
  } finally { await client?.close();store?.close();await net.close(); }
});
