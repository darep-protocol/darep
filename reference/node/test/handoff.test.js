import assert from 'node:assert/strict';
import test from 'node:test';
import { call, localNetwork, sample, until } from '../examples/local-pair.js';
import { connectClient } from '../src/mcp.js';
import { Store } from '../src/store.js';
import { loadConfig } from '../src/config.js';
import { fingerprint, Pairing } from '../src/operator-pairing.js';

test('B can invite C without exposing A–B data; two concurrent work types recover after cold restarts', async t => {
  const network = await localNetwork(['alice', 'bob', 'carol']);
  const {alice, bob, carol} = network;
  const people = [alice, bob, carol];
  const clients = [];
  t.after(async () => {
    try { await Promise.allSettled(clients.map(c => c.close())); }
    finally {
      for (const person of people) person.admin?.close();
      await network.close();
    }
  });
  async function session(person, scope = ['read','coordinate','confirm','handoff']) {
    const grant = person.admin.issue(scope, 1);
    const client = await connectClient({ ...grant, url: person.card.origin + '/mcp' });
    clients.push(client);
    return client;
  }
  for (const person of people) {
    person.admin = new Store(person.dir, person.card.id);
    person.pairing = new Pairing(person.admin, loadConfig(person.dir));
    await person.start();
    person.agent = await session(person);
  }
  async function pair(sender, recipient) {
    const offer = await sender.pairing.invite();
    const answer = await recipient.pairing.approve(offer.code, fingerprint(sender.card));
    const finish = await sender.pairing.approve(answer.code, fingerprint(recipient.card));
    assert.deepEqual(await recipient.pairing.approve(finish.code, fingerprint(sender.card)), { phase:'paired' });
  }
  await pair(alice, bob);
  const request = sample(bob.card.id);
  const {requestKey, ...approved} = request;
  alice.allow(approved);
  bob.allow({...approved, peer:alice.card.id});
  const game = await call(alice.agent, 'request_reschedule', request);
  await pair(bob, carol);
  assert.equal(carol.admin.contact(alice.card.id), null);
  const action = {kind:'handoff', summary:'Two sample buttons share one label.', nextStep:'Review the sample.', expectedResult:'Return approved wording.'};
  const args = {requestKey:'fixture-review', peer:carol.card.id, ...action};
  delete args.kind;
  await assert.rejects(call(bob.agent,'request_handoff',args), /403/);
  bob.admin.allowHandoff({peer:carol.card.id, action});
  const [sent,retry] = await Promise.all([call(bob.agent,'request_handoff',args), call(bob.agent,'request_handoff',args)]);
  assert.equal(sent.head,retry.head);
  assert.equal((await call(bob.agent,'list_authorized_handoffs')).approvals.length,0);
  await assert.rejects(call(bob.agent,'request_handoff',{...args, requestKey:'new-disclosure'}), /403/);
  await assert.rejects(call(bob.agent,'request_handoff',{...args, summary:'Changed text'}), /409/);
  const id = sent.threadId;
  const read = client => call(client,'get_handoff',{threadId:id});
  const act = (client,state,action) => call(client,'respond_handoff',{threadId:id,expectedHead:state.head,action});
  await until(async () => (await read(bob.agent)).history[0].delivery==='delivered');
  const schedules = await until(async () => {
    const {threads} = await call(bob.agent,'list_reschedules');
    return threads.some(item => item.threadId === game.threadId) && threads;
  });
  assert.deepEqual(schedules.map(item => item.threadId), [game.threadId]);
  assert.equal((await call(alice.agent,'list_handoffs')).threads.length,0);
  await assert.rejects(read(alice.agent), /404/);
  await assert.rejects(call(carol.agent,'get_reschedule',{threadId:game.threadId}), /404/);
  const scheduler = await session(bob, ['read','coordinate']);
  assert.ok(!(await scheduler.listTools()).tools.some(x => x.name==='list_handoffs'));
  await assert.rejects(call(scheduler, 'get_reschedule', {threadId:id}), /404/);
  await assert.rejects(call(scheduler, 'respond_reschedule',{threadId:id,expectedHead:id,action:{kind:'decline'}}), /404/);
  const accepted = await act(carol.agent,await read(carol.agent),{kind:'accept'});
  await until(async () => (await read(bob.agent)).status==='accepted');
  await Promise.all([bob.stop(),carol.stop()]);
  await Promise.all([bob.start(),carol.start()]);
  const fresh = await session(carol);
  const resumed = await read(fresh);
  assert.equal(resumed.head,accepted.head);
  const result = {kind:'complete',result:'Use “確認新時段”.'};
  await assert.rejects(act(fresh,resumed,result), /403/);
  carol.admin.allowHandoff({peer:bob.card.id,threadId:id,action:result});
  const done = await act(fresh,resumed,result);
  assert.equal((await act(fresh,resumed,result)).head,done.head);
  const atBob = await until(async () => {const s=await read(bob.agent); return s.status==='completed'&&s;});
  assert.equal(atBob.result, result.result);
  assert.deepEqual(atBob.history.map(h=>h.action.kind),['handoff','accept','complete']);
  const advanceGame = (p,s,a) => call(p.agent,'respond_reschedule',{threadId:game.threadId,expectedHead:s.head,action:a});
  const willing = await advanceGame(bob,game,{kind:'accept'});
  const choice = await advanceGame(bob,willing,{kind:'confirm',slot:willing.slots[0]});
  await until(async()=> (await call(alice.agent,'get_reschedule',{threadId:game.threadId})).head===choice.head);
  const agreement = await advanceGame(alice,choice,{kind:'confirm',slot:choice.selectedSlot});
  await until(async()=> (await call(bob.agent,'get_reschedule',{threadId:game.threadId})).head===agreement.head);
  assert.equal(agreement.status,'confirmed');
  t.diagnostic('A–B confirmed a reschedule. B–C completed an authorized handoff across two cold provider restarts.');
});
