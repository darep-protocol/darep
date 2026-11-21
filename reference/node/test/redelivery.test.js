import assert from 'node:assert/strict';
import test from 'node:test';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { localPair, call, until, sample } from '../examples/local-pair.js';
import { Store } from '../src/store.js';
import { connectClient } from '../src/mcp.js';

test('owner can redeliver the exact immutable event and blocked successors after fixing a peer route', async () => {
  const pair=await localPair();
  const {alice,bob}=pair;
  const rejecting=createServer((_req,res)=>res.writeHead(403).end());
  rejecting.listen(0,'127.0.0.1'); await once(rejecting,'listening');
  const admin=new Store(bob.dir,bob.card.id);
  let a,b;
  try {
    await Promise.all([alice.start(),bob.start()]);
    a=await connectClient(alice.grant); b=await connectClient(bob.grant);
    const {threadId}=await call(a,'request_reschedule',sample(bob.card.id));
    const read=client=>call(client,'get_reschedule',{threadId});
    await until(async()=>(await read(a)).transport.headDelivery==='delivered');
    await bob.stop();
    admin.trust({...alice.card,origin:'http://127.0.0.1:'+rejecting.address().port});
    const accepted=admin.respond({threadId,expectedHead:threadId,action:{kind:'accept'}});
    const selected=admin.respond({threadId,expectedHead:accepted.head,action:{kind:'confirm',slot:accepted.slots[0]}});
    await bob.start();
    const failed=await until(async()=>{const s=await read(b);return s.transport.failed===2 && s;});
    assert.equal(failed.head,selected.head);
    assert.equal(failed.transport.firstFailed.eventId,accepted.head);
    assert.throws(()=>admin.retryDelivery(threadId,selected.head),/first failed/);
    const eventRow=admin.db.prepare('SELECT body FROM events WHERE event_id=?').get(accepted.head);
    const actualNow=admin.now;
    admin.now=()=>Date.parse(JSON.parse(eventRow.body).expires);
    assert.throws(()=>admin.retryDelivery(threadId,accepted.head),/expired/);
    admin.now=actualNow;
    admin.trust(alice.card);
    assert.deepEqual(admin.retryDelivery(threadId,accepted.head),{eventId:accepted.head,queued:2,attemptsSoFar:1});
    assert.throws(()=>admin.retryDelivery(threadId,accepted.head),/first failed/);
    await until(async()=>(await read(b)).transport.headDelivery==='delivered');
    const result=await read(a);
    assert.equal(result.head,selected.head);
    assert.deepEqual(result.history.map(h=>h.event.id),[threadId,accepted.head,selected.head]);
    assert.equal(admin.db.prepare('SELECT COUNT(*) AS n FROM redeliveries').get().n,1);
  } finally {
    await a?.close();await b?.close();admin.close();await pair.close();
    await new Promise(done=>rejecting.close(done));
  }
});
