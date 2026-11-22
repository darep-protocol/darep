# Adapter contract

The kit never links to your code. It starts your **adapter**, a small program you write next to your implementation, and talks to it over stdin and stdout. Any language works.

- The kit writes one JSON request per line: `{"id": 7, "op": "verify", "params": {...}}`.
- The adapter answers each request with one JSON line, in order: `{"id": 7, "result": {...}}`, or `{"id": 7, "error": {"code": "unsupported" | "failed", "message": "..."}}`.
- `unsupported` means "my implementation has no such operation". The kit then reports the cases that need it as **skipped**, never as passed. `failed` means the operation broke; the case fails.
- Write nothing else to stdout. Logs go to stderr; the kit saves them in `adapter.log` next to the report.
- When stdin closes, clean up and exit.

Both reference implementations have working adapters, which are the best examples: [`adapters/node/adapter.js`](adapters/node/adapter.js) and [`adapters/python/adapter.py`](adapters/python/adapter.py). Keep your adapter thin: it should call the same code paths your product uses, and only translate.

Instants are RFC 3339 strings such as `2026-11-20T10:00:30Z`. Records, receipts and identity documents travel exactly as in the spec: compact JWS strings and JSON objects.

## Which operations you need

| Role | Operations | Mode |
|---|---|---|
| any | `describe`, `stop` | both |
| verifier | `verify`, `validateIdentity` | offline |
| signer | `sign` | offline |
| receiver | `reset`, `setClock`, `tick`, `stats`, `inspectIncoming`; optionally `fault`, `inspectThread`, `seedOutgoing` | offline |
| sender | `reset`, `setClock`, `tick`, `queueSigned`, `attempt`, `inspectOutgoing`, `due` | offline |
| receiver, sender | `liveStart`, `send`; optionally `restart`, `inspectIncoming`, `inspectOutgoing`, `stats` | live |

The roles follow the spec: a verifier and a signer as in [records.md §11](../spec/records.md#11-conformance-and-test-vectors), a receiver and a sender as in [delivery.md §10](../spec/delivery.md#10-conformance). Declare only the roles you implement.

## Common

**`describe`** `{}` → `{ name, version, roles: ["verifier", "signer", "receiver", "sender"], live: true }`. `roles` lists what the adapter can test.

**`stop`** `{}` → `{}`. Stop servers and workers; the kit may call `reset` or `liveStart` again afterwards, or close stdin.

## Verifier and signer (offline)

**`verify`** `{ jws, context, identities }` → `{ verdict: "accept", kid, record, payloadSha256 }` or `{ verdict: "reject", code }`.
Run [records.md §8](../spec/records.md#8-verification-procedure-and-codes) on `jws`. `context` is `{ typ: [..], mode: "admission" | "evidence", now, receiver, understood: [..], answered }`, as in the [records vectors](../vectors/v2/records/README.md#vector-format); `receiver` and `answered` may be `null`. `identities` is the list of pinned identity documents. `record` is the parsed payload, `payloadSha256` the lowercase hex SHA-256 of the exact payload bytes, `code` a registry code.

**`validateIdentity`** `{ document }` → `{ verdict: "accept" | "reject" }`. Would you accept this identity document as a pin (records.md §5.1, P-0)?

**`sign`** `{ payload, typ, kid, privateJwk }` → `{ jws }`. Serialize `payload` (an envelope object) your own way, sign it with the P-256 private JWK under `kid` and `typ`, and return the compact JWS. The kit checks it with the spec's reference verifier and compares the signed payload with `payload`.

## Receiver and sender (offline)

Offline delivery runs the [delivery vectors](../vectors/v2/delivery/README.md) with the vector's clock injected. Your delivery worker must **not** run on its own in this mode: the kit decides when anything happens.

**`reset`** → `{ inbox }` for a receiver, `{}` for a sender. Throw away all state and start a fresh party:

```jsonc
{
  "role": "receiver",                       // or "sender"
  "address": "acct:carol@vectors.test",     // the address under test
  "document": { ... },                      // its identity document
  "privateKeys": { "<kid>": { <private JWK> } },   // test-only keys for that document
  "pins": [ { "identity": { ... }, "inbox": "http://127.0.0.1:…/darep/v2/inbox" } ],
  "extensions": ["https://darep.org/ext/core/v2"],
  "jitter": true,                           // false: use zero retry jitter (sender/receipt-mismatch profile)
  "now": "2026-11-20T10:00:30Z"             // initial clock
}
```

A receiver starts an HTTP inbox on loopback and returns its URL; the kit posts the vectors' requests to it over real HTTP. A sender's pins point at an endpoint the kit runs, so its requests reach the kit. The vectors' `https://*.vectors.test` inbox URLs are replaced by these loopback URLs; that is the only change.

**`setClock`** `{ now }` → `{}`. Your clock reads `now` until the next call.

**`tick`** `{}` → `{}`. Do any pending work at the current clock: apply stored records, hold deadlines, give up expired deliveries. Do not send anything.

**`stats`** `{}` → `{ incoming, rejections }`: how many incoming records are stored, and how many signed rejection records you have emitted.

**`inspectIncoming`** `{ source, id }` → `{ found, recordBytes, receipt, outcome, applyCount, rejection }`, where `outcome` is `applied`, `pending`, `refused`, `unsupported` or `null`, and `rejection` is `null` or `{ recordBytes, deliverTo: [addresses] }` for the rejection record you emitted about it.

**`fault`** `{ kind: "rate-limited" | "unavailable", source? }` → `{}`. Optional. Make the next deliveries fail capacity checks (C3) with that code. Without it, `reject-rate-limited` and `reject-unavailable` are skipped.

**`inspectThread`** `{ thread }` → `{ head, applyOrder: [ids] }`. Optional; used for apply-order checks.

**`seedOutgoing`** `{ recordBytes }` → `{}`. Optional, experimental scenarios only: a record this party already sent and applied.

**`queueSigned`** `{ recordBytes }` → `{}`. Store an already signed record as outgoing, with one delivery per address in its `to`, exactly as your sender stores what it signs (delivery.md §7.1).

**`attempt`** `{ id, recipient }` → `{ result }`. Make exactly one delivery attempt of that record to that recipient now, ignoring the retry schedule. `result` is `delivered`, `transient`, `permanent`, `receipt-mismatch` or, when nothing was sent, the delivery's current status.

**`inspectOutgoing`** `{ id, recipient }` → `{ found, status, recordBytes, receipt, attempts, backoffMs, nextAttemptAt, refusal }`. `status` is `queued`, `delivered`, `failed` or `refused`. `attempts` is the evidence list, oldest first: `{ at, result, code, status, headers, body }` with the HTTP status, the response headers you kept, and the response body as a string. `backoffMs` and `nextAttemptAt` describe the retry schedule; leave them out if you cannot report them, and the kit notes that the backoff was not checked. `refusal` is `null` or `{ code }` from a signed rejection record (delivery.md §7.5).

**`due`** `{}` → `{ deliveries: [{ id, recipient }] }`. Deliveries your worker would attempt now.

## Live (loopback)

In live mode your implementation runs for real: real clock, its own keys, its own background delivery worker. The kit runs its own peer (the Node reference provider with a fresh test identity) and two fault-injecting proxies.

**`liveStart`** `{ addressHint, kitCard }` → `{ card }`. Create a fresh identity (an address such as `addressHint`, an identity document and keys), start your inbox on loopback (`http://127.0.0.1:PORT/...`), start your delivery worker, and pin `kitCard`. `kitCard` and `card` are both `{ identity: <identity document>, inbox: <inbox URL> }`, the contact a provider exchanges out of band ([https-binding.md §1.1](../spec/https-binding.md#11-where-the-urls-come-from)). This is explicit local pinning, not discovery: the kit pins your card in its peer and writes both cards to `live-pins.json`. The kit's peer pins one address per identity document, so return a document that lists only your test address.

**`send`** `{ to, type, data }` → `{ id }`. Create, sign and store an event of that type and data to `to`, and let your worker deliver it as it normally would. The kit only uses `https://darep.org/ext/core/v2#message`.

**`restart`** `{}` → `{}`. Optional. Stop the implementation and start it again from its durable state, on the same inbox URL, with its worker running.

`inspectIncoming`, `inspectOutgoing` and `stats` work as in offline mode and make more checks possible. Without them, cases still run on what the kit sees on the wire, and the report says what was not inspected.
