# Python reference peer (Wire v2)

This peer is the second implementation of DAREP Wire v2. It manages its own identity document and P-256 keys, pinned contacts, grants, records and SQLite outbox, and exposes an MCP stdio interface for agents.

Under decision D8 it conforms to the core ([signed records](../../spec/records.md), [delivery contract](../../spec/delivery.md), [HTTPS binding](../../spec/https-binding.md), receipts and rejections) plus `https://darep.org/ext/core/v2#message` and the `https://darep.org/ext/work/v2` handoff types. The `work/v2` handoff types are experimental and outside frozen Wire v2 conformance; their normative publication is future work. Experimental `reschedule/v2` stays Node-only. A record of any other type is still verified, stored and acknowledged, then given the outcome `unsupported` (delivery.md §3.3).

| File | Role |
| --- | --- |
| `wire.py` | Records layer: strict I-JSON, canonical base64url, the ES256 allow-list, `kid` URLs, identity documents and pins (P-0), the envelope, and the verification procedure of records.md §8 with its codes. It verifies and hashes the bytes received and never re-serializes them (NC1). |
| `work.py` | The types this peer applies: `core/v2#message` and the handoff lifecycle (`#handoff`, `#accept`, `#decline`, `#complete`), with the verb each needs. |
| `mailbox_db.py` | Store and pipelines: receive = verify → store → ack → apply, deduplication, stored receipts, pending and stale records, signed post-store rejections, store-once outbox, attempt evidence, grants and approvals that are closed and never deleted. |
| `peer.py` | HTTPS binding (inbox, identity document, status codes and `application/problem+json`), the sender's attempt classification, the outbox worker and the CLI. |
| `run_vectors.py` | Runs every vector in `vectors/v2/records/` and `vectors/v2/delivery/`. |
| `make_vector.py`, `check-vector.mjs` | A Python-signed handoff and Python-issued receipt, checked offline by the spec's Node reference verifier. |

## Install and run the checks

Run every command in this README from the repository root, with Python 3.11 or later and Node 22.18 or later. Dependencies are pinned in `uv.lock`.

```sh
uv sync --locked --project reference/python --extra agent
reference/python/.venv/bin/python reference/python/test_peer.py      # unit tests + every applicable v2 vector
reference/python/.venv/bin/python reference/python/run_vectors.py    # the vector results on their own, one line each
node reference/python/check-vector.mjs                             # Node's reference verifier accepts Python's bytes
reference/python/.venv/bin/python reference/python/verify_interop.py # live Node↔Python exchange (see below)
```

**Live interop.** `verify_interop.py` starts the Node reference provider (`reference/node/`) and this peer as separate processes and runs handoffs in both directions, including receipt replay after dropped responses and restarts, owner isolation and the Node-only reschedule flow. Run `npm ci` in `reference/node/` first.

## Create an identity

```sh
P=reference/python/.venv/bin/python
PEER=reference/python/peer.py
"$P" "$PEER" init --dir .darep/carol --id acct:carol@carol.test --origin http://127.0.0.1:4713
"$P" "$PEER" card --dir .darep/carol
"$P" "$PEER" serve --dir .darep/carol --port 4713
```

`init` creates an identity document with two keys, one with purpose `record` (signs events) and one with purpose `provider` (signs receipts and rejections). The document `id` defaults to `https://<domain>/.well-known/darep/<name>`; pass `--doc-id` to choose another. Each key's `kid` is that URL plus a `#fragment`. The inbox is `<origin>/darep/v2/inbox`. `serve` also answers `GET` on the document's path so that owners can compare pins. Nothing ever fetches a document to verify a record (D2).

For separate hosts, use an HTTPS `--origin` whose hostname is in the certificate's SAN and pass `--tls-cert` and `--tls-key`. With a private CA, set `SSL_CERT_FILE=/path/to/ca.pem` for Python and, separately, `NODE_EXTRA_CA_CERTS=/path/to/ca.pem` for Node. Plain HTTP is accepted only on loopback.

## Pin a contact

A contact is `{"identity": <identity document>, "inbox": <inbox URL>}`, which is what `card` prints. Pinning it is an owner decision (records.md TA-2): there is no trust on first use. Two ways:

- **Manual.** Exchange `card` output over a channel you already trust and run `trust --dir DIR --card FILE`.
- **Pairing.** `invite`, then `inspect` and `approve --fingerprint` on each side. Both owners compare fingerprints over a trusted channel, and nothing is pinned until both have approved. The pairing message format is local to this peer. It is not part of Wire v2. The Node reference provider's owner console speaks the same format.

An address can belong to only one pinned document (TA-4). Re-pinning the same document is accepted only when it is a monotonic update (records.md §5.5); anything else is refused.

## Approve what the agent can disclose

Before an agent opens a handoff or sends a result, the owner approves the recipient and the **exact content**. An approval is used once, in the transaction that signs the record, and is then closed with `closedAt` and the reason `used`. It is never deleted.

```json
{"peer":"acct:bob@bob.test","action":{"kind":"handoff","summary":"The sample document is ready.","nextStep":"Check the fields.","expectedResult":"Report your findings."}}
```

```json
{"peer":"acct:bob@bob.test","threadId":"<existing-thread-uuid>","action":{"kind":"complete","result":"I checked all three fields."}}
```

```sh
"$P" "$PEER" allow-handoff --dir .darep/carol --file owner-rule.json
"$P" "$PEER" grant --dir .darep/carol --output .darep/carol.client.json --verbs read,send,commit
```

Grants use the verbs of records.md §1.3. `read` lists threads and messages. `send` opens a handoff or declines one. `commit` accepts work or completes it, because those bind the owner. `manage` is never granted to an agent. `revoke --id GRANT_ID` closes a grant. Every signed event carries `grant: {id, actor}`: the grant's opaque id with `actor: "agent"`, or an owner-act id with `actor: "owner"` for records the owner sends directly, such as `message --peer ADDRESS --text TEXT`.

## Connect an agent

Configure the Python interpreter with `peer.py stdio --grant CLIENT.json` as an MCP stdio server.

| Tool | Verb | Use |
| --- | --- | --- |
| `list_authorized_handoffs` | send or commit | Find a task or result the owner approved. Returns `nextTool` and `readyArguments`. |
| `request_handoff` | send | Open a thread with the approved fields and a `requestKey`. A retry with the same key returns the same thread. |
| `list_handoffs`, `get_handoff` | read | Threads, whose turn it is, records with direction, delivery state, apply outcome and any refusal. |
| `respond_handoff` | send (decline) or commit (accept, complete) | Answer at the current `expectedHead`. |

The CLI works with the same grant: `call --grant CLIENT.json --tool list_handoffs --json '{}'`. It also exposes this CLI-only tool through `peer.py call`:

| Tool | Verb | Use |
| --- | --- | --- |
| `list_messages` | read | Received and sent `core/v2#message` records; not registered on MCP stdio. |

## What the peer promises on the wire

- **Receive.** Pre-store checks run in the order of delivery.md §3.1 and fail with a registry code as `application/problem+json`. A record that passes is committed with `synchronous=FULL` together with its receipt, and only then answered `200`. Type logic, turns, heads and approvals run after that and never change whether a receipt is issued. A refusal becomes a signed rejection record queued back to the sender.
- **Duplicates.** The dedupe key is (recipient, `source`, `id`) and only the payload digest is compared. A duplicate, even a re-signed one or one past `expires`, gets the stored receipt byte for byte. A different payload under the same `id` gets `id-conflict`.
- **Ordering.** An event whose predecessor is missing is stored, acknowledged and held `pending` for up to 7 days, then refused with `missing-predecessor` or `expired-before-apply`. A reply to an old head is refused with `stale-head`.
- **Send.** A record is serialized and signed once and stored with one outbox entry per recipient. Every attempt sends those bytes. Receipts are verified as records.md §8 step 15 requires, and must come from the delivery's recipient. Transient results back off from 1 s, doubling, capped at 30 minutes, with jitter and `Retry-After`. A delivery fails on a permanent code or at `expires` plus 300 s, and so do queued replies that depend on it. Redirects are never followed.
- **Evidence.** The receiver keeps the inbound JWS, the issued receipt, the apply outcome and any rejection it emitted. The sender keeps every attempt with its status, the headers it relied on and the response body, including mismatched receipts.
