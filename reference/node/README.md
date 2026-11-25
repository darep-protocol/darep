# DAREP reference provider (Node.js)

A reference implementation of DAREP Wire v2: [signed records](../../spec/records.md), the [delivery contract](../../spec/delivery.md) and the [HTTPS binding](../../spec/https-binding.md). It passes every records and delivery vector in [`vectors/v2/`](../../vectors/v2/).

| File | Role |
|---|---|
| `src/records.js` | Signed records: strict I-JSON, ES256 compact JWS over exact bytes, `kid` URLs, identity documents and pins, and the records.md §8 verification procedure. |
| `src/protocol.js` | Envelope construction, extension and type registry, grant verbs, input validation. |
| `src/store.js`, `src/schema.sql`, `src/migration-002.sql` | SQLite store and numbered migrations: receive pipeline (verify → store → ack → apply), receipts, signed rejections, outbox, delivery attempts, grants and owner approvals. |
| `src/provider.js` | HTTPS binding: inbox, identity documents, problem responses, and the sender's delivery worker. |
| `src/mcp.js` | MCP interface for agents, scoped by a grant. |
| `src/cli.js`, `src/config.js` | Command line and provider directory (identity, signing key). |
| `src/operator*.js`, `src/operator/` | Local owner console: pairing, approvals and grants in a browser on loopback. The pairing message format is local to the reference implementations and is not part of Wire v2. |
| `examples/local-pair.js` | Two loopback providers for tests and experiments. |

## Run

Run every command in this README from `reference/node/`. Node.js 22.18 or later. Node 22 prints an experimental warning for its built-in SQLite module.

```bash
npm ci
npm test
node src/cli.js --help
```

## Two providers on one machine

This walkthrough runs Alice and Bob as two Node providers on loopback, delivers one signed record from Alice to Bob, and shows the receipt coming back. For a walkthrough that sends a core `message` record from the Python peer instead, see the [darep.org Quickstart](https://darep.org/quickstart).

### Create and pin both identities

```bash
node src/cli.js init --dir .darep/alice --id acct:alice@alice.test --origin http://127.0.0.1:4711
node src/cli.js init --dir .darep/bob --id acct:bob@bob.test --origin http://127.0.0.1:4712
node src/cli.js card --dir .darep/alice > .darep/alice.card.json
node src/cli.js card --dir .darep/bob > .darep/bob.card.json
node src/cli.js trust --dir .darep/alice --card .darep/bob.card.json
node src/cli.js trust --dir .darep/bob --card .darep/alice.card.json
```

`card` prints `{"identity": <identity document>, "inbox": <inbox URL>}`. Pinning a card with `trust` is an owner decision (records.md TA-2): exchange cards over a channel you already trust. Plain HTTP is accepted only on loopback. For separate hosts, use HTTPS origins and pass `--tls-cert` and `--tls-key`, or terminate TLS at a reverse proxy that preserves `Host`. For a private CA, set `NODE_EXTRA_CA_CERTS=/path/to/ca.pem` for Node. The Python peer separately uses `SSL_CERT_FILE=/path/to/ca.pem`.

### Start both providers

Run each in its own terminal, from `reference/node/`, and leave them running:

```bash
node src/cli.js serve --dir .darep/alice --port 4711    # terminal A: prints "Provider ready: acct:alice@alice.test at 127.0.0.1:4711"
node src/cli.js serve --dir .darep/bob --port 4712      # terminal B
```

`serve` also runs the sender's delivery worker, so a provider delivers its outbox only while it is serving.

### Send a record

The Node CLI has no command for an owner to send a record directly. Here an agent credential sends a handoff that Alice's owner approved first. The handoff types (`https://darep.org/ext/work/v2`) are experimental and outside frozen Wire v2 conformance; signing, delivery and the receipt are core behaviour. In a third terminal, approve the exact content and issue the credentials:

```bash
cat > .darep/handoff-rule.json <<'EOF'
{"peer":"acct:bob@bob.test","action":{"kind":"handoff","summary":"The sample document is ready.","nextStep":"Check the fields.","expectedResult":"Report your findings."}}
EOF
node src/cli.js allow-handoff --dir .darep/alice --file .darep/handoff-rule.json
node src/cli.js grant --dir .darep/alice --output .darep/alice.client.json --verbs read,send
node src/cli.js grant --dir .darep/bob --output .darep/bob.client.json --verbs read
node src/cli.js call --grant .darep/alice.client.json --tool list_authorized_handoffs --json '{}'
```

The approval in that output has `readyArguments`. Pass them to `request_handoff` unchanged, with the `requestKey` from your output:

```bash
node src/cli.js call --grant .darep/alice.client.json --tool request_handoff --json '{"requestKey":"approval-<from your output>","peer":"acct:bob@bob.test","summary":"The sample document is ready.","nextStep":"Check the fields.","expectedResult":"Report your findings."}'
```

An approval is used once. A retry with the same `requestKey` returns the same thread and does not create another record.

### Check delivery and the receipt

Read Alice's side:

```bash
node src/cli.js call --grant .darep/alice.client.json --tool list_handoffs --json '{}'
```

When Alice's sender has verified a signed receipt from Bob (records.md §8 step 15), the thread shows `"headDelivery": "delivered"` and `"pending": 0`. `queued` means no verified receipt yet; read again after a few seconds. In `request_handoff` or `get_handoff` output, each sent record also has `delivery`, `attempts` and `receiptStoredAt`.

An outgoing record also shows `"outcome": "applied"`. That is Alice's local state: her provider applied its own record to its thread. It is not evidence that Bob stored or did anything. Delivery is shown only by `delivery: "delivered"` with a verified receipt. Neither field means Bob accepted or completed the work: the thread's `status` stays `requested` until Bob answers.

Read Bob's side:

```bash
node src/cli.js call --grant .darep/bob.client.json --tool list_records --json '{}'
```

Each stored record has `signedBytes` (Alice's compact JWS, byte for byte as received) and `receipt` (Bob's signed storage receipt, also a compact JWS). Base64url-decoding a JWS header and payload only displays them; it does not verify anything. Verification is the records.md §8 procedure against a pinned identity document, which Alice's sender ran on the receipt before marking the delivery `delivered`. A receipt means stored, never done.

### Stop and restart the receiver

1. Press Ctrl+C in terminal B to stop Bob. Leave Alice running.
2. In the third terminal, approve and send a second handoff: run `allow-handoff` with the same file, then `list_authorized_handoffs`, then `request_handoff` with the new `requestKey`.
3. Run `list_handoffs`. The new thread shows `"headDelivery": "queued"` and `"pending": 1`.
4. Restart Bob in terminal B with the same directory: `node src/cli.js serve --dir .darep/bob --port 4712`.
5. Run `list_handoffs` again until the new thread shows `delivered` (or `failed`). Alice's worker retries the same signed bytes with backoff, so the longer Bob was stopped, the longer this can take. A delivery still unacknowledged at the record's `expires` plus 300 seconds is marked `failed` and is not retried (delivery.md §7.3), so restart Bob before then; in this example `expires` is seven days after sending. Let the worker retry: repeating `request_handoff` with the same `requestKey` is safe and returns the same thread, but approving and sending a new request creates another record.

This is a process stop and restart, not a power-loss test. When finished, press Ctrl+C in both terminals; the data stays in `.darep/`.

### Other commands

`grant --dir DIR --output CLIENT.json --verbs read,send,commit` issues an agent credential with the verbs of records.md §1.3. `stdio --grant CLIENT.json` serves it to an agent as an MCP stdio server. `operator --dir DIR` starts the local owner console.
