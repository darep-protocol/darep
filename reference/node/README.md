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

```bash
node src/cli.js init --dir .darep/alice --id acct:alice@alice.test --origin http://127.0.0.1:4711
node src/cli.js init --dir .darep/bob --id acct:bob@bob.test --origin http://127.0.0.1:4712
node src/cli.js card --dir .darep/alice > .darep/alice.card.json
node src/cli.js card --dir .darep/bob > .darep/bob.card.json
node src/cli.js trust --dir .darep/alice --card .darep/bob.card.json
node src/cli.js trust --dir .darep/bob --card .darep/alice.card.json
node src/cli.js serve --dir .darep/alice --port 4711    # and, in another terminal, bob on 4712
```

`card` prints `{"identity": <identity document>, "inbox": <inbox URL>}`. Pinning a card with `trust` is an owner decision (records.md TA-2): exchange cards over a channel you already trust. Plain HTTP is accepted only on loopback. For separate hosts, use HTTPS origins and pass `--tls-cert` and `--tls-key`, or terminate TLS at a reverse proxy that preserves `Host`. For a private CA, set `NODE_EXTRA_CA_CERTS=/path/to/ca.pem` for Node. The Python peer separately uses `SSL_CERT_FILE=/path/to/ca.pem`.

`grant --dir DIR --output CLIENT.json --verbs read,send,commit` issues an agent credential with the verbs of records.md §1.3. `stdio --grant CLIENT.json` serves it to an agent as an MCP stdio server. `operator --dir DIR` starts the local owner console.
