# DAREP test vectors

Run commands in this README from the repository root.

The `work/v2` handoff and `reschedule/v2` types are experimental extensions, not part of frozen Wire v2 conformance. Normative publication of `work/v2` is future work. Vectors and runners are verification aids, not a complete conformance determination.

| Directory | Covers |
|---|---|
| [`v2/records/`](v2/records/README.md) | [Signed records](../spec/records.md): envelope, `kid`, keys, `typ`, identity documents and the §8 verification procedure. Includes the reference verifier `check.mjs`. |
| [`v2/delivery/`](v2/delivery/README.md) | [Delivery contract](../spec/delivery.md) and [HTTPS binding](../spec/https-binding.md): receiver and sender scenarios. |

```bash
npm ci                      # from the repository root; the delivery generator uses `jose`
npm run vectors:check
npm run vectors:generate    # byte-for-byte deterministic: `git diff --exit-code vectors/` stays empty
```

## Test-only keys

`v2/records/keys.json` and `v2/delivery/test-keys.json` contain **private keys that are published on purpose**, so that anyone can regenerate, check and extend the vectors. They are test-only keys: they protect nothing, they MUST NOT sign any real record, and their identity documents MUST NOT be pinned outside tests. Every address and identity-document URL in the vectors uses the reserved `.test` top-level domain. They are not secrets, and a secret scanner that flags them can ignore these two files.

### Shared key access model (#25)

These are tooling formats, not wire schemas. Records use `keys.<alias>.{kid,privateJwk,seed}`; delivery uses `keys.<kid>` whose value is the private JWK directly. A common normalized entry is `{kid, privateJwk, alias?, seed?}`. `alias` and `seed` are optional metadata, not key identity. The records file's deliberately unbound `attacker` entry has `kid: null`; retain it by alias for negative signing tests and exclude it from key-URL lookup. The delivery file's top-level HMAC test secret is separate and is not a P-256 entry.

Equivalent JavaScript loaders (given the parsed files) are:

```js
const fromRecords = file => Object.entries(file.keys).map(([alias, key]) => ({
  kid: key.kid, privateJwk: key.privateJwk, alias, seed: key.seed,
}));
const fromDelivery = file => Object.entries(file.keys).map(([kid, privateJwk]) => ({
  kid, privateJwk,
}));
// Either normalized array supports the same lookup:
const byKid = entries => new Map(entries.filter(entry => entry.kid !== null)
  .map(entry => [entry.kid, entry.privateJwk]));
```

The files remain in their existing formats. Any future physical unification should preserve key material and signed fixture bytes, update both generators atomically, and document the tooling-format migration.

## Legacy strings

`v2/records/negative/legacy-typ.json` and `v2/records/negative/v1-envelope.json` carry the pre-v2 `typ` value and type namespace (`agent-network-event+jws`, `net.agentnetwork.*`). They are there so that a verifier proves it rejects them (records.md §11, https-binding.md §6).
