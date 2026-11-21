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

## Legacy strings

`v2/records/negative/legacy-typ.json` and `v2/records/negative/v1-envelope.json` carry the pre-v2 `typ` value and type namespace (`agent-network-event+jws`, `net.agentnetwork.*`). They are there so that a verifier proves it rejects them (records.md §11, https-binding.md §6).
