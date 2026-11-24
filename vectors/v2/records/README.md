# DAREP Wire v2 signed-record vectors

Run commands in this README from the repository root.

The `work/v2` handoff and `reschedule/v2` types are experimental extensions, not part of frozen Wire v2 conformance. Normative publication of `work/v2` is future work. Vectors and runners are verification aids, not a complete conformance determination.

Test vectors for [spec/records.md](../../../spec/records.md). Each vector is one signed record, the context to verify it in, and the expected verdict.

```bash
node vectors/v2/records/check.mjs      # verify every vector against the documented procedure
node vectors/v2/records/generate.mjs   # regenerate every file here (byte-for-byte deterministic)
```

Both scripts use only Node built-ins (Node ≥ 22.18, as in `package.json`).

## Test keys: TEST ONLY

`keys.json` contains **private** keys. They are published on purpose so anyone can regenerate and extend the vectors. They protect nothing, and an implementation MUST NOT accept them outside a test. Each key is derived from a fixed seed string (see `derivation` in the file), and every signature uses deterministic ECDSA ([RFC 6979](https://www.rfc-editor.org/rfc/rfc6979)), so rerunning `generate.mjs` reproduces every file exactly. The generator self-checks its RFC 6979 implementation against the RFC's own P-256 test vector and verifies every signature it writes with OpenSSL.

The file uses `keys.<alias>.{kid,privateJwk,seed}`. Normalize each entry to `{kid, privateJwk, alias?, seed?}`; see the [shared key access model and equivalent loaders](../../README.md#shared-key-access-model-25) for this schema and delivery's `keys.<kid>` schema. Neither is a wire schema, and neither physical format changes in v0.1.1.

The test identities live under the reserved `.test` TLD:

| Identity | Document | Keys |
|---|---|---|
| `acct:bob@vectors.test` | `https://bob.vectors.test/.well-known/darep/bob` | `#sig-2026-01` revoked, `#sig-2026-05` retired on 2026-11-15, `#sig-2026-11` current (`record`), `#provider-2026-11` (`provider`) |
| `acct:carol@vectors.test` | `https://carol.vectors.test/.well-known/darep/carol` | `#key-2026-11` (`record`, `provider`) |
| `acct:dave@vectors.test` | `https://dave.vectors.test/.well-known/darep/dave` | `#key-2026-11` (`record`, `provider`) |

An `attacker` key exists in `keys.json` with `kid: null` and is deliberately absent from every identity document. Keep it by alias for negative signing tests; exclude it from key-URL lookup.

## Files

| File | Contents |
|---|---|
| `identities.json` | The pinned identity-document snapshots. Every vector is verified against all of them. |
| `invalid-identities.json` | Negative identity-document cases that MUST fail pin validation (records.md §5.1, §5.3 P-0). |
| `index.json` | Every vector's name and expected verdict and code. |
| `positive/*.json`, `negative/*.json` | One vector each. |
| `selftest/` | Harness self-test fixtures, not conformance vectors (see below). Not listed in `index.json`. |
| `keys.json` | Test keys (see above). Verifiers do not need this file. |
| `generate.mjs` | Writes all of the above. |
| `check.mjs` | Reference verifier: records.md §8, one numbered step per check. It also validates `identities.json` as pins (P-0) and prints why each rejection fired. |

## Vector format

```jsonc
{
  "name": "negative/expired",
  "description": "…",
  "spec": "§7.2",                      // the rule under test
  "context": {
    "mode": "admission",               // or "evidence" (records.md §7.3): skips steps 12–14
    "now": "2026-11-20T12:00:00Z",     // the verifier's clock
    "receiver": "acct:carol@vectors.test",
    "typ": "darep-event+jws",       // the typ (or array of typs) the verifier expects in this context
    "understood": ["https://darep.org/ext/core/v2", "…"],
    "answered": "eyJ…"                 // receipts only: the JWS of the record being answered (§8 step 15)
  },
  "jws": "eyJ…",                       // the compact JWS: the only input that is signed
  "headerUtf8": "{\"alg\":\"ES256\",…}",
  "payloadUtf8": "{\n \"darep\": \"2\", …",  // null when the payload is not valid UTF-8; then payloadHex
  "payloadSha256": "…",                // SHA-256 of the exact payload bytes
  "expected": { "verdict": "reject", "code": "expired" }
  // positives: { "verdict": "accept", "kid": "…", "record": { …parsed payload… }, "numbers"?: "exact" | "binary64" }
  // positive/receipt also has "receiptFor": the vector whose payloadSha256 it must equal
}
```

`expected.numbers` says how runners compare the numbers in `expected.record` with the parsed record. Absent or `"exact"`, the values must be equal. `"binary64"` rounds the numbers on both sides to IEEE 754 binary64 first, for payloads whose number lexemes carry more precision than binary64 (a parser that keeps arbitrary-size integers, such as Python's, would otherwise differ from one that does not). The exact lexemes stay pinned by `payloadUtf8` and `payloadSha256` (NC1).

`headerUtf8`, `payloadUtf8` and `payloadSha256` exist for readers and cross-checks. A verifier under test should be given only `jws`, `context` and `identities.json`.

Work and reschedule payloads here illustrate signed envelopes; passing these records checks requires no implementation of their application semantics.

## Coverage

| Positive (accept) | Negative (reject → code) |
|---|---|
| `handoff` | `wrong-kid` → `unknown-key` |
| `reschedule` (no whitespace) | `kid-not-url` → `bad-header` |
| `receipt` (for `handoff`), `receipt-signing-before-stored-at` (verifier acceptance despite issuer inconsistency) | `kid-of-other-identity` → `signer-mismatch` |
| `rejection` (signed, post-store) | `alg-none`, `alg-hs256`, `alg-es384-label` → `unsupported-alg` |
| `rejection-extension-code` (code is an extension URI) | `rejection-missing-code`, `rejection-nonstring-code`, `rejection-empty-data` → `malformed` |
| `rejection-unknown-code` (valid unregistered bare code) | `ext-empty-fragment`, `required-empty-fragment`, `type-empty-fragment` → `malformed`; `kid-empty-fragment` → `bad-header` |
| `message-multi-recipient` | `legacy-typ`, `typ-context-mismatch`, `crit-header` → `bad-header` |
| `extra-header-member` | `embedded-jwk-ignored`, `tampered-payload` → `bad-signature` |
| `unknown-type-not-required` | `duplicate-header-member`, `duplicate-payload-member`, `bom`, `invalid-utf8` → `malformed` |
| `unknown-optional-extension`, `extension-query`, `extension-empty-query` | `v1-envelope` → `unsupported-version` |
| `rotated-key-within-validity` | `unknown-top-level-member`, `expiry-window-too-long` → `malformed` |
| `evidence-mode-expired` | `unknown-required-extension` → `unsupported-extension` |
| | `expired` → `expired`, `not-yet-valid` → `not-yet-valid` |
| | `retired-key-after-validity`, `revoked-key`, `wrong-key-purpose` → `key-not-valid` |
| | `wrong-recipient` → `wrong-recipient` |
| | `b64-header` → `bad-header`; `noncanonical-base64url`, `noncharacter` → `malformed` |
| | `receipt-predates-record`, `receipt-mismatch`, `receipt-mismatch-after-window` → `receipt-mismatch` |
| | `receipt-with-ext` → `malformed`; `receipt-after-delivery-window` → `expired` |
| | `kid-query`, `kid-empty-query`, `kid-broad-fragment` → `unknown-key` (K-1 syntax passes; no valid pin can resolve them) |
| | `kid-uppercase-host`, `kid-hyphen-host`, `kid-single-label-host`, `kid-default-port`, `kid-dot-segment`, `kid-hex-ipv4`, `kid-octal-ipv4`, `kid-userinfo` → `bad-header` |
| | `type-uppercase-host`, `type-trailing-hyphen-host`, `type-default-port`, `type-dot-segment`, `type-userinfo` → `malformed` |
| | Pin validation (`invalid-identities.json`): `id-with-query`, `id-with-empty-query`, `id-with-empty-fragment`, `id-uppercase-host`, `id-default-port`, plus missing/wrong-type fields, empty keys, invalid addresses, key IDs, purposes, instants, validity ordering and JWK coordinates → reject (P-0) |

## Harness self-test fixtures

`selftest/` holds fixtures that check the vector runners, not implementations: `numbers-binary64.json` (a records vector in the format above, with `expected.numbers: "binary64"`) and `pin-updates.json` (cases for the conformance kit's optional `checkUpdate` adapter operation: an old and a new snapshot of one identity document, and whether records.md §5.5 lets the update be a routine rotation, a SHOULD, or requires an owner decision, a MUST). They use only behaviour the frozen text already fixes. Each runner's own tests show a deliberately wrong implementation failing them: `check.mjs`, `reference/node/test/records-vectors.test.js`, `reference/python/test_peer.py` and the kit's `--selftest` mode.

Rejection codes are defined in the code registry, [delivery.md §5](../../../spec/delivery.md#5-rejections-and-the-code-registry). Delivery-contract vectors (deduplication, ordering, problem+json, sender behaviour) belong to `vectors/v2/delivery/`. `check.mjs` exports `verifyRecord`, which the delivery generator's `--check` runs over every record in those vectors.
