# DAREP Wire v2 delivery vectors

Run commands in this README from the repository root.

The `work/v2` handoff and `reschedule/v2` types are experimental extensions, not part of frozen Wire v2 conformance. Normative publication of `work/v2` is future work. Vectors and runners are verification aids, not a complete conformance determination.

Request/response scenarios for [Delivery contract](../../../spec/delivery.md) and [HTTPS binding](../../../spec/https-binding.md). Each file is one scenario with expected outcomes.

> **TEST ONLY.** [`test-keys.json`](test-keys.json) holds private keys that are published on purpose. They MUST NOT sign any real record, and their identity documents MUST NOT be pinned outside tests. Every address uses the reserved `.test` TLD.

## Files

| File | Content |
|---|---|
| `generate.mjs` | Generator. `node vectors/v2/delivery/generate.mjs` rewrites everything. `--check` verifies the committed files without writing anything: signatures, payload bytes and digests, and every record and receipt through the records reference verifier (`../records/check.mjs`), whose verdict must equal the vector's expected code. |
| `test-keys.json` | Private P-256 JWKs by key URL, plus the HMAC secret used for the `unsupported-alg` vector. Created once and reused. |
| `identities.json` | Public identity documents (records.md §5.1 shape), which addresses each test receiver pins, and each address's inbox URL as binding configuration (https-binding.md §1.1). |
| `receiver/*.json` | Vectors for a receiver under test: the runner POSTs and checks the response and the stored state. |
| `sender/*.json` | Vectors for a sender under test: the runner acts as the receiving endpoint and checks what the sender does next. |

## Scenarios

| Vector | What it shows |
|---|---|
| `receiver/first-delivery` | Baseline: verify, store, receipt, apply. |
| `receiver/duplicate-delivery` | The byte-identical stored receipt is returned for a resend, a resend after expiry, and a re-signed copy. No second store or apply. |
| `receiver/out-of-order` | A reply that arrives before its predecessor is stored, acked, held `pending`, then applied. **depends on the experimental work/v2 extension**. |
| `receiver/out-of-order-hold-deadline` | A pending record whose predecessor never arrives is refused with `missing-predecessor`. **depends on the experimental work/v2 extension**. |
| `receiver/out-of-order-pending-predecessor` | A reply whose predecessor is stored with outcome `pending` stays `pending` until the predecessor finishes, then the chain applies in causal order. |
| `receiver/out-of-order-refused-predecessor` | When a pending record's predecessor arrives and is refused (`invalid-data`), the waiting record is applied normally and judged by its own type logic (`stale-head` for a handoff). **depends on the experimental work/v2 extension**. |
| `receiver/stale-head` | A record that points at an old head is stored and acked, then refused with a signed rejection record. **depends on the experimental work/v2 extension**. |
| `receiver/unknown-type` | An unknown type without `required[]` is stored and acked; outcome `unsupported`. |
| `receiver/reject-<code>` | One vector for each pre-store code in the registry (delivery.md §5.1). `reject-malformed` and `reject-wrong-recipient` have several steps. |
| `sender/receipt-mismatch` | Eight kinds of bad receipt, each with the records.md §8 code it fails with. None counts as delivery, each is kept, and each retry sends the same bytes. |
| `sender/retry-same-bytes` | 503 with `Retry-After`, a dropped connection and a redirect, then success. Same bytes every time. |
| `sender/permanent-rejection` | A permanent code fails the delivery at once and SHOULD fail dependent records. |
| `sender/status-fallback` | Classification when there is no recognized code. |
| `sender/give-up-at-expiry` | Transient failures until `expires` plus the skew allowance, then `failed`. |

## Reading a vector

- `receiver` or `sender` gives the address under test, the key URLs it signs with (private halves in `test-keys.json`), the addresses it has pinned, and the extensions it implements.
- `priorState` lists records the party under test already holds.
- `records` holds every record used. For each record: `envelope` (decoded), `payloadUtf8` (the exact payload bytes), `payloadSha256`, and `recordBytes` (the compact JWS).
- Each step has `at`, the clock of the party under test. Runners should inject it. An implementation that cannot inject its clock checks `storedAt` for format only and skips the time-dependent steps.
- `request` is the HTTP request, including the `darep-recipient` header that names the delivery's recipient address (https-binding.md §2.1). `bodyEqualsRecord` means the body must equal that record's `recordBytes`, byte for byte. `bodyFill` describes a generated body.
- `respond` (sender vectors) is what the runner answers.
- `expect` is the required outcome. Receipts and rejection records are signed by the implementation under test, and ES256 signatures are randomized. So `expect` lists the fields that must match, not the bytes, except `receiptBytesEqualStep`, which requires the response body to equal the receipt from an earlier step byte for byte.
- `applyOutcome` is one of `applied`, `pending`, `refused` or `unsupported` (delivery.md §3.3). `stored: "unchanged"` means nothing new was stored. `applyCount` counts how often the applier ran for the record.
- `optional: true` on a rejection record means the implementation MAY emit it. If it does, it must match.
- `should` marks a SHOULD-level expectation. A runner reports it but does not fail on it.

## Shapes

Every record, receipt, rejection record and identity document here has the shape defined in [Signed records](../../../spec/records.md): events per §4.3 (`expires` and `grant` always present), receipts per §4.4, rejection records per §4.5 (signed with a `provider` key), identity documents per §5.1. Codes come from the registry in [delivery.md §5](../../../spec/delivery.md#5-rejections-and-the-code-registry). `--check` fails if any of them drifts from the records procedure.

Signatures use deterministic ES256 (RFC 6979) over the committed keys in `test-keys.json`, and payload bytes use fixed ids and times, so regeneration is byte-for-byte deterministic.

## Conformance subsets (D8)

The four scenarios marked above carry `conformance: "depends on the experimental work/v2 extension"` in their metadata. They test experimental handoff semantics and are not required for frozen Wire v2 conformance. Core conformance is achievable without them. All other scenarios use core messages or test core handling of unknown types/extensions. Both reference implementations support handoff and run every current vector, including the experimental scenarios, with no skips. Experimental reschedule scenarios, if added, must be marked separately.
