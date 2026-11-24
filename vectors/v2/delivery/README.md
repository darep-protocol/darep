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
| `selftest/receiver/*.json`, `selftest/sender/*.json` | Harness self-test fixtures, not conformance vectors: they check the runners' own capabilities (below). Runners load them only from their self-tests. |

### Test-key access (#25)

`test-keys.json` uses `keys.<kid>` with the private JWK directly as the value. Normalize entries to `{kid, privateJwk}`. Records instead use `keys.<alias>.{kid,privateJwk,seed}`; their alias and seed are optional metadata in the common `{kid, privateJwk, alias?, seed?}` view. See the [equivalent loaders](../../README.md#shared-key-access-model-25). These tooling schemas and their key material are unchanged. Dave's existing test key is now listed with both `record` and `provider` purposes in `identities.json` for the multi-recipient scenario.

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
| `sender/receipt-other-recipient` | Dave's correctly signed receipt for a record addressed to Carol and Dave passes records §8, but fails delivery to Carol under §7.4 rule 2; retain it and retry unchanged bytes. |
| `sender/retry-same-bytes` | 503 with `Retry-After`, a dropped connection and a redirect, then success. Same bytes every time. |
| `sender/permanent-rejection` | A permanent code fails the delivery at once and SHOULD fail dependent records. |
| `sender/status-fallback` | Status fallback plus recognized-code precedence over deliberately conflicting statuses (500/`malformed`, 400/`unavailable`); the conflicts test sender robustness, not conforming receiver output. |
| `sender/give-up-at-expiry` | Transient failures until `expires` plus the skew allowance, then `failed`. |

## Reading a vector

- `receiver` or `sender` gives the address under test, the key URLs it signs with (private halves in `test-keys.json`), the addresses it has pinned, and the extensions it implements.
- `priorState` lists records the party under test already holds.
- `records` holds every record used. For each record: `envelope` (decoded), `payloadUtf8` (the exact payload bytes), `payloadSha256`, and `recordBytes` (the compact JWS).
- Each step has `at`, the clock of the party under test. Runners should inject it. An implementation that cannot inject its clock checks `storedAt` for format only and skips the time-dependent steps.
- `request` is the HTTP request, including the `darep-recipient` header that names the delivery's recipient address (https-binding.md §2.1). The body is `body` (text, sent as UTF-8), `bodyBase64` (any octets, sent exactly), or `bodyFill` (a generated body). `bodyEqualsRecord` (sender vectors) means the body must equal that record's `recordBytes`, byte for byte.
- `respond` (sender vectors) is what the runner answers: `status`, `headers` and `body`; `connection` for a dropped connection; or `raw`, the exact response octets (below).
- Record ids are unique per source only (delivery.md §6), so runners address stored records by `(source, id)`. Where a vector names a record by id (`afterApply[].record`, `finalState.applyOrder`, `finalState.stored`), the id must belong to one source among the vector's records, or the entry must name the source: `afterApply` items take a `source` member, and `applyOrder` and `stored` entries may be `{ "source", "id" }` objects instead of ids.
- `expect` is the required outcome. Receipts and rejection records are signed by the implementation under test, and ES256 signatures are randomized. So `expect` lists the fields that must match, not the bytes, except `receiptBytesEqualStep`, which requires the response body to equal the receipt from an earlier step byte for byte.
- `applyOutcome` is one of `applied`, `pending`, `refused` or `unsupported` (delivery.md §3.3). `stored: "unchanged"` means nothing new was stored. `applyCount` counts how often the applier ran for the record.
- `optional: true` on a rejection record means the implementation MAY emit it. If it does, it must match.
- `should` marks a SHOULD-level expectation. A runner reports it but does not fail on it.

### Raw responses

`respond.raw` gives a sender vector full control of the response framing: status line, headers, transfer coding, truncation and size.

```jsonc
"respond": { "raw": {
  "segments": [ { "text": "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" },  // text: sent as UTF-8
                { "base64": "…" },                                                        // any octets
                { "fill": { "octet": "a", "length": 70000 } } ],                          // generated octets
  "end": "close",                // after the last segment: "close" (orderly) or "reset" (TCP reset)
  "decodedBody": "eyJ…"          // optional: the body a correct HTTP client sees, for receiptStored and evidence checks
} }
```

Runners serve it from a loopback TCP responder that reads the sender's request and writes the segments exactly, and the sender's own HTTP client reads it (Node: the real `fetch()`; Python: `peer.post()`; the kit: the adapter's sender).

### Harness self-test fixtures

`selftest/` exercises the runner capabilities above with behaviour the frozen text already fixes: `receiver/same-id-two-sources` (two records with one id from two sources have different outcomes), `receiver/binary-body` (`bodyBase64`, including octets that are not UTF-8), and `sender/raw-framing` (a reset in the middle of a response head, and a chunked receipt). Each runner's tests show a deliberately wrong implementation failing them: an outcome written by id alone, a receiver that drops undecodable octets, an HTTP client that keeps the chunk framing (`reference/node/test/delivery-vectors.test.js`, `reference/python/test_peer.py`, and `npm test --workspace conformance` for the kit).

### Retry assertions and test profile (#21)

In `sender/receipt-mismatch`, `expect.backoff.minimumSeconds` asserts the existing one-second initial minimum; `nonDecreasing` compares each underlying backoff delay with the previous one. `nextAttemptNotBefore` is a mandatory schedule floor, not evidence of doubling. The scheduled retry also cannot precede the computed backoff. A harness should observe the implementation's backoff state separately from a `Retry-After` floor and jitter; elapsed time between scripted attempts does not establish the computed delay.

`retryProfile` declares a one-second initial delay, doubling, and zero jitter. The reference runners suppress jitter only for this profile. `expect.should` reports recommended backoff delays of 1, 2, 4, 8, 16, 32, 64 and 128 seconds and the corresponding computed next-attempt times. A deviation is reported, not failed: a two-second first retry or another permitted policy does not fail conformance merely for missing this profile. With jitter enabled, inspect the underlying backoff or control the random source; do not demand exact wall-clock equality with the zero-jitter expectations. Scripted attempt times are stimuli, not a universal retry schedule.

`expect.recordsVerdict` asserts the records §8 verdict independently of the sender's attempt result. In `sender/receipt-other-recipient`, it is `accept` even though delivery to Carol is a `receipt-mismatch`; `verifyCode` records that sender-side failure code.

## Shapes

Every record, receipt, rejection record and identity document here has the shape defined in [Signed records](../../../spec/records.md): events per §4.3 (`expires` and `grant` always present), receipts per §4.4, rejection records per §4.5 (signed with a `provider` key), identity documents per §5.1. Codes come from the registry in [delivery.md §5](../../../spec/delivery.md#5-rejections-and-the-code-registry). `--check` fails if any of them drifts from the records procedure.

Signatures use deterministic ES256 (RFC 6979) over the committed keys in `test-keys.json`, and payload bytes use fixed ids and times, so regeneration is byte-for-byte deterministic.

## Conformance subsets (D8)

The four scenarios marked above carry `conformance: "depends on the experimental work/v2 extension"` in their metadata. They test experimental handoff semantics and are not required for frozen Wire v2 conformance. Core conformance is achievable without them. All other scenarios use core messages or test core handling of unknown types/extensions. Both reference implementations support handoff and run every current vector, including the experimental scenarios, with no skips. Experimental reschedule scenarios, if added, must be marked separately.
