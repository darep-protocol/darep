# DAREP, Wire v2: Delivery contract

DAREP means Durable Agreement, Receipt & Evidence Protocol. Spec home: https://darep.org.

Status: **DAREP Wire v2, frozen (spec v0.1)** · Date: 2026-11-21 · Document 2 of 3

1. [Signed records](records.md): the envelope, `kid`, keys, `typ` and the identity document.
2. **Delivery contract** (this document): what a receiver promises when it acknowledges a record, and what a sender does until it gets that acknowledgement.
3. [HTTPS binding](https-binding.md): how the contract runs over HTTPS.

Decisions are cited by ID (D1–D8, NC1) from the [Wire v2 decision record](decisions-wire-v2.md).
Vectors for this document are in [`vectors/v2/delivery/`](../vectors/v2/delivery/).

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY and OPTIONAL are to be read as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

This document does not depend on HTTP. Status codes, paths, headers and media types are defined only in the HTTPS binding.

Ownership: [Signed records](records.md) owns the shape of every record, receipt and rejection, the identity document, and the verification procedure (records.md §8). This document owns what receipts and rejections mean and when they are issued, and it holds the **code registry** (§5): the one list of every rejection code. The other two documents link to it and define no codes of their own.

## 1. Scope

The delivery contract covers:

- the receive pipeline: verify, then store, then acknowledge, then apply (§3);
- the receipt and what it promises (§4, D4);
- the two rejection tiers and the code registry (§5, D6);
- deduplication and idempotency (§6);
- the sender's obligations: store once, resend the same bytes, retry, give up (§7, NC1);
- ordering (§8);
- evidence retention (§9, D4, D5).

It does not define the meaning of any record type. Work lifecycles, roles and admission are extensions over the slots that [Signed records](records.md) defines. The contract treats a record's `type` and `data` as opaque until the **apply** step.

## 2. Terms

**Record.** A signed JWS whose payload is a Wire v2 envelope, as defined in [Signed records](records.md) §4. A record that is delivered has `typ` `darep-event+jws` or `darep-rejection+jws` (D1). Both always carry `expires` (records.md §4.3, §4.5). A receipt (`darep-receipt+jws`) is never delivered (§4).

**Record bytes.** The exact compact JWS string as the sender first produced it. **Payload bytes** are the exact bytes of the JWS payload. Nothing in this document ever re-serializes a payload (NC1).

**Sender.** The provider that signs a record for one of its addresses and delivers it.

**Receiver.** The provider that hosts a recipient address and accepts deliveries for it.

**Recipient address.** One `acct:` address listed in the record's `to[]`. A **delivery** is the transfer of one record to one recipient address. A record with three recipients produces three deliveries, each with its own receipt and dedupe key, even when one receiver hosts several of the addresses. The binding names the recipient address of each delivery explicitly ([HTTPS binding](https-binding.md) §2.1). It is not taken from the identity document, which carries no transport information in A1 (records.md P-1).

**Store.** To commit durably, as defined in §4.1.

**Acknowledge (ack).** To return a signed receipt for a delivery (§4).

**Apply.** To run the type-specific logic for a stored record: workflow state, turn and head checks, owner policy, approvals, quotas on work, and any effect visible to an agent or owner.

**Dedupe key.** The triple (recipient address, `source`, `id`) (§6).

**Skew allowance (`skew`).** 300 seconds, as fixed in [Signed records](records.md) §7.2. This document uses that value and does not define its own.

**Expiry.** The record's `expires`. Senders SHOULD set it to `time` plus 7 days, and it is at most 30 days after `time` (records.md §7).

**Hold window.** 7 days, measured from `storedAt`. The longest a receiver holds a record as `pending` (§8.2).

## 3. Receive pipeline

A receiver MUST process every delivery in four steps, in this order:

1. **Verify.** Run the pre-store checks in §3.1. On any failure, the receiver MUST NOT store the record and MUST NOT issue a receipt. It answers with a pre-store rejection (§5.1).
2. **Store.** Commit the record durably (§4.1), together with the evidence in §9.1.
3. **Acknowledge.** Sign a receipt (§4), store it, and return it to the sender.
4. **Apply.** Hand the stored record to the type's applier (§3.3).

Workflow, turn, head and policy checks MUST NOT run before step 3 completes, and their outcome MUST NOT change whether a receipt is issued (D6). A record that the applier later refuses is still stored, still acknowledged and still kept as evidence. The refusal travels as a signed rejection record (§5.3).

A receiver MAY run step 4 in the same process turn as step 3 or later from a durable queue. If it crashes after step 2, it MUST complete steps 3 and 4 when it restarts. A stored record MUST NOT stay unapplied without an apply outcome (§3.3) being recorded eventually.

### 3.1 Pre-store checks

The receiver MUST evaluate the checks in the order below and report the code of the first one that fails. The order determines the first failure for the same verification context, subject to the explicitly permitted early `rate-limited` response and the C1/R12 choice for unhosted recipients below. Rows R1–R12 and R13–R14 are steps 1–14 of the verification procedure in [Signed records](records.md) §8, run in admission mode with the delivery's recipient address as the receiver and `darep-event+jws` and `darep-rejection+jws` as the expected `typ` values. Deduplication (D) runs between R12 and R13, so that a late retry of a record already stored still gets its receipt. All codes are defined in the registry (§5.1).

| # | Check | Failure code |
|---|---|---|
| C1 | The carrier request is well formed for the binding: method, media type, encoding, and exactly one recipient address named. | `method-not-allowed`, `unsupported-media-type`, `wrong-recipient` |
| C2 | The record bytes do not exceed the size limit (§3.4). | `too-large` |
| R1–R12 | records.md §8 steps 1–12: framing, header, `alg`, `typ`/`kid`, key resolution against the **pinned** identity documents only (D2), signature over the bytes as received (NC1), payload, version, envelope, `source` binding, key purpose and validity, and the recipient address of this delivery is in `to[]` and hosted by this receiver. Only the envelope is checked. `data` is not checked against any type schema. | `malformed`, `unsupported-alg`, `bad-header`, `unknown-key`, `bad-signature`, `unsupported-version`, `signer-mismatch`, `key-not-valid`, `wrong-recipient` |
| D | Deduplication (§6). A duplicate ends the pipeline here: the receiver returns the stored receipt and does nothing else. | `id-conflict` |
| R13 | records.md §8 step 13: `time ≤ now + skew` and `now < expires + skew`. | `not-yet-valid`, `expired` |
| R14 | records.md §8 step 14: every URI in `required[]` names an extension the receiver implements for this recipient address. | `unsupported-extension` |
| C3 | The receiver has capacity: sender quota, storage, and its own health. | `rate-limited`, `unavailable` |

A receiver MAY also refuse with `rate-limited` at any point before R1, to shed load from a source it cannot yet identify. It reports `unavailable` whenever the store step fails.

A missing or unparseable recipient address is a carrier error (C1). A single-tenant receiver SHOULD report an unhosted recipient address at R12, after the signature has been verified, so an unauthenticated request learns nothing about which addresses it hosts. A receiver that hosts no address named in the delivery (for example a multi-tenant provider that stores pins per hosted address and therefore has no pins to verify against) MAY return `wrong-recipient` at C1, before signature verification.

The only checks allowed before storage are the ones in this table. In particular, a receiver MUST NOT refuse a record before storage because of its `type`, its `data`, its thread state, its `inReplyTo`, the sender's turn, or an owner policy.

### 3.2 What is stored before the record is applied

Every record that passes §3.1 is stored and acknowledged, including:

- a record whose `type` the receiver does not implement, when that type is not covered by `required[]`;
- a record whose `inReplyTo` names a record the receiver has not stored yet (out of order, §8.2);
- a record whose `inReplyTo` names a record that is no longer the head of its thread (stale, §8.3);
- a record that the applier will refuse for any other reason.

### 3.3 Apply outcomes

The applier records exactly one final outcome per stored record and recipient address:

| Outcome | Meaning | Rejection record (§5.3) |
|---|---|---|
| `applied` | The type logic accepted the record and its effects are visible. | None |
| `pending` | Not final. The record waits for its predecessor (§8.2). | None yet |
| `refused` | The type logic or owner policy refused the record. | MUST be emitted |
| `unsupported` | The receiver does not implement `type`. The record stays stored and visible to the owner as a raw signed record. | MAY be emitted with code `unsupported-type` |

`pending` is the only outcome that may change later. It ends as `applied`, `refused` or `unsupported`.

An applier MUST NOT emit a rejection record in response to a rejection record. A rejection record whose `inReplyTo` names an outgoing record the receiver holds is applied by marking that outgoing record refused (§7.5). Any other rejection record is stored and applied as `applied` with no further effect.

### 3.4 Size limit

Record bytes MUST NOT exceed 65,536 octets (64 KiB). A receiver MUST accept every record up to that size, and MUST reject larger ones with `too-large` without reading more than the limit plus one octet. A future extension MAY allow larger records only when both parties declare support for it. A sender MUST NOT create a record larger than the limit. This is the only size limit in Wire v2. Signed records defines none of its own.

## 4. Receipts (D4)

A receipt is a record with `typ` `darep-receipt+jws` and `type` `https://darep.org/ext/core/v2#receipt`. Its exact shape is defined in [Signed records](records.md) §4.4. It is signed by the receiver with a key of the recipient address's identity document whose purpose is `provider` (records.md §5.2). Its `source` is the recipient address of the delivery. A receipt is never delivered as a record. It travels only as the answer to a delivery.

### 4.1 What "stored" means

A receiver MUST NOT issue a receipt until all of the following are true:

1. The record bytes and the evidence in §9.1 are committed to storage that survives a process crash and a host power loss. Examples are a committed SQLite transaction with `synchronous=FULL`, a committed transaction in a database that fsyncs its write-ahead log before acknowledging, or a file written and fsynced together with its directory entry.
2. The receipt itself is committed in the same transaction or in a later one, so that a duplicate delivery can return the same receipt bytes (§6).

Storage replicated to other machines counts as durable only if the commit waits for that replication.

`data.storedAt` is the receiver's clock at commit. The receipt's `time` is when it was signed, which is at or after `storedAt`. This is an issuer obligation; Wire v2 records §8 does not add a verifier rejection condition for `time < data.storedAt`. Applications may report that inconsistency without changing the protocol verification verdict.

### 4.2 Retention promise

By issuing a receipt, the receiver promises that it will keep the record bytes, the receipt and the dedupe key for at least 30 days after `storedAt` (D4). It SHOULD keep them indefinitely, as evidence (D4, §9). The promise is fixed by this document, so the receipt does not restate it.

The receiver MUST also keep the dedupe key until at least the record's `expires` plus `skew`, even when that is later than `storedAt` plus 30 days. Otherwise a late retry could be stored twice (records.md TM-2a).

### 4.3 What a receipt does not promise

A receipt says only that the record bytes were stored durably for the recipient address. It does not state or imply that the record was read, understood, accepted, applied, or permitted by policy, nor anything about work state (D4). A sender MUST NOT treat a receipt as acceptance. In the work extension, "delivered" is the receipt and nothing more.

### 4.4 Receipt contents

The receipt's members are fixed by records.md §4.4: `source` is the recipient address, `to` is `[<record's source>]`, `thread` and `inReplyTo` are the record's `thread` and `id`, `ext` is `{}`, `required` is `[]`, there is no `expires`, `grant` or `subject`, and `data` is exactly `{sha256, storedAt}`. `sha256` is the lowercase hex SHA-256 of the record's payload bytes as received (NC1).

No other members are allowed, because a receipt is evidence and its meaning must not drift. A sender treats a receipt with extra members as a receipt mismatch (§7.4).

The receipt hashes the payload bytes, not the whole JWS. A sender that wrongly re-signs the same payload therefore still matches its receipt. §7.1 still forbids re-signing.

## 5. Rejections and the code registry

There are two rejection tiers (D6). They never overlap: a delivery either fails before storage and gets a pre-store rejection, or it is stored and acknowledged and can later get a signed rejection record. It never gets both.

This section is the **code registry** for Wire v2. Every code a receiver or sender produces is listed here exactly once. [Signed records](records.md) §8 and the [HTTPS binding](https-binding.md) §3 refer to these codes and define none of their own. A new bare code needs a new decision and an entry here. Extensions define their own post-store codes as URIs (§5.3).

A **permanent** code means resending the same bytes cannot succeed. A **transient** code means a later attempt with the same bytes can succeed.

### 5.1 Pre-store codes

A pre-store rejection is not signed and is not stored by the receiver as a record. The receiver SHOULD keep a log of pre-store rejections for operations and abuse handling, but this document does not require it.

The rejection carries exactly one code from the table below. The binding defines how it is carried. In HTTPS it is an `application/problem+json` body ([HTTPS binding](https-binding.md) §2.3). Receivers MUST NOT use any other pre-store code in Wire v2.

| Code | Raised at (§3.1) | Class | Meaning |
|---|---|---|---|
| `method-not-allowed` | C1 | permanent | The carrier request does not use the delivery operation. |
| `unsupported-media-type` | C1 | permanent | The request is not declared as a compact JWS, or it uses a content encoding the receiver does not accept. |
| `too-large` | C2 | permanent | Record bytes exceed §3.4. |
| `malformed` | R1, R2, R7, R9 | permanent | Not a well-formed Wire v2 record: framing, base64url, encoding, JSON, or envelope schema (records.md §2, §3, §4). |
| `unsupported-alg` | R3 | permanent | `alg` is not on the allow-list (records.md §3.1). |
| `bad-header` | R4 | permanent | A `typ` the receiver does not expect, `crit` or `b64` present, or a `kid` that is not a valid key URL (records.md §3.2, §3.3). |
| `unknown-key` | R5 | permanent | `kid` does not name a key in any pinned identity document. |
| `bad-signature` | R6 | permanent | The signature does not verify over the bytes received. |
| `unsupported-version` | R8 | permanent | `darep` is missing or is not `"2"`. |
| `signer-mismatch` | R10 | permanent | The identity document that holds `kid` does not list `source`. |
| `key-not-valid` | R11 | permanent | The key lacks the purpose for this `typ`, is revoked, or its validity window does not cover `time`. |
| `wrong-recipient` | C1, R12 | permanent | No single valid recipient address was named (C1), the named recipient address is not hosted by the receiver (C1 or R12), or it is not in `to[]` (R12). |
| `id-conflict` | D | permanent | The dedupe key is already stored with different payload bytes. |
| `not-yet-valid` | R13 | transient | `time` is later than the receiver's clock plus `skew`. |
| `expired` | R13 | permanent | `expires` plus `skew` has passed. |
| `unsupported-extension` | R14 | permanent | A URI in `required[]` is not implemented for the recipient address. |
| `rate-limited` | C3 | transient | Quota exceeded. The binding can carry a retry delay. |
| `unavailable` | C3 | transient | The receiver cannot store right now, for example because storage is full or a lock timed out. |

A sender that receives a code it does not recognize MUST treat it by the binding's fallback rule ([HTTPS binding](https-binding.md) §3).

### 5.2 Sender-side results

These codes are produced by a sender while it checks an answer. They never travel in a problem response.

| Code | Meaning |
|---|---|
| `receipt-mismatch` | A receipt or rejection record does not answer the record it claims to (records.md RC-1, §8 step 15), or a receipt's `source` is not the recipient address of this delivery (§7.4). |
| `expired` | A receipt arrived after the delivery of its record had closed (records.md TM-4a). Same code as above, raised by the sender. |

A receipt that fails any other step of records.md §8 is also a receipt mismatch for §7.2. The sender records the step's code from §5.1 with it.

### 5.3 Post-store rejection records

When the applier gives a stored record the outcome `refused`, the receiver MUST emit a rejection record. When the outcome is `unsupported` it MAY emit one. Either choice is conformant: emitting one lets the sender stop waiting, and not emitting one leaves room for a receiver that adds the type later.

A rejection record is a record with `typ` `darep-rejection+jws` and `type` `https://darep.org/ext/core/v2#rejection`, whose exact shape is defined in [Signed records](records.md) §4.5:

- it is signed by a key of the recipient address that refused, with purpose `provider` (records.md §5.2), because the applier is the provider;
- `source` is that recipient address, `to` is `[` the refused record's `source` `]`, `thread` is the refused record's `thread`, and `inReplyTo` is the refused record's `id`;
- it carries `expires`, like every delivered record, and no `grant`;
- `data` is `{code, detail?}`: one code from the table below or an extension code (§5.3.1), and an optional human-readable `detail` of 1–1,000 characters.

A receiver MUST emit at most one rejection record per stored record and recipient address. It MUST store the rejection record before sending it and deliver it under §7 like any other outgoing record. A rejection is final: a later software upgrade does not retract it.

Post-store codes:

| Code | Meaning |
|---|---|
| `stale-head` | `inReplyTo` names a stored record that is no longer the head of its thread (§8.3). |
| `wrong-turn` | The type's lifecycle says it is not the source's turn, or the thread is closed. |
| `invalid-transition` | The type's lifecycle does not allow this action from the current state. |
| `invalid-data` | `type` is implemented but `data` does not validate against its schema (records.md T-2). |
| `missing-predecessor` | `inReplyTo` named a record that did not arrive before the hold deadline (§8.2). |
| `expired-before-apply` | The record's `expires` passed while it was `pending`. |
| `policy-denied` | Owner policy, an approval rule or a work quota refused it. `detail` MUST NOT reveal private policy. |
| `unsupported-type` | The receiver does not implement `type` (outcome `unsupported`). |

#### 5.3.1 Extension codes

Extensions MAY define further post-store codes as an extension URI plus `#` plus a name, under their own extension ID, for example `https://darep.org/ext/work/v2#terms-mismatch` (records.md §4.5, U-2). Bare codes are reserved for the tables in this section.

## 6. Deduplication and idempotency

The dedupe key is (recipient address, `source`, `id`). Senders MUST generate `id` as a UUID v4 that is unique per `source` ([Signed records](records.md) §4.2).

When a delivery passes checks C1–R12 (§3.1) and the receiver already holds a record for the same dedupe key:

- If the SHA-256 of the new payload bytes equals the stored digest, the delivery is a **duplicate**. The receiver MUST return the receipt it stored for the first delivery, byte for byte. It MUST NOT store a second copy, sign or store a new receipt, or apply the record again. This holds even if the record is now past its `expires` (R13 is skipped) and even if the JWS signature bytes differ, because only the payload is compared. Returning stored bytes means replays cost the receiver no signatures and no storage. The stored receipt still passes the sender's checks while the delivery is still open (before `expires` + `skew`), because those checks bound a receipt's `time` by the record's own `time` and `expires`, not by requiring a fresh receipt timestamp (records.md TM-4a).
- If the digests differ, the receiver MUST reject the delivery with `id-conflict` and MUST NOT change anything it has stored.

Because the stored receipt is returned unchanged, a sender that lost the response to a successful delivery recovers by resending. The result is the same as if the first response had arrived.

The same `id` from a different `source`, or for a different recipient address on the same receiver, is a different dedupe key and is not a duplicate.

## 7. Sender obligations

### 7.1 Store once, resend the same bytes (NC1)

A sender MUST, in one durable commit and before the first delivery attempt:

1. serialize the envelope to payload bytes once;
2. sign it once, producing the record bytes;
3. store the record bytes and one outbox entry per recipient address in `to[]`.

Every attempt, for every recipient, MUST send those stored record bytes unchanged. A sender MUST NOT re-serialize or re-sign a record for a retry, a redelivery requested by an operator, or a key rotation. After rotation, the old signature stays verifiable ([Signed records](records.md) §5.4), so there is no need to re-sign.

### 7.2 Attempts and backoff

A sender attempts a delivery, then classifies the result:

| Result | Action |
|---|---|
| A receipt that passes §7.4 | Mark the delivery `delivered`. Store the receipt bytes. Stop. |
| A pre-store rejection with a permanent code | Mark the delivery `failed`. Store the rejection. Stop (§7.3). |
| A pre-store rejection with a transient code | Schedule a retry. |
| No answer, a timeout, a broken connection, or a carrier error the binding marks transient | Schedule a retry. The record may already be stored. The retry is safe because of §6. |
| A receipt that fails §7.4 | Store it as evidence, record the attempt as `receipt-mismatch`, and schedule a retry. |

Retries MUST use exponential backoff. The first retry backoff delay MUST be at least 1 second. Each later backoff delay SHOULD double, MUST NOT be shorter than the previous backoff delay, and SHOULD be capped at 30 minutes. Senders SHOULD add random jitter of up to 20 percent. If a rejection carries a retry delay, for example the binding's `Retry-After`, the sender MUST NOT retry before it; that wait is honoured as a floor for that one attempt only and does not count as a step in the backoff sequence, so the non-decreasing rule applies to the backoff delays only.

### 7.3 When to give up

A sender MUST stop attempting a delivery and mark it `failed` at the first of:

- a permanent pre-store rejection;
- the record's `expires` plus `skew`, without a valid receipt. After that point the delivery is closed and the sender MUST NOT accept a receipt for it (records.md TM-4a).

A sender MAY also stop earlier on operator request. When a delivery fails, the sender SHOULD also mark as failed, without sending them, the later queued records of the same thread to the same recipient address whose `inReplyTo` chain depends on it. Otherwise the receiver would only hold them until they are refused with `missing-predecessor`. This stays a SHOULD: a sender that sends them anyway is still safe, because the receiver refuses them with signed evidence.

An operator MAY request redelivery of a failed delivery. Redelivery sends the same record bytes (§7.1), only before `expires`, and MUST keep the history of the earlier attempts.

### 7.4 Receipt verification

A sender MUST accept a receipt only if both of the following hold. Otherwise it is a **receipt mismatch**.

1. The receipt passes the verification procedure of [Signed records](records.md) §8 in admission mode, with the sender's own address as the receiver, `darep-receipt+jws` as the expected `typ`, the sender's pinned identity documents, and the delivered record as the answered record `R`. That covers the signature, the `provider` key purpose and validity at the receipt's `time`, the exact receipt shape (§4.4), and step 15: correlation with `R`, including the digest of `R`'s stored payload bytes, `time ≥ R.time − skew`, and `now < R.expires + skew`.
2. The receipt's `source` equals the recipient address of this delivery, not just any address in `R.to[]`. Without this rule, a receipt for one address could stand in for another address hosted by the same provider.

A mismatched receipt is never proof of delivery. The sender MUST keep it as evidence (§9.2), because a validly signed receipt with wrong contents is itself a fact about the receiver.

### 7.5 Receiving a rejection record

When a sender receives a rejection record (as a receiver, through §3) whose `inReplyTo` names one of its outgoing records, it first checks it against that record with records.md RC-1 (§8 step 15). A rejection record that fails RC-1 is kept as evidence and has no further effect. Otherwise the sender applies it by recording the refusal against that record and the rejection's `source` as recipient address. The delivery stays `delivered`, because the receipt is still valid. The refusal is a separate fact. The sender MUST NOT resend the refused record.

## 8. Ordering

### 8.1 No ordering guarantee on the carrier

The contract does not guarantee that deliveries arrive in the order they were created. Receivers MUST accept and store records in any order (§3.2).

A sender SHOULD deliver the records of one thread to one recipient address in creation order, and SHOULD NOT begin the first attempt of a record until the earlier records of that thread to that recipient address have a receipt or have failed. A sender MAY deliver different threads and different recipients in parallel.

### 8.2 Out-of-order records

Rejection records are exempt from the causal waiting and hold-deadline rules below; apply them immediately under §3.3, even when unmatched.

Except for rejection records, a record whose `inReplyTo` names a record the provider does not yet hold (neither as a received record for that recipient address nor as one of its own outgoing records), or holds with outcome `pending`, MUST be stored, acknowledged, and given the outcome `pending`. A `pending` record stays `pending` until its predecessor reaches a final outcome (`applied`, `refused` or `unsupported`) or its own hold deadline passes.

When the named predecessor reaches a final outcome, the receiver MUST apply the waiting records whose `inReplyTo` names it, in their storage order. If the predecessor was `refused`, each waiting record is applied normally and judged by its own type logic (for example, in the handoff lifecycle its `inReplyTo` is not the thread head, which yields `stale-head`).

The **hold deadline** of a pending record is the earlier of its `expires` and `storedAt` plus the hold window. At the hold deadline, the receiver MUST refuse a record that is still pending, with `missing-predecessor`, or with `expired-before-apply` if its `expires` was the earlier of the two.

### 8.3 Stale records

A type's applier decides what the head of a thread is. For types with a single linear head, such as the handoff lifecycle, a record whose `inReplyTo` names a stored record that is not the current head is refused with `stale-head`. It stays stored and acknowledged. The sender learns about the refusal from the signed rejection record and can read the thread again and send a new record.

### 8.4 Apply order

Rejection records are exempt from causal waiting: they are applied immediately under §3.3, including when the answered record is absent or pending. All other records are applied in causal order: a record MUST NOT be applied while the record its `inReplyTo` names is absent or `pending`; it is applied only after that predecessor reaches a final outcome (`applied`, `refused` or `unsupported`). Records that are not causally related are applied in the receiver's storage order. Two receivers can therefore apply concurrent records of a thread in different orders. Extensions resolve this through their own head and turn rules, which produce stale-head refusals rather than silent divergence.

## 9. Evidence retention (D4, D5)

Evidence is kept from the first record. Retention in this section applies at least for the periods in §4.2, and SHOULD be indefinite.

### 9.1 Receiver

For each stored delivery, the receiver MUST keep:

- the record bytes exactly as received, not only the decoded payload;
- the payload digest, `storedAt`, and the recipient address;
- the receipt bytes it issued;
- the apply outcome and the time it was reached;
- any rejection record it emitted, as record bytes, together with that record's own delivery history.

### 9.2 Sender

For each outgoing record, the sender MUST keep:

- the record bytes (§7.1);
- per recipient address: every attempt with its time and result class, every pre-store rejection received, every receipt received including mismatched ones, and the final state;
- any rejection record received about it (§7.5).

### 9.3 Grants and actors (D5)

When a provider signs an event on behalf of one of its addresses, it MUST record locally which grant authorized it and whether the owner or an agent acted. It also writes these into the envelope `grant` slot as `{ "id": <string>, "actor": "owner" | "agent" }` ([Signed records](records.md) §4.3). A signed delegation record is reserved and MUST NOT be built in A1 (D5).

A receiver stores the `grant` slot as part of the record bytes. It cannot verify the sender's grant in A1 and MUST NOT present it to its owner as verified.

### 9.4 Grants and approvals are closed, never deleted (D5)

A provider MUST NOT delete a grant, an approval or a sharing rule. To end one, it records a `closedAt` timestamp and a reason. Reasons include `revoked`, `expired`, `used`, `withdrawn` and `thread-closed`. A closed grant or approval MUST NOT authorize anything after `closedAt`, and MUST be kept at least as long as any stored record that references it.

## 10. Conformance

Conformance means meeting all applicable normative requirements for the receiver or sender role. The vectors in [`vectors/v2/delivery/`](../vectors/v2/delivery/) and their runners are verification aids, not a complete conformance determination. Under the D8 amendment, vectors that depend on experimental `work/v2` or reschedule semantics are outside frozen Wire v2 conformance; core conformance is achievable without them. Both reference implementations run every vector that applies to them, including their supported experimental types.

The delivery vectors and the [records vectors](../vectors/v2/records/) share one verification procedure. `node vectors/v2/delivery/generate.mjs --check` runs every record and receipt in the delivery vectors through the records reference verifier (`vectors/v2/records/check.mjs`) and fails if a pre-store vector's expected code differs from the code that procedure returns.

## 11. Deferred items

One item remains deferred.

| # | Item | Spec editor | Milestone | State |
|---|---|---|---|---|
| 1 | **Erasure.** D4 sets retention for at least 30 days from `storedAt` as MUST and indefinite as SHOULD. No decision covers an owner who asks for evidence to be erased, for example under data-protection law. The intended direction is an erased closed state that keeps the digest (`erasedAt`, payload removed, `sha256` and receipt kept), so that evidence of the fact survives without its content. | Kyle Hui | A3 | Deferred |

## Errata 2026-11-21

- **§8.2 / §8.4 and §9.3.** Made the §3.3 rejection-record exemption from causal waiting explicit, and scoped grant recording to events. Clarified the D4 retention start as `storedAt` in the decision record.
- **§10 conformance.** Distinguished all applicable normative requirements from vector coverage and separated experimental work scenarios under the D8 amendment.

- **§3.1, §5.1 unhosted recipient on a multi-tenant provider.** Permitted a receiver that hosts no address named in the delivery (for example a multi-tenant provider with per-address pins) to return `wrong-recipient` at C1, before signature verification. Adjusted `receiver/reject-wrong-recipient`.
- **§6 duplicate receipt check.** Qualified that a duplicate's stored receipt still passes the sender's checks while the delivery is still open (before `expires` + `skew`).
- **§7.2 `Retry-After` vs backoff.** Clarified that a `Retry-After` wait is honoured as a floor for that one attempt only and does not count as a step in the backoff sequence; the non-decreasing rule applies to backoff delays only. Fixed `sender/receipt-mismatch` retry spacing to match doubling and adjusted `sender/retry-same-bytes`.
- **§8.2, §8.4 predecessor states.** Specified normatively that a record whose predecessor is `pending` stays `pending` until the predecessor reaches a final outcome (`applied`, `refused` or `unsupported`), and that when a predecessor is `refused`, waiting records are applied normally and judged by their own type logic (yielding `stale-head` for a handoff). Added `receiver/out-of-order-pending-predecessor` and `receiver/out-of-order-refused-predecessor`.
- **Protocol rename.** Renamed the protocol to DAREP, with `darep-*` `typ` strings and `https://darep.org/` URIs, per the D1 amendment dated 2026-11-21; behavior is unchanged.
- **Envelope version member.** Renamed the record envelope protocol-version member `ack` to `darep`, retaining the value `"2"`, per the D3 amendment dated 2026-11-21.
- **Remaining protocol identifiers.** Renamed the identity-document version member to `darep` (value `"2"`), the well-known path to `/.well-known/darep/<name>`, the inbox path to `/darep/v2/inbox`, and the recipient header to `Darep-Recipient`, per the amendment dated 2026-11-21; behavior is unchanged.

## Errata 2026-11-21 (v0.1.1)

- #20: Clarified that receipt signing at or after `storedAt` is an issuer obligation, not an additional verifier check (§4.1).
- #24: Qualified the deterministic failure-order explanation by the existing early-response exceptions (§3.1).
