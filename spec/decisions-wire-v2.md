# DAREP Wire v2 decisions

DAREP means Durable Agreement, Receipt & Evidence Protocol. Spec home: https://darep.org.

Status: **Accepted** · DAREP Wire v2, frozen (spec v0.1) · Date: 2026-11-20, amended 2026-11-21 · Decided by: the spec editor (Kyle Hui) · Scope: Wire v2 freeze

This file records the editor decisions that the Wire v2 spec documents and both implementations build on.
Cite a decision by its ID (for example `D2`, `NC1`).
The key words MUST, MUST NOT, SHOULD and MAY are to be read as described in RFC 2119 and RFC 8174.

An accepted decision changes only through a new decision that names the one it supersedes.
Once Wire v2 is frozen, any change to a string inside signed bytes is a breaking change.

## Summary

| ID | Decision | Constrains |
|---|---|---|
| D1 | Protocol name "DAREP", spec domain `darep.org`; frozen `typ` values and extension-ID pattern | All signed bytes |
| D2 | `kid` = HTTPS URL of the identity document + `#fragment`; resolved from the pinned contact in A1 | Records, identity, verification |
| D3 | Own envelope, not strict CloudEvents; `darep: "2"` version slot | Envelope shape |
| D4 | Receipt = durably committed, kept ≥ 30 days from `storedAt`; says nothing about acceptance | Delivery contract, storage |
| D5 | Envelope `grant` slot = `{id, actor}`; signed delegation record reserved, not built | Envelope, evidence |
| D6 | Two-tier rejections: pre-store `problem+json`, post-store signed rejection record | Delivery contract, HTTPS binding |
| D7 | Apache-2.0 (code and spec), CC-BY-4.0 (explanatory documents), DCO sign-off | Repository, contributions |
| D8 | Python peer conforms to core + handoff/message; reschedule is Node-only | Conformance, vectors |
| NC1 | No canonicalization: verify exact bytes, never re-serialize | Signing, verification, receipts |

## D1 — Protocol name and spec domain

**Decision.**
The protocol name is **DAREP** (Durable Agreement, Receipt & Evidence Protocol) and the spec domain is **`darep.org`**.
The following strings are frozen for Wire v2:

- JWS `typ` values: `darep-event+jws`, `darep-receipt+jws`, `darep-rejection+jws` (the last one per D6).
- Extension IDs: `https://darep.org/ext/<name>/v<n>` (for example `https://darep.org/ext/work/v2#handoff`).
- Implementations MUST NOT mint new `net.agentnetwork.*` names (the pre-v2 namespace) inside signed bytes.

**Rationale.** After the freeze these strings are expensive to change, because they sit inside signed bytes.

**Constrains.** Every signed record, every extension ID, the vectors, and both implementations.

The name was settled after a name-conflict check on an earlier working name (amendment of 2026-11-21, below).

## D2 — `kid` is a URL

**Decision.**

- `kid` MUST be an absolute HTTPS URL of the signer's identity document plus a `#fragment` that names exactly one key, for example `https://example.com/.well-known/darep/alice#sig-2026-11`.
- In A1 the receiver MUST resolve `kid` against the **pinned** contact, never over the network. The pinned contact card becomes a snapshot of the identity document with a `keys[]` list. Network fetch of identity documents arrives in A2.
- The signer's address appears only in the payload `source`.
- The receiver MUST check that the identity document lists that `source` address, and that the selected key's purpose and validity window cover the record's `time`.

**Rationale.** A URL `kid` makes rotation and future resolution possible without changing the wire, while A1 stays offline-verifiable.

**Constrains.** The signed-records spec, the identity-document and key shape, contact pinning, and the verification order.

## D3 — Own envelope, not strict CloudEvents

**Decision.**

- Wire v2 does NOT claim strict CloudEvents conformance.
- The envelope keeps the existing CloudEvents-named attributes: `id`, `source`, `type`, `subject`, `time`.
- `specversion: "1.0"` is replaced by `darep: "2"` (the protocol version; see the D3 amendment below). `datacontenttype` is dropped.
- Top-level slots: `to[]`, `thread`, `inReplyTo`, `expires`, `ext` (a map keyed by extension URI), `required[]` (extension URIs the receiver must understand), `grant` (per D5).

**Rationale.** A recipients array and an extension map are not valid CloudEvents context attributes, which are scalars.

**Constrains.** The envelope schema, the vectors, and any documentation that claims CloudEvents compatibility.

## D4 — What a receipt promises

**Decision.**

- Issuing a receipt means the record is durably committed (fsync or committed transaction).
- The receiver MUST keep the record for at least 30 days after `storedAt`, and SHOULD keep it indefinitely as evidence.
- A receipt says nothing about acceptance, policy or work state.
- Both issued receipts and signed rejections (D6) MUST be retained.

**Rationale.** The sender needs a precise, testable meaning for "delivered" that is independent of what the receiver later does with the record.

**Constrains.** The delivery contract, the receiver's storage and retention, and the receive order verify → store → ack → apply.

**Amendment 2026-11-21 (to D4):** the retention period starts at the receipt’s `data.storedAt`, not at receipt issuance. The D4 text above reflects this clarification.

## D5 — Grants in the envelope

**Decision.**

- In A1 the envelope `grant` slot is `{ "id": <string>, "actor": "owner" | "agent" }`.
- The signing provider records the grant locally and closes grants and approvals with a timestamp rather than deleting them; the receiver stores the unverified `grant` reference as part of the record bytes.
- The slot shape is reserved for a future signed delegation record. That record MUST NOT be built in A1.

**Rationale.** Evidence needs to show who acted under which grant now, without freezing a delegation format that is not designed yet.

**Constrains.** The envelope and the evidence store.

## D6 — How rejections are carried

**Decision.** Rejections come in two tiers.

1. **Pre-store** (bad signature, unknown signer, wrong recipient, too large, expired, missing required extension): the receiver MUST NOT store or ack the record, and MUST answer with `application/problem+json` carrying a code from a fixed, spec-defined list.
2. **Post-store application refusal** (for example stale head, wrong turn): the record is stored and acked, then the applier MUST emit a **signed** rejection record (`typ` `darep-rejection+jws`) into the same thread.

**Rationale.** Transport-level failures need cheap, machine-readable codes. Application refusals need signed evidence the sender can keep.

**Constrains.** The delivery contract, the HTTPS binding, the rejection-code registry, and the vectors.

## D7 — License

**Decision.**
Code and the specification are licensed under Apache-2.0 (`LICENSE`, copyright 2026 Rev.Vision).
Explanatory documents are licensed under CC-BY-4.0 (`LICENSE-docs` lists which files).
Every contribution MUST carry a DCO sign-off (`git commit -s`), as described in `CONTRIBUTING.md`. There is no copyright assignment.

**Rationale.** A permissive license and a sign-off that does not need a contributor agreement. Apache-2.0 §3 grants a patent license from contributors for claims they can license that are necessarily infringed by their contributions alone or combined with the Work to which they were submitted, subject to its terms. It is not blanket patent clearance for implementing DAREP. No broader patent commitment is made.

**Constrains.** The repository, every `package.json` in this repository, and all contributions.

## D8 — Python conformance subset

**Decision.**
The Python peer MUST conform to the core (signed records, delivery, receipt, rejection) plus the handoff and message types.
Reschedule is an optional type and stays Node-only.

**Rationale.** That satisfies "both implementations pass the same vectors" for the core without porting every optional type.

**Constrains.** The conformance statement, the vector layout (core vectors are separate from optional-type vectors), and the Python peer's scope.

**Amendment 2026-11-21 (to D8):** `https://darep.org/ext/work/v2` handoff types and the reschedule types are experimental extensions, not part of frozen Wire v2 conformance. D8’s implementation scope above remains a reference-implementation target; core conformance requires neither extension. Normative publication of `work/v2` is future work.

## NC1 — No canonicalization

**Decision.**

- Wire v2 uses no canonicalization (no JCS or similar).
- A signature covers the exact payload bytes as transmitted. A receipt hashes the exact payload bytes.
- Verifiers MUST verify the received bytes and MUST NOT re-serialize a payload before verifying or hashing it.
- Senders store an outgoing record once and MUST resend the same bytes.
- How a sender serializes JSON before signing (for example sorted keys) is its own choice and is not part of the wire contract.

**Rationale.** Already true in both implementations. It removes a whole class of cross-language mismatches.

**Constrains.** Signing, verification, receipt hashing, retry and resend, and the negative vectors.

**Amendment 2026-11-21 (to D1):** the protocol is renamed DAREP (Durable Agreement, Receipt & Evidence Protocol) after a name-conflict check on the earlier working name. All `typ` strings become `darep-*` and all URIs move to `https://darep.org/`. D1 above states the result. Nothing else in D1 changes.

**Amendment 2026-11-21 (to D3):** the record envelope protocol-version member `ack` is renamed `darep`, with value `"2"`.

The identity-document version member is also renamed to `darep` (value `"2"`), the well-known path to `/.well-known/darep/<name>`, the inbox path to `/darep/v2/inbox`, and the recipient header to `Darep-Recipient`; behavior is unchanged.
