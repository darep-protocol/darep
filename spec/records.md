# DAREP · Signed records

DAREP means Durable Agreement, Receipt & Evidence Protocol. Spec home: https://darep.org.

Status: **DAREP Wire v2, frozen (spec v0.1)** · 2026-11-21 · Document 1 of 3

This document defines what a DAREP record is, how it is signed, and how anyone holding the signer's identity document decides whether a record is valid.
It says nothing about how records travel. The [delivery contract](delivery.md) defines verify → store → ack → apply, retries, deduplication, rejection handling and the **code registry** (every rejection code, with its class and meaning). The [HTTPS binding](https-binding.md) defines the one carrier.

Ownership between the three documents: this document owns the shape of every signed record (events, receipts, rejections), the identity document, and the verification procedure (§8). The delivery contract owns what receipts and rejections mean, when they are issued, and the code registry. The HTTPS binding owns status codes and the `application/problem+json` mapping.

Decisions are cited by ID from the [Wire v2 decision record](decisions-wire-v2.md) (D1–D8, NC1).
Test vectors live in [`vectors/v2/records/`](../vectors/v2/records/README.md). Where this text and the vectors disagree, that is a defect to resolve through the errata/change process in [GOVERNANCE.md](../GOVERNANCE.md). Neither silently wins.

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY and OPTIONAL are to be read as described in BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they appear in all capitals.

## Contents

1. [Principals, trust anchor and permission verbs](#1-principals-trust-anchor-and-permission-verbs)
2. [Bytes and JSON](#2-bytes-and-json)
3. [JWS protected header](#3-jws-protected-header)
4. [Record envelope](#4-record-envelope)
5. [Identity document and keys](#5-identity-document-and-keys)
6. [Types and extensions](#6-types-and-extensions)
7. [Time, expiry and clock skew](#7-time-expiry-and-clock-skew)
8. [Verification procedure and codes](#8-verification-procedure-and-codes)
9. [Reserved slots, not built](#9-reserved-slots-not-built)
10. [Security considerations](#10-security-considerations)
11. [Conformance and test vectors](#11-conformance-and-test-vectors)
12. [Deferred items](#12-deferred-items)
- [Appendix A. Changes from Wire v1](#appendix-a-changes-from-wire-v1)
- [Appendix B. Gaps this document closes](#appendix-b-gaps-this-document-closes)

## 1. Principals, trust anchor and permission verbs

### 1.1 Principals

- An **identity** is an address of the form `acct:name@domain`, for example `acct:bob@vectors.test`. An address is the stable name a record is sent from and to.
- The **owner** of an identity is the person or organization that controls it. The owner decides which keys speak for the identity and which agents may act for it.
- A **provider** holds an identity's keys and records, signs on its behalf, and receives records addressed to it. One provider may serve many identities.
- An **agent** is software that acts for the owner through the provider under a **grant**. An agent never holds the identity's signing keys.

### 1.2 The trust-anchor rule

A verifier needs to know which keys speak for an address. The trust anchor is the single authority it accepts for that answer.

- **TA-1.** A verifier MUST take the keys for an identity only from that identity's trust anchor.
- **TA-2.** In A1 the trust anchor is the **receiving owner's pin**: a snapshot of the sender's identity document (§5) that the owner accepted out of band, for example by comparing it in person or over a channel they already trust (D2). There is no trust on first use. A record from an identity with no pinned document is rejected (`unknown-key`).
- **TA-3.** Nothing received in-band can add, replace or re-enable a key. That covers a record, a JWS header member (`jwk`, `jku`, `x5c`, `x5u` and the rest, §3.3), a payload field, and any network response. In A1 a verifier MUST NOT fetch identity documents over the network (D2).
- **TA-4.** The binding between address and keys is checked in both directions. The key named by `kid` belongs to a pinned document, that document lists the record's `source` (§8 step 10), and an address MUST NOT appear in more than one pinned document at once. A verifier MUST refuse to pin a document whose address already belongs to another pinned document until the owner removes the old pin.
- **TA-5.** Changing the pin is an owner decision (§5.5). From A2, an identity will declare its own anchor (a `root`-purpose key, §5.2) that signs later versions of its document. Even then, the only way to change the anchor itself will be through the anchor or a fresh owner decision.

The trust anchor answers *who signed this*. It does not answer *what that signer is allowed to do*. That is the job of grants (§1.3) and of the receiver's own policy.

### 1.3 Permission verbs

A grant authorizes an agent to make its owner's provider sign records. Permissions are named by a small fixed set of verbs. Each verb is scoped by record type and, optionally, by peer.

| Verb | Allows the agent to | Examples |
|---|---|---|
| `read` | Read threads, records, receipts and delivery state for the owner | Listing the inbox |
| `send` | Have the provider sign and send records that do not bind the owner | A message, opening a handoff or reschedule request, a counter-proposal |
| `commit` | Have the provider sign records that bind the owner to an obligation or a final decision | Accepting work, confirming a time, declaring work complete |
| `manage` | Change the identity's own configuration | Pinning contacts, changing the identity document, issuing or closing grants and approvals |

Rules:

- **PV-1.** A grant is the tuple `{id, verbs[], types[], peers[]?, expires, closedAt?}`, held by the owner's provider. `types[]` lists type URIs or extension URIs (§6.1). An extension URI covers every type it defines. A grant is closed by setting `closedAt`. It is never deleted (D5).
- **PV-2.** `manage` MUST NOT be granted to an agent in A1. Only the owner exercises it.
- **PV-3.** Every type definition MUST state which verb each of its records needs, `send` or `commit`. When a type does not say, or the provider does not know the type, the provider MUST require `commit`.
- **PV-4.** A provider MUST check the grant's verb, type scope, peer scope, expiry and closure before it signs a record for an agent. A record signed outside its grant is the provider's fault, not the receiver's to detect.
- **PV-5.** The signed record carries only a reference to the authority it was made under, `grant: {id, actor}` (§4.3, D5). Verbs and scopes stay local in A1. The receiver records the reference as a claim made by the signer. It cannot check it.

The four Wire v1 scopes map as follows: `read` → `read`, `coordinate` → `send` on reschedule types, `confirm` → `commit` on reschedule confirmation, `handoff` → `send` and `commit` on work types. Type definitions own the exact per-type verb.

## 2. Bytes and JSON

### 2.1 Encoding

- **B-1.** A record payload is a JSON text ([RFC 8259](https://www.rfc-editor.org/rfc/rfc8259)) encoded as UTF-8. Invalid UTF-8 MUST be rejected (`malformed`).
- **B-2.** A payload MUST NOT begin with a byte order mark (U+FEFF). A verifier MUST reject one (`malformed`) and MUST NOT strip it. A decoder that silently drops a leading BOM is not conformant, because the signed bytes and the parsed bytes would then differ.
- **B-3.** The same rules apply to the decoded JWS protected header.

Vectors: `negative/bom`, `negative/invalid-utf8`.

### 2.2 Strict JSON

- **J-1.** Payload and header MUST be I-JSON ([RFC 7493](https://www.rfc-editor.org/rfc/rfc7493)): no duplicate member names in any object, no unpaired surrogates (including escaped ones such as `"\ud800"`), no Unicode noncharacters (U+FDD0–U+FDEF and every code point ending in FFFE or FFFF, escaped or not) in member names or strings, and numbers that fit an IEEE 754 double.
- **J-2.** A verifier MUST reject an object with a duplicate member name (`malformed`). It MUST NOT keep the first or the last value instead. Parsers disagree on which one wins, so two verifiers would otherwise read different records from the same signed bytes.
- **J-3.** Insignificant whitespace and member order carry no meaning and are covered by the signature like every other byte.

Implementation note (non-normative). `JSON.parse` in JavaScript, and the header parsing inside common JOSE libraries, accept duplicate names and keep the last one. A conformant Node verifier needs a duplicate-aware parse of both header and payload. `negative/duplicate-header-member` is a header that `jose` accepts as `alg: ES256`. The Python peer's `object_pairs_hook` already rejects duplicates.

Vectors: `negative/duplicate-payload-member`, `negative/duplicate-header-member`, `negative/noncharacter`.

### 2.3 No canonicalization (NC1)

- **C-1.** The signature covers the exact payload bytes as transmitted. Wire v2 defines no canonical form (no JCS or similar).
- **C-2.** A verifier MUST verify and hash the received bytes. It MUST NOT parse and re-serialize a payload before verifying it, hashing it, storing it, or forwarding it.
- **C-3.** A sender serializes JSON however it likes (indentation, member order). That choice is not part of the wire. Once signed, the record is stored once and resent as the same bytes (NC1; the [delivery contract](delivery.md) owns the resend rule).
- **C-4.** Anything that refers to a record by content, such as a receipt (§4.4), uses SHA-256 over the exact payload bytes: the base64url-decoded second segment of the compact JWS.

The vectors deliberately use different serializations. `positive/handoff` is indented, `positive/reschedule` has no whitespace.

## 3. JWS protected header

A record is a JWS in Compact Serialization ([RFC 7515 §7.1](https://www.rfc-editor.org/rfc/rfc7515#section-7.1)): `BASE64URL(header) "." BASE64URL(payload) "." BASE64URL(signature)`. Wire v2 uses neither the JSON serialization nor an unprotected header.

- **S-1.** Each segment MUST be canonical unpadded base64url ([RFC 4648 §5](https://www.rfc-editor.org/rfc/rfc4648#section-5)): only `[A-Za-z0-9_-]`, no `=`, a length that is not 1 modulo 4, and zero unused bits in the last character. Equivalently, decoding the segment and re-encoding it gives back the same string. A verifier MUST reject anything else (`malformed`, §8 step 1). Lenient decoders, including Node's `Buffer.from(s, 'base64url')`, silently drop dangling characters, so a conformant verifier performs this check itself.

### 3.1 Algorithm allow-list

- **A-1.** The allow-list for Wire v2 is exactly `["ES256"]`: ECDSA with P-256 and SHA-256 ([RFC 7518 §3.4](https://www.rfc-editor.org/rfc/rfc7518#section-3.4)). The signature is the 64-byte `R || S` form, not DER.
- **A-2.** A verifier MUST reject any other `alg` value, including `none`, every `HS*`, and other ECDSA curves (`unsupported-alg`). It MUST make that check before it looks up a key (§8 step 3).
- **A-3.** A verifier MUST take the algorithm from the allow-list, never from the key or from the header alone. A key in an identity document is a P-256 key and is used only with ES256.
- **A-4.** Adding an algorithm needs a new decision and a new entry in this list. Until then, a P-256 key is the only kind an identity document may list (§5.1).

Vectors: `negative/alg-none`, `negative/alg-hs256` (an HMAC keyed with the signer's public key, the classic confusion attack), `negative/alg-es384-label`.

### 3.2 `typ` and `kid`

**`typ`.** Three values are frozen (D1). A verifier MUST compare them exactly and case-sensitively, with no `application/` prefix. This is stricter than RFC 7515's recommendation, and simpler.

| `typ` | Carries | Signed by a key with purpose |
|---|---|---|
| `darep-event+jws` | Every record that is not a receipt or rejection | `record` |
| `darep-receipt+jws` | A storage receipt (§4.4) | `provider` |
| `darep-rejection+jws` | A signed post-store rejection (§4.5, D6) | `provider` |

A verifier always knows which `typ` values it expects from context. A delivery endpoint expects events and rejections, and a sender waiting on a receipt expects a receipt. A verifier MUST reject a `typ` it does not expect (`bad-header`). Wire v1's `agent-network-event+jws` and `agent-network-receipt+jws` MUST be rejected (D1).

**`kid`.** The `kid` names exactly one key in exactly one identity document (D2).

- **K-1.** `kid` MUST be an absolute `https:` URL with a non-empty fragment, no userinfo, and at most 2048 characters, matching the normalized URI rules below. Example: `https://bob.vectors.test/.well-known/darep/bob#sig-2026-11`.
  - **Normalized `https:` URI rules** (used by K-1, §5.1 and §6.1 so non-JavaScript verifiers need no WHATWG URL parser):
    - **Scheme.** Exact lowercase `https://`.
    - **No userinfo.** The authority MUST NOT contain `@`.
    - **Host.** Either a **lowercase LDH DNS name** — two or more `.`-separated labels of 1–63 characters matching `[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?` (lowercase ASCII letters, digits and hyphens; no leading or trailing hyphen per label; at least one dot; total length at most 253) whose final label does not match `^(?:[0-9]+|0x[0-9a-f]*)$` — or, in test contexts only, a canonical **dotted-decimal IPv4 address** (four `.`-separated decimal integers `0`–`255` with no leading zeros). Uppercase letters, single-label hosts, IPv6 literals, and hex, octal or shorthand IPv4 addresses are forbidden.
    - **Port.** OPTIONAL. When present it MUST be a decimal integer `1`–`65535` with no leading zeros and MUST NOT be the default port `:443`.
    - **Path.** MUST be present and start with `/`, MUST contain only printable ASCII `0x21`–`0x7E` excluding `"`, `#`, `<`, `>`, `?`, `` ` ``, `{`, `}`, `\`, and MUST NOT contain dot segments (`.` or `..`, or percent-encoded forms such as `%2e`, `%2e%2e`, `.%2e`, `%2e.`, case-insensitively).
    - **Query and fragment.** Wherever this document says **no fragment** or **no query**, the `#` or `?` character itself MUST NOT appear (a trailing `#` or `?` is invalid even though WHATWG `.hash` / `.search` would be empty). Where a fragment is required, `#` MUST appear and MUST be followed by one or more printable ASCII characters `0x21`–`0x7E` excluding `"`, `#`, `<`, `>`, `` ` ``. Where a query is permitted and present, the characters between `?` and `#` (or end) MUST be printable ASCII `0x21`–`0x7E` excluding `"`, `#`, `<`, `>`, `'`.
- **K-2.** The part before `#` is the identity document's `id`. The whole string is the key's `id` in that document (§5.1). Both comparisons are exact string comparisons.
- **K-3.** In A1 the verifier resolves `kid` only against pinned snapshots (§5.3, TA-2). The `kid`'s host is a name, not an instruction to connect.
- **K-4.** The `kid` carries no address. The signer's address appears only in the payload `source` (D2).
- **K-5.** In A1 the `kid`'s host need not match the domain of `source`. A hosted provider can serve identity documents for many domains. A2 resolution will bind the two, and that rule is not part of Wire v2 records.

Vectors: `negative/kid-not-url` (the v1 form, `kid` = `acct:` address), `negative/wrong-kid`, `negative/legacy-typ`, `negative/typ-context-mismatch`.

The URI slots use the same normalized syntax with these existing restrictions:

| Slot | Query | Fragment |
|---|---|---|
| Identity document `id` (§5.1) | Forbidden, including empty `?` | Forbidden |
| Header `kid` syntax (K-1, step 4) | Permitted, including empty `?` | Required; K-1's broad printable-ASCII grammar |
| Pinned `keys[].id` (§5.1, step 5) | Forbidden, because the prefix is the document `id` | Required; 1–64 characters from `[A-Za-z0-9._-]` |
| Extension URI (U-1) | Permitted, including empty `?` | Forbidden |
| Type URI (U-2) | Permitted, including empty `?` | Required; K-1's broad grammar, within U-2's total length limit |

For example, `https://bob.vectors.test/.well-known/darep/bob?v=1#sig-2026-11`, `https://bob.vectors.test/.well-known/darep/bob?#sig-2026-11`, and `https://bob.vectors.test/.well-known/darep/bob#key{wide}` satisfy K-1 but cannot match a valid pinned document/key. A syntactically valid `kid` that cannot match a valid pinned document/key fails step 5 with `unknown-key`, not step 4 with `bad-header`. An extension URI such as `https://example.test/ext/poll/v1?` and its type URI `https://example.test/ext/poll/v1?#vote` have a permitted empty query.

Test context is an explicit local deployment or test-harness policy, shared by identity-document validation and record verification. It is not inferred from an untrusted record or request. Outside an explicitly selected test context, the test-only IPv4 alternative is unavailable. No wire field advertises this policy.

### 3.3 Other header members

Wire v1 required the header to have exactly `alg`, `kid` and `typ`. Wire v2 drops that rule.

- **H-1.** The header MUST contain `alg`, `kid` and `typ`. It MAY contain other members. A verifier MUST ignore members it does not understand, except as below.
- **H-2.** The header MUST NOT contain `crit`. Wire v2 defines no critical header parameters, so a verifier MUST reject any header that has one (`bad-header`).
- **H-2a.** The header MUST NOT contain `b64` ([RFC 7797](https://www.rfc-editor.org/rfc/rfc7797)), whatever its value. A verifier that honored `b64: false` would read different payload bytes than one that ignored it, so a verifier MUST reject the member outright (`bad-header`) rather than ignore it.
- **H-3.** A verifier MUST NOT use `jwk`, `jku`, `x5c`, `x5u`, `x5t`, `x5t#S256` or any other header member to find, build or trust a key (TA-3). If they are present, they are ignored like any other unknown member.
- **H-4.** Senders SHOULD NOT add header members. Anything a receiver must act on belongs in the signed payload.

Vectors: `positive/extra-header-member`, `negative/crit-header`, `negative/b64-header`, `negative/embedded-jwk-ignored` (an attacker's own key in `jwk`, with Bob's `kid`).

## 4. Record envelope

The envelope is DAREP's own format. It keeps the CloudEvents attribute names `id`, `source`, `type`, `subject` and `time`, but it does not claim CloudEvents conformance (D3). A recipients array and an extension map cannot be CloudEvents context attributes.

### 4.1 Members

The payload is a JSON object with exactly the members below. A verifier MUST reject a payload with any other top-level member (`malformed`). New top-level members can only arrive in a new protocol version. Everything else goes into `ext` (§6.2).

| Member | Type | Presence | Meaning |
|---|---|---|---|
| `darep` | string | REQUIRED | Protocol version. Exactly `"2"` (D3). Replaces CloudEvents `specversion`. |
| `id` | string | REQUIRED | Record ID: a lowercase UUID version 4. Unique per `source`. Can be mapped to an external identifier such as an Agent2Agent (A2A) message ID. |
| `source` | string | REQUIRED | The signer's address, `acct:name@domain`, at most 200 characters. |
| `type` | string | REQUIRED | Record type: an absolute `https:` URI with a fragment, at most 512 characters (§6.1). |
| `subject` | string | OPTIONAL | 1–200 characters. What the record is about inside the thread, for example a work-item or A2A task ID. It is not a thread ID: `thread` is. Receipts carry no `subject`. |
| `time` | string | REQUIRED | When the signer created the record (§7.1). |
| `to` | array of strings | REQUIRED | 1–32 distinct recipient addresses. MUST NOT contain `source`. |
| `thread` | string | REQUIRED | Thread ID, a lowercase UUID v4. The record that opens a thread uses its own `id`. |
| `inReplyTo` | string or null | REQUIRED | The `id` of the record this one answers, or `null`. |
| `expires` | string | Depends on `typ` (§4.3–4.5) | After this instant the record MUST NOT be admitted (§7.2). |
| `ext` | object | REQUIRED, may be `{}` | Extension data keyed by extension URI (§6.2). |
| `required` | array of strings | REQUIRED, may be `[]` | Extension URIs the receiver MUST understand to admit the record (§6.2). At most 32, distinct. |
| `grant` | object | Depends on `typ` (§4.3–4.5) | The authority the record was made under (D5). |
| `data` | object | REQUIRED, may be `{}` | Type-specific content. Opaque to this document except for receipts and rejections. |

Vectors: `negative/v1-envelope` (`unsupported-version`), `negative/unknown-top-level-member`.

### 4.2 Field rules

- **E-1.** Version first. A verifier MUST check that `darep` equals `"2"` before it applies any other envelope rule. A payload without `darep`, such as a Wire v1 envelope, gets `unsupported-version`, not `malformed`.
- **E-2.** `id` and `thread` MUST match `^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`. `inReplyTo`, when not `null`, matches the same pattern.
- **E-3.** If `thread` equals `id` (the record opens a thread), `inReplyTo` MUST be `null`. A record inside a thread MAY have `inReplyTo: null`. `inReplyTo` may name a record from any participant.
- **E-4.** Addresses (`source`, entries of `to`) MUST match `^acct:[a-z0-9][a-z0-9._-]{0,62}@L(\.L)+$`, where `L` is `[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?`. This is the Wire v1 rule, unchanged.
- **E-5.** One record goes to every address in `to` as the **same signed bytes**. Each recipient's provider verifies it with itself as the receiver (§8 step 12). Fan-out never re-signs.
- **E-6.** `time` and `expires` follow §7.1. When `expires` is present, it MUST be later than `time` and at most 30 days after it.
- **E-7.** A field that is out of range or has the wrong type is `malformed`.

Vectors: `positive/message-multi-recipient`, `negative/expiry-window-too-long`.

### 4.3 Events (`darep-event+jws`)

- `type` MUST NOT be `https://darep.org/ext/core/v2#receipt` or `#rejection`.
- `expires` is REQUIRED. Senders SHOULD use 7 days after `time`, which matches the Wire v1 retry window.
- `grant` is REQUIRED and is exactly `{ "id": string (1–200 characters), "actor": "owner" | "agent" }` (D5).
  - `actor: "agent"`: an agent made the record under the grant named by `id`.
  - `actor: "owner"`: the owner made it directly. `id` names the provider's local record of that owner act.
  - An agent acting on an owner's pre-approval sends `actor: "agent"` with its own grant's `id`. The provider keeps the approval locally as evidence.
  - `id` is an opaque local reference. It MUST NOT be a bearer token, contain one, or be derived from one in a reversible way.
  - The `grant` object is reserved to grow into a reference to a signed delegation record. That record is not built in A1 (D5). Until then, receivers MUST reject unknown members inside `grant`.

Vectors: `positive/handoff`, `positive/reschedule`, `positive/message-multi-recipient`.

### 4.4 Receipts (`darep-receipt+jws`)

A receipt is signed evidence that the receiver durably stored one record. What "stored" means, how long the record is kept, and when a receipt is issued are defined by D4 and the [delivery contract](delivery.md) (§4). This section fixes only the record's shape.

A receipt is returned only in the response to the delivery it answers. It is never delivered as a record of its own, so it has no admission window (§7.2 TM-4a).

- `source` is the receiving identity: the recipient address of the delivery it answers, not merely its provider. `to` is exactly `[<source of the received record>]`.
- `type` is `https://darep.org/ext/core/v2#receipt`.
- `thread` is the received record's `thread`. `inReplyTo` is the received record's `id` and MUST NOT be `null`.
- `expires` MUST be absent. A receipt is evidence of something that happened. It does not expire.
- `grant` MUST be absent. The provider issues receipts on its own authority.
- `ext` MUST be `{}` and `required` MUST be `[]`. `subject` MUST be absent. A receipt is evidence, and its meaning must not drift through extensions.
- `data` is exactly `{ "sha256": <64 lowercase hex>, "storedAt": <instant> }`. `sha256` is computed over the received record's exact payload bytes (C-4). The receiver retains the record until at least `storedAt` + 30 days (D4); that promise is fixed by the delivery contract, so the receipt does not restate it.

The `time >= data.storedAt` relationship is an issuer obligation under [delivery §4.1](delivery.md#41-what-stored-means). Wire v2 §8 does not add a verifier rejection condition for this relationship. Applications may report inconsistent evidence without changing the protocol verification verdict.

- **RC-1. Correlation.** A receipt or signed rejection counts as an answer to a record `R` only if all of the following hold: its `source` is in `R.to`, its `to` is `[R.source]`, its `inReplyTo` is `R.id`, its `thread` is `R.thread`, and its `time` is not earlier than `R.time` − skew (§7.2). For a receipt, `data.sha256` must also equal the SHA-256 of `R`'s exact stored payload bytes. A verifier that holds `R`, such as the sender matching a delivery response or an evidence checker, MUST run this check as §8 step 15. A failure there is `receipt-mismatch`. A receipt that fails it proves nothing about `R`. The delivery contract adds one sender-side rule on top: a receipt's `source` must equal the recipient address of the delivery it answers.

Vectors: `positive/receipt`, which receipts `positive/handoff`; `negative/receipt-mismatch`, a valid receipt with the wrong digest; `negative/receipt-mismatch-after-window`; `negative/receipt-predates-record`; `negative/receipt-with-ext`; `negative/receipt-after-delivery-window`.

### 4.5 Signed rejections (`darep-rejection+jws`)

A signed rejection is the second tier of D6. The receiver stored and acked a record, and the applier then refused it, for example because the thread head moved. Pre-store rejections are never signed records. They travel as `application/problem+json` (D6; see the [HTTPS binding](https-binding.md)).

- `source` is the refusing identity. `to` is exactly `[<source of the refused record>]`.
- `type` is `https://darep.org/ext/core/v2#rejection`.
- `thread` is the refused record's `thread`. `inReplyTo` is the refused record's `id` and MUST NOT be `null`.
- `expires` is REQUIRED, because the rejection is delivered like any other record. `grant` MUST be absent.
- `data` is `{ "code": <string>, "detail"?: <string> }`, with no other members. `code` MUST be present and MUST be a string: either a bare code matching `^[a-z0-9-]{1,64}$` (defined in the post-store table of the [code registry](delivery.md#5-rejections-and-the-code-registry)), or an extension-defined code: an extension URI plus `#` plus a name, in the form of a `type` (U-2), for example `https://darep.org/ext/work/v2#terms-mismatch`. For forward compatibility, verifiers MUST accept a syntactically valid `code` that is not in the registry and treat it as an unknown refusal. `detail` is 1–1000 characters of human-readable text and MUST NOT be needed to interpret the code.
- A rejection carries no digest of the refused record. `inReplyTo` with `source` and `thread` identifies it unambiguously, because a receiver stores at most one payload per (recipient, `source`, `id`) and refuses a different payload under the same `id` (delivery contract §6).

Vectors: `positive/rejection` (code `stale-head`), `positive/rejection-extension-code`, `positive/rejection-unknown-code`, `negative/rejection-missing-code`, `negative/rejection-nonstring-code`, `negative/rejection-empty-data`.

## 5. Identity document and keys

### 5.1 Shape

An identity document says which keys speak for which addresses. In A1 it exists as a pinned snapshot (§5.3). From A2 it is also published at its `id` URL.

```json
{
  "darep": "2",
  "id": "https://bob.vectors.test/.well-known/darep/bob",
  "addresses": ["acct:bob@vectors.test"],
  "updated": "2026-11-01T00:00:00Z",
  "keys": [
    {
      "id": "https://bob.vectors.test/.well-known/darep/bob#sig-2026-05",
      "purpose": ["record"],
      "publicKeyJwk": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" },
      "validFrom": "2026-05-01T00:00:00Z",
      "validUntil": "2026-11-15T00:00:00Z"
    },
    {
      "id": "https://bob.vectors.test/.well-known/darep/bob#sig-2026-11",
      "purpose": ["record"],
      "publicKeyJwk": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" },
      "validFrom": "2026-11-01T00:00:00Z"
    }
  ]
}
```

| Member | Rule |
|---|---|
| `darep` | `"2"`. |
| `id` | Absolute `https:` URL satisfying K-1's normalized URI rules, with no fragment (`#`), no query (`?`) and no userinfo, of at most 2048 characters. RECOMMENDED form: `https://<domain>/.well-known/darep/<name>`. |
| `addresses` | 1 or more `acct:` addresses this document speaks for (TA-4). |
| `updated` | Instant (§7.1) of the last change. Informational. |
| `keys` | 1 or more key entries, each with a distinct `id`. |
| `keys[].id` | The document `id` + `#` + a fragment of 1–64 characters from `[A-Za-z0-9._-]`. This is the `kid` a signer uses. |
| `keys[].purpose` | Non-empty array of distinct values from §5.2. |
| `keys[].publicKeyJwk` | A public P-256 key as a JWK ([RFC 7517](https://www.rfc-editor.org/rfc/rfc7517)): exactly `kty: "EC"`, `crv: "P-256"`, `x`, `y`. It MUST NOT contain `d`. |
| `keys[].validFrom` | Instant. The key signs nothing dated earlier. |
| `keys[].validUntil` | OPTIONAL instant, later than `validFrom`. The key signs nothing dated at or after it. Set it to retire a key in a planned rotation. |
| `keys[].revoked` | OPTIONAL instant at which the owner declared the key compromised or withdrawn. See §5.4. |
| `keys[].account` | Reserved for a linked external account as a [CAIP-10](https://standards.chainagnostic.org/CAIPs/caip-10) identifier. Not built in A1. |

A verifier MUST ignore document members it does not understand. The document is not itself signed in A1. Its authority comes from the owner's pin (TA-2).

### 5.2 Key purposes

| Purpose | Signs | In A1 |
|---|---|---|
| `record` | `darep-event+jws` records | Used |
| `provider` | `darep-receipt+jws` and `darep-rejection+jws` | Used |
| `root` | Future versions of this identity document and its key history (TA-5) | Reserved. MUST NOT verify any record. |
| `delegate` | Records made by a delegate holding its own key, under a signed delegation record (D5) | Reserved. MUST NOT verify any record. |

One key MAY carry several of the active purposes. A small provider can keep a single key with `["record", "provider"]`, which is what the test identity Carol does. A reserved purpose (`root`, `delegate`) MUST NOT be combined with any other purpose on the same key. A document that does so fails pin validation (P-0). A verifier MUST reject a record whose key lacks the purpose its `typ` needs (`key-not-valid`).

Vector: `negative/wrong-key-purpose` (Bob's `provider` key signs an event).

### 5.3 Resolving `kid` in A1: the pinned snapshot

- **P-0. Pin validation.** Before pinning, a verifier MUST check the document against §5.1 and §5.2. That means exact JWK members, `crv` P-256, and coordinates that lie on the curve. It MUST refuse a document whose `id` equals that of another pinned document, whose key `id`s are not all distinct, or whose addresses overlap another pinned document's (TA-4). At most one pinned document has a given `id`, so `kid` resolution is never ambiguous. Replacing a snapshot (§5.5) swaps it atomically. Verification (§8) assumes that every pinned document passed P-0.
- **P-1.** The receiver keeps one pinned snapshot per contact. A snapshot is an identity document as the owner accepted it (TA-2). It replaces the Wire v1 contact card `{version: 1, id, origin, publicKey}`. Where to deliver (the provider endpoint) is binding configuration, not part of the identity document in A1.
- **P-2.** To resolve a `kid`, the verifier takes the part before `#`, finds the pinned snapshot with that exact `id`, then finds the key whose `id` equals the whole `kid`. If either lookup fails, the result is `unknown-key`.
- **P-3.** The verifier MUST NOT fetch the document, follow redirects, or consult DNS in order to verify (D2).

### 5.4 Rotation and revocation

Keys are retired or revoked. They are never removed from the document, so earlier records stay verifiable.

- **R-1. Rotation.** To rotate, the owner adds a new key and sets `validUntil` on the old one. A record whose `time` falls inside the old key's window stays valid indefinitely. A record dated at or after `validUntil` and signed with the old key is rejected (`key-not-valid`).
- **R-2.** Rotation limits the damage from an old key only within the admission window. For events and rejections, admission requires `expires` to be in the future (§7.2) and `expires` to be at most 30 days after `time`. A retired key therefore cannot get a back-dated record admitted more than about 30 days after its `validUntil`. A receipt is admitted only while the delivery it answers is open (TM-4a), so the same 30-day bound holds for receipts. Outside admission, in evidence mode, a retired key that is later stolen can sign records dated inside its old window indefinitely: a signer's own timestamp cannot prove when signing happened. A key that may be compromised MUST therefore be revoked, not merely retired.
- **R-3. Revocation.** A key with `revoked` set MUST NOT verify any record, whatever the record's `time`, in admission or evidence mode (§7.3). A thief can back-date `time`, so a record's own timestamp cannot rescue it. Records already admitted and stored remain in the receiver's store with their receipts. How to weigh such stored evidence is receiver policy and outside Wire v2. An honest answer needs a timestamp the signer cannot back-date, which requires future identity-resolution and timestamping work.
- **R-4.** Validity is evaluated against the record's `time` exactly, with no skew allowance: `validFrom ≤ time < validUntil`.
- **R-5.** A key entry's `id`, `publicKeyJwk` and `validFrom` never change once published. Reusing a key `id` for different key material is forbidden.

Vectors: `positive/rotated-key-within-validity`, `negative/retired-key-after-validity`, `negative/revoked-key`.

### 5.5 Updating a pinned snapshot in A1

A1 has no in-band document update. The owner can re-pin a newer snapshot out of band. An implementation SHOULD accept the newer snapshot as a routine rotation, with no new trust decision, only when it is **monotonic**: same `id`, every existing key still present with the same `id`, `publicKeyJwk`, `purpose` and `validFrom`, `validUntil` and `revoked` only added or moved earlier, and no address removed. Any other change MUST be presented to the owner as a new trust decision. It is not a rotation.

## 6. Types and extensions

### 6.1 URIs

- **U-1.** Every extension is named by an absolute `https:` URI satisfying K-1's normalized URI rules, with no fragment (`#`) and no userinfo, of at most 512 characters. DAREP extensions use `https://darep.org/ext/<name>/v<n>`, where `<name>` is lowercase `[a-z0-9-]+` and `<n>` is a positive integer (D1). Anyone else MUST mint extension URIs under a domain they control, never under `darep.org`.
- **U-2.** A record `type` is an extension URI (U-1) plus `#` plus a non-empty type name (at most 512 characters total), for example `https://darep.org/ext/work/v2#handoff`. The URI before `#` is the extension that defines the type.
- **U-3.** A breaking change to an extension gets a new `v<n>`. The record envelope itself changes only with `darep`.
- **U-4.** Senders MUST NOT mint protocol identifiers under `net.agentnetwork.*` (D1). Protocol identifiers are `typ`, `type`, the keys of `ext` and the entries of `required`. U-1 and U-2 already make such a name invalid in those positions (`malformed`). Free text inside `data` is content and is not checked.

Names used by this document and its vectors:

| URI | Defined by | Status |
|---|---|---|
| `https://darep.org/ext/core/v2` | This document: `#receipt` (§4.4), `#rejection` (§4.5) and `#message` (below). | Core. Every conformant receiver understands it. |
| `https://darep.org/ext/work/v2` | Experimental work extension: `#handoff` and its replies | Not part of frozen Wire v2 conformance (D8 amendment). |
| `https://darep.org/ext/reschedule/v2` | Experimental reschedule extension: `#request` and its replies | Not part of frozen Wire v2 conformance; Node only (D8 amendment). |

The handoff (`work/v2`) and reschedule types are experimental extensions, not part of frozen Wire v2 conformance. Normative publication of `https://darep.org/ext/work/v2` is future work. Core conformance requires neither extension.

**`core/v2#message`.** A free-form message between participants. It is an event (`darep-event+jws`) and needs the `send` verb (PV-3). Its `data` is exactly `{ "text": <non-empty string> }`. Size is bounded only by the delivery contract's record size limit. Like any type's `data`, it is checked by the applier after storage (T-2), not by §8.

Core types are an extension named `core` with its own version number. `vN` of an extension does not track `darep`. `work/v2` and `reschedule/v2` follow D1's example.

The `data` shapes in `positive/handoff` and `positive/reschedule` carry the Wire v1 action fields over unchanged, except that the v1 `action.kind` becomes the `type` fragment. They illustrate the envelope. They do not define those extensions.

### 6.2 `ext` and `required`

- **X-1.** `ext` maps extension URIs (U-1) to any JSON value. Each key MUST be an extension URI with no fragment.
- **X-2.** A receiver MUST ignore an `ext` entry it does not understand, unless that entry's URI is listed in `required`. It still stores the exact bytes (NC1).
- **X-3.** `required` lists extension URIs the receiver MUST understand to admit the record. If any is unknown to the receiver, it MUST reject the record before storing it (`unsupported-extension`; D6 tier 1).
- **X-4.** A URI in `required` does not need an entry in `ext`. Listing a type's own extension in `required` says "do not admit this unless you understand this type".
- **X-5.** Senders SHOULD list only what genuinely changes the meaning of the record for a receiver that ignores it. Storing and acknowledging an unknown record is always safe, so most records need no `required` entries beyond their own type's extension, if that.

Vectors: `positive/unknown-optional-extension`, `negative/unknown-required-extension`.

### 6.3 Unknown types

- **T-1.** Verification (§8) does not depend on knowing `type`. A receiver MUST be able to verify, store and acknowledge a record of a type it does not implement, provided none of the record's `required` extensions are unknown to it.
- **T-2.** Validating `data` against its type is the applier's job, after storage. A record with a known type and invalid `data` is stored, acked, and then refused with a signed rejection (§4.5). The one exception is `core/v2#receipt` and `#rejection`, whose `data` is checked in §8 step 9.

Vector: `positive/unknown-type-not-required`.

## 7. Time, expiry and clock skew

### 7.1 Format and window

- **TM-1.** `time`, `expires`, `storedAt` and identity-document instants are UTC timestamps matching `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$`, and they MUST be valid calendar instants ([RFC 3339](https://www.rfc-editor.org/rfc/rfc3339) profile: uppercase `T` and `Z`, no offset, at most millisecond precision, no leap second).
- **TM-2.** When `expires` is present, `time < expires ≤ time + 30 days` (2,592,000 seconds).
- **TM-2a.** The ceiling bounds how long a receiver must remember a record ID to catch replays. A record can be admitted from `time − skew` until `expires + skew`, which is at most 30 days + 2 × skew (30 days and 10 minutes) after its first admission, slightly longer than D4's 30-day minimum. The [delivery contract](delivery.md) (§4.2, §6) therefore requires deduplication entries to be kept until at least `expires + skew`.

### 7.2 Admission checks

Let `now` be the verifier's clock and `skew` = 300 seconds. These values are fixed for Wire v2, not advertised per receiver. The delivery contract uses the same `skew` and does not define its own. Senders SHOULD set `expires` to `time` + 7 days, which matches the Wire v1 retry window.

- **TM-3.** A receiver MUST reject a record with `time > now + skew` (`not-yet-valid`).
- **TM-4.** A receiver MUST reject a record with `now ≥ expires + skew` (`expired`). Both are pre-store rejections (D6 tier 1).
- **TM-4a. Receipts.** A receipt has no `expires` (§4.4), because it comes back in the delivery response. TM-3 applies to it. Its lower bound comes from the record it answers: RC-1 requires `time ≥ R.time − skew`, and a sender MUST reject a receipt for `R` once `now ≥ R.expires + skew` (`expired`, §8 step 15), because its delivery of `R` has closed by then (delivery contract §7.3). A receipt for a duplicate delivery is the receipt stored for the first delivery, byte for byte (delivery contract §6), and still passes these rules.
- **TM-5.** No other lower bound on `time` applies. TM-2 and TM-4 together make an event's or rejection's `time` later than `now − 30 days − skew`. TM-4a and RC-1 bound a receipt's `time` from below by the answered record's `time`.
- **TM-6.** Expiry gates admission only. At a receiver, deduplication runs before the time checks (delivery contract §3.1), so a retried duplicate of an already-stored record still gets its receipt after expiry.

Vectors: `negative/expired`, `negative/not-yet-valid`, `negative/receipt-predates-record`, `negative/receipt-after-delivery-window`.

### 7.3 Evidence mode

Verifying a stored record later, for example a third party checking an evidence bundle, uses **evidence mode**. Evidence mode runs §8 steps 1–11, and step 15 when the answered record is at hand. It skips steps 12–14, which depend on who receives the record and when. An expired record is still a valid signed record. Revoked keys still fail (R-3).

Vector: `positive/evidence-mode-expired`, `negative/revoked-key` (evidence mode).

## 8. Verification procedure and codes

A verifier runs these steps in order and stops at the first failure. The order is normative, so that two conformant verifiers return the same code for the same input. Every vector exercises one failure. A receiver runs the delivery contract's carrier checks before step 1 and its deduplication check between steps 12 and 13 ([delivery contract](delivery.md) §3.1). It does not otherwise reorder these steps.

Inputs: the compact JWS string, the expected `typ` values, the pinned snapshots (each already validated by P-0), and in admission mode also `now`, the receiver's own address, and the set of extension URIs it understands. For step 15, the input also includes the answered record's JWS. The local test-context policy (§3.2) is shared with P-0 validation; it is not a wire input.

| Step | Check | On failure |
|---|---|---|
| 1 | Exactly three `.`-separated segments, each canonical base64url (S-1), with non-empty header and payload | `malformed` |
| 2 | The header decodes to strict JSON (§2) that is an object | `malformed` |
| 3 | `alg` is in the allow-list (§3.1) | `unsupported-alg` |
| 4 | `typ` is one of the expected values; no `crit` and no `b64`; `kid` satisfies K-1 (§3.2, §3.3) | `bad-header` |
| 5 | `kid` resolves to a pinned key (§5.3) | `unknown-key` |
| 6 | The signature is 64 bytes and verifies with that key over the ASCII bytes of `header "." payload` exactly as received | `bad-signature` |
| 7 | The payload decodes to strict JSON (§2) that is an object | `malformed` |
| 8 | `darep` is `"2"` (E-1) | `unsupported-version` |
| 9 | The envelope satisfies §4 for its `typ`, including the receipt and rejection `data` shapes | `malformed` |
| 10 | The key's document lists `source` in `addresses` (TA-4) | `signer-mismatch` |
| 11 | The key has the purpose for `typ`, is not revoked, and its validity covers `time` (§5.2, §5.4) | `key-not-valid` |
| 12 | *Admission only.* The receiver's address is in `to` | `wrong-recipient` |
| 13 | *Admission only.* `time ≤ now + skew`, then, except for a receipt, `now < expires + skew` (§7.2) | `not-yet-valid`, `expired` |
| 14 | *Admission only.* Every URI in `required` is understood (§6.2) | `unsupported-extension` |
| 15 | *Receipts and rejections, whenever the answered record `R` is known.* Correlation with `R` (RC-1). Then, *for a receipt in admission mode*, `now < R.expires + skew` (TM-4a) | `receipt-mismatch`, `expired` |

The signature is checked (step 6) before the payload is parsed (step 7), so a payload changed after signing fails as `bad-signature` even when it is no longer valid JSON. Steps 10–14 run only on authenticated content. With freshly created keys, a back-dated record fails at step 11 (`key-not-valid`) before step 13 (`expired`).

Every code above is defined, with its class and meaning, in the single [code registry](delivery.md#5-rejections-and-the-code-registry) in the delivery contract. In admission mode at a receiver, every failure in steps 1–14 is a D6 tier-1, pre-store rejection. The HTTPS binding maps each code to a status and an `application/problem+json` body ([HTTPS binding](https-binding.md) §3). `receipt-mismatch`, and `expired` from step 15, are sender-side results and never travel as a problem response.

A verifier SHOULD NOT reveal more about which step failed to an unauthenticated sender than these codes do. In particular, it SHOULD NOT say which keys it has pinned.

## 9. Reserved slots, not built

The following extension URIs are reserved for the purposes listed. Senders MUST NOT emit them in Wire v2 until their extension is specified. A receiver that meets one treats it as an unknown extension (§6.2): it ignores the entry, unless the URI is listed in `required`, in which case it rejects the record. Reserving them now fixes the slot shape, a URI-keyed `ext` entry, without freezing semantics that are not designed yet.

| Reserved URI | Intended content |
|---|---|
| `https://darep.org/ext/payment/v1` | Payment terms attached to an offer or agreement: amount, asset, payee, conditions. Shaped so that an illustrative external payment protocol such as x402, or on-chain escrow, can map onto it. No wallet in the core. |
| `https://darep.org/ext/settlement/v1` | A reference from an agreement to an external settlement or execution record, for example a CAIP-10 account plus a transaction or invoice ID. |
| `https://darep.org/ext/evidence/v1` | Hashes of deliverables and evidence. Each is `{alg, value, mediaType?, size?}` over the exact bytes, with `sha-256` the expected first algorithm. |
| `https://darep.org/ext/verifier/v1` | A named third-party verifier for a piece of work, by address, and the terms under which it attests. |
| `https://darep.org/ext/deadline/v1` | Explicit deadlines in an agreement: respond-by, deliver-by, accept-by. Distinct from `expires`, which is only the admission window. |
| `https://darep.org/ext/delegation/v1` | The future signed delegation record that `grant` will reference (D5). |

The identity-document member `keys[].account` (§5.1) and the key purposes `root` and `delegate` (§5.2) are reserved in the same way.

## 10. Security considerations

- **Key confusion.** The fixed allow-list (§3.1), the ban on key-bearing header members (H-3), and resolution from pinned snapshots only (TA-3) together close the known JWS key-confusion attacks: `alg: none`, HMAC keyed with a public key, and an attacker-supplied `jwk`. See `negative/alg-none`, `negative/alg-hs256` and `negative/embedded-jwk-ignored`.
- **Parser differentials.** Duplicate members, a BOM, invalid UTF-8, and unpaired surrogates all let two parsers read different content from the same signed bytes. They are rejected rather than normalized (§2).
- **Signature malleability.** ECDSA signatures are malleable: `(r, n − s)` also verifies. DAREP never identifies a record by its signature bytes. Identity is `(source, id)`, and content is the SHA-256 of the payload bytes. Implementations MUST NOT key storage, deduplication or receipts on the JWS signature or on the full JWS string. Verifiers are not required to enforce low-S.
- **Replay.** A replayed record carries the same `(source, id)` and is caught by deduplication in the delivery contract. Expiry (§7.2) bounds how long a receiver must remember IDs.
- **Clock trust.** `time` is the signer's claim. Key validity (R-4) is evaluated against it, which is exactly why revocation (R-3) ignores it.
- **Privacy.** `grant.id` is visible to every recipient. It MUST be opaque (§4.3). Records are signed, not encrypted. Confidentiality is the carrier's job in A1.

## 11. Conformance and test vectors

Conformance means meeting all applicable normative requirements. Vectors and runners are verification aids, not a complete conformance determination. A **conformant verifier** implements §2–§8; the records vectors check verdicts and rejection codes. A **conformant signer** produces only records that a conformant verifier accepts in admission mode. In particular it never emits a BOM, a duplicate member, a header with `crit`, or a reserved extension.

The D8 amendment separates core conformance from experimental application types. All records vectors test core verification, including envelopes containing experimental handoff and reschedule payloads; they do not require those application semantics (T-1).

Each vector file states the verification `context` (`mode`, `now`, `receiver`, expected `typ`, `understood` extensions, and for receipts the `answered` record), the `jws`, the decoded header and payload, the payload's SHA-256, and `expected`: `{verdict: "accept", kid, record}` or `{verdict: "reject", code}`. Vector files are regenerated deterministically by `generate.mjs` and checked by `check.mjs`, a step-by-step rendering of §8. See [`vectors/v2/records/README.md`](../vectors/v2/records/README.md).

## 12. Deferred items

Normative publication of the experimental `work/v2` extension remains future work (§6.1). The protocol name is resolved as DAREP; identifiers follow the D1 amendment dated 2026-11-21.

## Appendix A. Changes from Wire v1

| Wire v1 (the pre-standard prototype, not published) | Wire v2 (this document) |
|---|---|
| `typ` `agent-network-event+jws` / `agent-network-receipt+jws` | `darep-event+jws` / `darep-receipt+jws` / `darep-rejection+jws` (D1) |
| Header has exactly `alg`, `kid`, `typ` | `alg`, `kid`, `typ` required; others ignored; `crit` rejected (§3.3) |
| `kid` = `acct:` address | `kid` = identity-document URL + `#fragment` (D2) |
| ES256 hard-coded | Declared allow-list `["ES256"]` (§3.1) |
| `specversion: "1.0"`, `datacontenttype` | `darep: "2"`, no `datacontenttype` (D3) |
| `type` `net.agentnetwork.<x>.v1` | `type` URI `https://darep.org/ext/<name>/v<n>#<type>` (D1) |
| `subject` = thread ID | `thread`; `subject` optional (§4.1) |
| `data.to` (one address) | Top-level `to[]` |
| `data.previous` | Top-level `inReplyTo` |
| `data.action.kind` | Encoded in the `type` fragment |
| No expiry field; fixed 7-day window | `expires`, at most 30 days (§7) |
| — | `ext`, `required`, `grant` |
| Receipt `{version: 1, from, to, eventId, sha256, storedAt}` | Receipt is a record: envelope plus `data {sha256, storedAt}` (§4.4) |
| Contact card `{version: 1, id, origin, publicKey}`, permanently pinned | Pinned identity-document snapshot with `keys[]`, purposes and validity (§5) |
| Scopes `read`, `coordinate`, `confirm`, `handoff` | Verbs `read`, `send`, `commit`, `manage` (§1.3) |
| Unknown types rejected | Unknown types verify, store and ack (§6.3) |

## Errata 2026-11-21

- **P-0 validation.** Completed identity-document validation in the checker and both reference implementations, including required `updated`, non-empty keys, field types and formats, addresses, JWK coordinates and validity ordering; expanded the generated invalid-pin corpus.
- **Conformance scope.** Clarified that experimental work and reschedule semantics are outside frozen Wire v2 conformance (D8 amendment), and that vectors and runners are verification aids.

- **§8 step 15 order.** Confirmed the normative order: full RC-1 correlation (including the receipt digest) runs before the TM-4a delivery-window check. Fixed `vectors/v2/records/check.mjs` and added `negative/receipt-mismatch-after-window`.
- **§4.5 rejection codes.** Clarified that `data.code` MUST be present and MUST be a string (bare code matching `^[a-z0-9-]{1,64}$` or extension code URI), and that verifiers MUST accept syntactically valid unregistered codes as unknown refusals for forward compatibility. Fixed `check.mjs` and added `positive/rejection-unknown-code`, `negative/rejection-missing-code`, `negative/rejection-nonstring-code` and `negative/rejection-empty-data`.
- **§3.2 K-1, §5.1, §6.1 empty `#` / `?`.** Stated that wherever this document says "no fragment" or "no query", the `#` or `?` character itself is forbidden (including a trailing empty `#` or `?`). Fixed `check.mjs` and added negative vectors and pin cases.
- **§3.2 K-1, §5.1, §6.1 host and URI rules.** Replaced reliance on WHATWG URL parsing with normative rules for `kid`, document `id`, extension URIs and `type` URIs: lowercase LDH DNS names (at least one dot, no leading/trailing hyphen per label, non-numeric/non-`0x`-hex final label) or canonical dotted-decimal IPv4 in test contexts only; no uppercase, no `:443`, no dot segments, no hex or octal IPv4, no userinfo. Fixed `check.mjs` and added negative vectors for each case.
- **§5.1 / §5.3 P-0 document `id` query.** Fixed `validatePins` in `check.mjs` to reject identity document `id`s carrying a query, and added `invalid-identities.json`.
- **§8 back-dated records.** Added an informative sentence noting that with freshly created keys, a back-dated record fails at step 11 (`key-not-valid`) before step 13 (`expired`).
- **Protocol rename.** Renamed the protocol to DAREP, with `darep-*` `typ` strings and `https://darep.org/` URIs, per the D1 amendment dated 2026-11-21; behavior is unchanged.
- **Envelope version member.** Renamed the record envelope protocol-version member `ack` to `darep`, retaining the value `"2"`, per the D3 amendment dated 2026-11-21.
- **Remaining protocol identifiers.** Renamed the identity-document version member to `darep` (value `"2"`), the well-known path to `/.well-known/darep/<name>`, the inbox path to `/darep/v2/inbox`, and the recipient header to `Darep-Recipient`, per the amendment dated 2026-11-21; behavior is unchanged.

## Errata 2026-11-21 (v0.1.1)

- #18: Clarified URI-slot query and fragment rules and step-5 key-resolution failures (§3.2).
- #19: Explained local selection of the shared test-only IPv4 policy (§3.2, §8 inputs).
- #20: Distinguished the receipt signing-time obligation from verifier rejection conditions (§4.4).
