# DAREP, Wire v2: HTTPS binding

DAREP means Durable Agreement, Receipt & Evidence Protocol. Spec home: https://darep.org.

Status: **DAREP Wire v2, frozen (spec v0.1)** · Date: 2026-11-21 · Document 3 of 3

1. [Signed records](records.md): the envelope, `kid`, keys, `typ` and the identity document.
2. [Delivery contract](delivery.md): the receive pipeline, receipts, rejections, retries and evidence.
3. **HTTPS binding** (this document): how the delivery contract runs over HTTPS.

Decisions are cited by ID (D1–D8, NC1) from the [Wire v2 decision record](decisions-wire-v2.md).
Vectors are in [`vectors/v2/delivery/`](../vectors/v2/delivery/). Each vector states the HTTP request and the expected response defined here.

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY and OPTIONAL are to be read as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

This binding adds no meaning to records. Everything a record means is in the signed bytes. A second binding can replace this one without changing anything already stored or signed.

This binding owns HTTP status codes and the `application/problem+json` mapping. It defines no rejection codes: every code is in the [code registry](delivery.md#5-rejections-and-the-code-registry) of the delivery contract.

## 1. Resources

A provider exposes two kinds of resource:

| Resource | Method | Purpose | A1 status |
|---|---|---|---|
| Inbox | `POST` | Accept one delivery for one recipient address and return a receipt or a pre-store rejection. One inbox MAY serve every address the provider hosts. | REQUIRED |
| Identity document | `GET`, `HEAD` | Serve the identity document that `kid` points into. | RECOMMENDED in A1, REQUIRED from A2 (D2) |

No other endpoint is part of the protocol. Health checks, administration and the MCP edge for agents are local matters and are out of scope.

### 1.1 Where the URLs come from

The inbox URL is **binding configuration**, not part of the identity document. In A1 the identity document carries keys and addresses only ([Signed records](records.md) P-1). A sender stores, for each recipient address, the inbox URL it learned out of band together with the pinned identity document, for example from the same contact exchange. The sender MUST NOT construct an inbox URL from the address, and MUST NOT fetch anything to discover one (D2). Discovery of inbox URLs arrives with network resolution in A2.

The identity document URL is the `kid` with its fragment removed (D2).

Every request names the delivery's recipient address explicitly in the `Darep-Recipient` header (§2.1). The recipient address is therefore never inferred from the URL, and one inbox URL can serve many addresses.

### 1.2 Provisional recommended layout

Senders treat both URLs as opaque. The recommended identity-document path `/.well-known/darep/` is **provisional**, pending IANA well-known URI registration (RFC 8615). Providers SHOULD use this layout:

```
Identity document   https://{host}/.well-known/darep/{name}
Key URL (kid)       https://{host}/.well-known/darep/{name}#{key-name}
Inbox               https://{host}/darep/v2/inbox
```

`{name}` is the local part of the `acct:` address. `{key-name}` is chosen by the provider and MUST stay stable for the lifetime of the key.

Example for `acct:carol@example.com`:

```
https://example.com/.well-known/darep/carol
https://example.com/.well-known/darep/carol#sig-2026-11
https://example.com/darep/v2/inbox
```

Identity documents are referenced by full URLs (`kid`/`id`). If the recommended path changes, new identity documents use the new path; existing pinned URLs stay valid and must continue to be served without redirects. Moving the recommendation does not rewrite existing document IDs or key URLs.

### 1.3 Transport security

Every URL in this binding MUST use the `https` scheme. Clients MUST validate the server certificate chain and host name. TLS 1.3 is RECOMMENDED and TLS 1.2 is the minimum.

For local testing only, a provider MAY use `http` when the host is a loopback address (`127.0.0.1`, `[::1]` or `localhost`). A sender MUST refuse an `http` URL for any other host.

TLS protects the transfer only. Authenticity comes from the record signature, and receivers MUST NOT treat the TLS client identity, IP address or any request header as the sender's identity.

## 2. Delivering a record

### 2.1 Request

```
POST {inbox URL}
Content-Type: application/jose
Darep-Recipient: {recipient address}
Content-Length: {octets}

{record bytes}
```

- The method MUST be `POST`.
- `Darep-Recipient` MUST appear exactly once and MUST be one `acct:` address in the form of [Signed records](records.md) E-4, compared as an exact string. It names the recipient address of this delivery ([Delivery contract](delivery.md) §2). A request with no `Darep-Recipient`, more than one, or a value that is not a valid address fails check C1 with `wrong-recipient`. Whether the named address is in the record's `to[]` is checked after the signature verifies (check R12). A single-tenant receiver SHOULD also defer the hosted-address check to R12 so an unauthenticated request cannot probe which addresses exist; a receiver that hosts no address named in `Darep-Recipient` (for example a multi-tenant provider whose pins are scoped per hosted address) MAY return `wrong-recipient` at C1, before signature verification ([Delivery contract](delivery.md) §3.1).
- `Content-Type` MUST be `application/jose` (RFC 7515 § 9.2.1). Parameters are ignored.
- The body MUST be exactly the stored record bytes: the compact JWS, with no leading or trailing whitespace and no line break ([Delivery contract](delivery.md) §7.1). A receiver MUST NOT trim the body. A body with extra bytes fails as `malformed`.
- The sender MUST NOT apply a `Content-Encoding`. A receiver MAY reject any `Content-Encoding` other than `identity` with `unsupported-media-type`.
- The sender SHOULD send `Content-Length`. A receiver MUST stop reading at 65,537 octets and answer `too-large` ([Delivery contract](delivery.md) §3.4), whether or not `Content-Length` was sent.
- The sender MUST NOT send cookies or an `Authorization` header, and the receiver MUST NOT require them. The signature authenticates the record.
- The sender MUST NOT follow redirects (§3).

### 2.2 Success response

```
HTTP/1.1 200 OK
Content-Type: application/jose
Cache-Control: no-store

{receipt bytes}
```

The receipt promises retention until at least `data.storedAt` plus 30 days (D4; [Delivery contract](delivery.md) §4.2). The receiver answers `200` only after the record and the receipt are durably stored ([Delivery contract](delivery.md) §4.1). The body is the compact JWS of the receipt, with no whitespace.

A duplicate delivery gets `200` with the byte-identical receipt stored for the first delivery ([Delivery contract](delivery.md) §6). The binding does not signal whether a delivery was a duplicate.

`200` is the only success status. A sender MUST treat any other `2xx` status, or a `200` whose body is not a receipt that passes [Delivery contract](delivery.md) §7.4, as a receipt mismatch.

### 2.3 Problem responses

A pre-store rejection ([Delivery contract](delivery.md) §5.1) is an `application/problem+json` response (RFC 9457):

```
HTTP/1.1 403 Forbidden
Content-Type: application/problem+json
Cache-Control: no-store

{
  "type": "https://darep.org/problems/unknown-key",
  "title": "Unknown key",
  "status": 403,
  "code": "unknown-key"
}
```

| Member | Required | Value |
|---|---|---|
| `type` | yes | `https://darep.org/problems/` followed by `code`. |
| `code` | yes | One code from the pre-store table of the [code registry](delivery.md#51-pre-store-codes). |
| `status` | yes | The HTTP status from §3. |
| `title` | yes | A short English summary. Informative only. |
| `detail` | no | Human-readable explanation, at most 1,000 Unicode code points. It MUST NOT reveal private policy or whether an address exists beyond what the code already says. |
| `record` | no | The record's `id`. Only allowed when the rejection comes from check R10 or later, so the signature has verified and the envelope is valid, and a receiver never echoes unauthenticated input as an identifier. |

Receivers MUST NOT add other members in Wire v2.

For `rate-limited` and `unavailable`, the receiver SHOULD send `Retry-After` in seconds. For `not-yet-valid`, it MAY send `Retry-After`. The sender MUST NOT retry before the time it states ([Delivery contract](delivery.md) §7.2).

The sender MUST store the status, the headers it relied on, and the problem body as evidence ([Delivery contract](delivery.md) §9.2).

## 3. Status codes

| Status | Codes | Class |
|---|---|---|
| `200` | none (receipt) | success |
| `400` | `malformed`, `bad-header`, `unsupported-alg`, `bad-signature`, `unsupported-version` | permanent |
| `403` | `unknown-key`, `signer-mismatch`, `key-not-valid`, `wrong-recipient` | permanent |
| `405` | `method-not-allowed`. The response MUST include `Allow: POST`. | permanent |
| `409` | `id-conflict` | permanent |
| `413` | `too-large` | permanent |
| `415` | `unsupported-media-type` | permanent |
| `422` | `expired`, `unsupported-extension` | permanent |
| `425` | `not-yet-valid` | transient |
| `429` | `rate-limited` | transient |
| `503` | `unavailable` | transient |

A record whose envelope member `darep` is missing or is not `"2"` gets `unsupported-version` with status `400` ([Records](records.md) E-1).

A receiver MUST use the status listed for each code. `wrong-recipient` uses `403` rather than `421 Misdirected Request`, which describes the case more precisely but is handled poorly by many HTTP clients and proxies.

A request to a URL that is not an inbox gets `404`, with or without a body, and no DAREP code. Answering unknown paths with `wrong-recipient` would reveal that the host runs DAREP.

**Fallback.** A sender classifies a response by its `code` when the body is a problem document with a code from the delivery contract. Otherwise it classifies by status:

- `408`, `425`, `429` and every `5xx` are transient.
- `3xx` is transient. The sender MUST NOT follow the redirect. A redirect usually means a misconfigured inbox URL, which an operator can fix before the record expires.
- Every other `4xx` is permanent. This includes `404` for an inbox URL that does not exist.
- A connection failure, a TLS failure or a timeout is transient.

A transient result can also mean that the record was stored and only the response was lost. Resending the same bytes is safe ([Delivery contract](delivery.md) §6).

## 4. Time limits

A receiver SHOULD answer within 5 seconds. It only verifies and stores; applying happens after the response ([Delivery contract](delivery.md) §3). These limits are recommendations, not requirements, because they depend on deployment. A sender SHOULD wait at least 10 seconds for a complete response before treating the attempt as a timeout. A sender MUST NOT read more than 65,536 octets of any response body.

## 5. Serving the identity document (D2)

### 5.1 In A1: pinned, not fetched

In A1 a receiver resolves every `kid`, and a sender resolves every receipt `kid`, against the identity document it has **pinned** for that address. The pinned copy is obtained out of band, for example by exchanging contact cards. Neither party fetches an identity document to verify a record or a receipt (D2).

A provider SHOULD still serve its identity documents in A1, so that pinned copies can be compared and A2 resolution can be tested. A party that fetches a served document in A1 MUST NOT replace its pinned copy automatically. A changed document is only a signal for the operator.

### 5.2 Response

```
GET https://example.com/.well-known/darep/carol

HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: max-age=300
Access-Control-Allow-Origin: *

{identity document}
```

- The response body is the identity document defined in [Signed records](records.md) §5.1. It contains no inbox URL (§1.1).
- The `id` of the document MUST equal the request URL without query or fragment.
- The server MUST NOT redirect. A client MUST NOT follow a redirect for this resource.
- A key that has expired or been revoked MUST remain in the document with its validity window or revocation time, so that old signatures stay verifiable ([Signed records](records.md) §5.4).
- The server MAY set `Access-Control-Allow-Origin: *` because the document is public. The inbox SHOULD NOT send CORS headers: it is not a browser API.
- An address that does not exist or is private gets `404` with no body. The server MUST answer the same way for both, so that the response does not reveal whether a private address exists.

Network resolution from an address to its identity document (WebFinger, refusal of internal addresses, caching rules) is defined in A2 and is out of scope here.

## 6. Migration from v1

Wire v2 replaces v1 entirely. The v1 path `/federation/events`, the `agent-network-*` `typ` values and the `net.agentnetwork.*` types are not part of this binding (D1). A v2 provider does not need to accept v1 records.

## 7. Deferred items

Media-type registration remains deferred. The identity-document path is provisional under §1.2.

| # | Item | Spec editor | Milestone | State |
|---|---|---|---|---|
| 1 | **Media types.** This binding uses the registered `application/jose` for records and receipts and plain `application/json` for identity documents. Registering specific types such as `application/darep-event+jws` and `application/darep-identity+json` would make `Content-Type` match `typ`, but registration takes time and adds nothing a receiver does not already get from `typ`. | Kyle Hui | A3 | Deferred |
| 2 | **`/.well-known/darep/`.** IANA well-known URI registration is pending. If a different path is needed, follow the migration policy in §1.2. | Kyle Hui | Pending registration | Provisional |

## Errata 2026-11-21

- **§1.2 identity-document path.** Marked the recommendation provisional pending IANA registration and documented migration while preserving existing pinned URLs.

- **§2.1 `Darep-Recipient` hosted-address check.** Aligned with [Delivery contract](delivery.md) §3.1: a receiver that hosts no address named in `Darep-Recipient` (for example a multi-tenant provider whose pins are scoped per hosted address) MAY return `wrong-recipient` at C1, before signature verification.
- **Protocol rename.** Renamed the protocol to DAREP, with `darep-*` `typ` strings and `https://darep.org/` URIs, per the D1 amendment dated 2026-11-21; behavior is unchanged.
- **Envelope version member.** Renamed the record envelope protocol-version member `ack` to `darep`, retaining the value `"2"`, per the D3 amendment dated 2026-11-21.
- **Remaining protocol identifiers.** Renamed the identity-document version member to `darep` (value `"2"`), the well-known path to `/.well-known/darep/<name>`, the inbox path to `/darep/v2/inbox`, and the recipient header to `Darep-Recipient`, per the amendment dated 2026-11-21; behavior is unchanged.
