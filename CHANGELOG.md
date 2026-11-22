# Changelog

## Unreleased

Tooling only; the specification and vectors are unchanged.

- Conformance kit 0.1.0 in [`conformance/`](conformance/README.md), run as `npx darep-conformance`: offline vectors through a language-neutral adapter contract, live loopback deliveries in both directions through fault-injecting proxies, JSON and Markdown reports, and adapters for both reference implementations. A verification aid, not certification; [TRADEMARK.md](TRADEMARK.md#conformance-kit-results) says how a passing result may be stated.

## v0.1.1 (unreleased)

Clarifications and editorial fixes only; Wire v2 conformance is unchanged.

- #18: Clarify URI-slot query/fragment rules and `unknown-key` resolution failures.
- #19: Explain explicit local test-only IPv4 policy and test enabled/disabled URI parsing.
- #20: Distinguish receipt signing-time obligations from verifier checks.
- #21: Separate mandatory retry bounds from SHOULD-level doubling profile expectations.
- #22: Exercise recognized problem-code precedence over conflicting HTTP statuses.
- #23: Isolate the multi-recipient receipt source check with a valid receipt from another recipient.
- #24: Qualify the deterministic failure-order explanation by its existing exceptions.
- #25: Document both test-key schemas and equivalent loaders into a common normalized view.

## Spec v0.1 = DAREP Wire v2 (frozen), 2026-11-21

The first public release of the specification, the test vectors and the two reference implementations.

**Specification** ([spec/](spec/))

- [Signed records](spec/records.md): ES256 compact JWS over the exact payload bytes with no canonicalization (NC1); `typ` values `darep-event+jws`, `darep-receipt+jws` and `darep-rejection+jws`; `kid` as the HTTPS URL of an identity document plus a fragment (D2), resolved against pinned identity documents; the envelope with its `darep: "2"` version member (D3) and `grant: {id, actor}` slot (D5); extension IDs under `https://darep.org/ext/`; the numbered verification procedure.
- [Delivery contract](spec/delivery.md): verify → store → acknowledge → apply. A receipt means the record bytes were durably stored, nothing more (D4). Deduplication, out-of-order handling, retries with the same bytes, and a two-tier rejection model: pre-store problem responses and post-store signed rejection records (D6). Evidence retention.
- [HTTPS binding](spec/https-binding.md): the inbox `POST /darep/v2/inbox` with the `Darep-Recipient` header, identity documents at the provisional path `/.well-known/darep/<name>`, status codes and `application/problem+json`.
- [Decision record](spec/decisions-wire-v2.md): D1–D8 and NC1, with the 2026-11-21 amendments and errata.

**Vectors** ([vectors/v2/](vectors/v2/)): 65 signed-record vectors and 90 identity-pin cases, plus receiver and sender delivery scenarios. Generators are deterministic.

**Implementations** ([reference/](reference/)): the Node.js reference provider and the Python peer. Both pass every vector that applies to them. The Python peer implements the core plus the message and handoff types (D8); experimental reschedule is Node-only. Work and reschedule semantics are outside frozen Wire v2 conformance.

**Repository**: Apache-2.0 for code and the specification, CC-BY-4.0 for explanatory documents, DCO sign-off, governance and trademark policy.

**Pre-publication corrections (2026-11-21):** completed P-0 pin checks and HTTP method/identity responses with regression tests; clarified conformance, experimental extensions, rejection ordering and `storedAt` retention; marked the well-known path provisional. Updated governance, private security reporting, licensing notices, copy-paste instructions and CI DCO enforcement. See the dated errata in each specification document and the D4/D8 amendments.
