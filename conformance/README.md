# DAREP conformance kit

A local tool that tells you how far your implementation of DAREP Wire v2 conforms, before you talk to anyone else's.

It is a **verification aid, not certification**. A passing run supports the statement "passes the DAREP v0.1 conformance kit (verification aid, not certification)" for the roles it tested, and nothing more. Conformance means meeting all applicable normative requirements; every report lists the requirements this kit does not test.

Everything runs on your machine, on loopback. There is no public test server: Wire v2 has no discovery, so both sides of a test pin each other explicitly, and the kit writes that configuration for you.

## What it runs

| Mode | What happens | Roles |
|---|---|---|
| `offline` | The [records vectors](../vectors/v2/records/README.md) and [delivery vectors](../vectors/v2/delivery/README.md), through your adapter, with the vector's clock injected. Your receiver's inbox gets real HTTP requests; your sender talks to a scripted endpoint. | verifier, signer, receiver, sender |
| `live` | A local DAREP peer (the Node reference provider, with a fresh test identity) and two fault-injecting proxies exchange real deliveries with your running implementation, in both directions: the happy path, byte-identical and re-signed retries, `id-conflict`, wrong recipient, bad signature, unknown key, too large, expired, not yet valid, unsupported extension, problem+json shapes, a signed rejection record after storage, dropped acknowledgements with a restart, `Retry-After`, a permanent rejection, a mismatched receipt, and a received rejection record. Only `core/v2#message` is used. | receiver, sender |

Each signed object your implementation produces is judged by the spec's own reference verifier, [`vectors/v2/records/check.mjs`](../vectors/v2/records/check.mjs). The experimental `work/v2` scenarios run only with `--experimental` and are reported separately; they never affect the result (D8).

## Quickstart

You need Node.js 22.18 or later and a clone of this repository.

**1. Install.** From the repository root:

```bash
npm ci
```

```bash
npm ci --prefix reference/node
```

The second command installs the Node reference provider. Its adapter uses it, and so does live mode, whose kit peer is that provider. Testing your own implementation offline needs only the first command.

**2. See a passing run.** The reference implementations ship with adapters:

```bash
npx darep-conformance offline --adapter node-reference
```

The Python peer needs [uv](https://docs.astral.sh/uv/) and Python 3.11 or later:

```bash
uv sync --locked --project reference/python --extra agent
```

```bash
npx darep-conformance all --adapter python-reference
```

**3. Write an adapter for your implementation.** An adapter is a small program that reads JSON requests on stdin and answers on stdout, in any language. It translates operations such as "verify this record", "reset with these pins" or "send a message" into calls to your code. [ADAPTER.md](ADAPTER.md) is the contract; [`adapters/node/adapter.js`](adapters/node/adapter.js) and [`adapters/python/adapter.py`](adapters/python/adapter.py) are complete examples. Start with the roles you have: a verifier needs only `describe`, `verify` and `validateIdentity`.

**4. Run it against your implementation.**

```bash
npx darep-conformance offline --adapter "python3 path/to/my_adapter.py" --roles verifier
```

```bash
npx darep-conformance all --adapter "./my-adapter"
```

**5. Read the report.** The kit prints a summary and writes `darep-conformance-report/report.md` and `report.json` (change the directory with `--out`), plus `adapter.log` and, for live mode, `live-pins.json`. The exit status is 0 when the run passes, 1 when it does not, and 2 for a usage or setup error.

## Reading the report

The report states:

- **the result**: "Passes the DAREP v0.1 conformance kit (verification aid, not certification)" when no core case failed, or "Does not pass …";
- **the scope**: the roles tested (verifier, signer, receiver, sender), the modes, and the subset. Only the core subset decides the result. A role is in scope only if none of its required cases was skipped; cases that need an optional adapter operation (such as `fault`) may be skipped. A run against a checkout whose `spec/` or `vectors/` were changed locally gives no result;
- **the revision**: the spec label, the git tag, describe output and commit of the checkout the kit ran from, and whether `spec/` or `vectors/` were modified locally, plus the kit version;
- **every case** with its status, spec references and details: `pass`, `fail`, `skip` (your adapter does not support what the case needs), or `advisory` (a SHOULD-level expectation that was not met, which never fails a run);
- **traceability**: each case cites the clauses it checks (for example `delivery.md §6` or `records.md TA-2`). A case marked `vector-only` checks a rule that only a vector implies, with no published normative text behind it (today: the experimental `work/v2` scenarios); its result says nothing about conformance;
- **requirements not covered**: what passing the kit does not show, such as retention for 30 days, power-loss durability, TLS, identity-document serving and key rotation.

If you state the result publicly, use the exact wording above together with the kit version, the roles and the spec revision, and link to the report if you can. See [TRADEMARK.md](../TRADEMARK.md#conformance-kit-results). Do not call it certification, compliance or endorsement.

## Options

```
darep-conformance <offline|live|all> --adapter <command|node-reference|python-reference>
  --roles verifier,signer,receiver,sender   test only these roles (default: all the adapter declares)
  --experimental                            include the experimental work/v2 delivery scenarios
  --out DIR                                 report directory (default ./darep-conformance-report)
  --patience SECONDS                        live mode: longest wait for an expected event (default 120)
```

## Limits worth knowing

- Live mode runs on loopback `http`, which the HTTPS binding allows for local testing only (https-binding.md §1.3). It does not test TLS.
- Live mode takes about 30 seconds against the reference implementations, because it waits for real retries. The spec sets only minimum delays, so the kit waits up to `--patience` seconds (default 120) for each expected retry, apply outcome or rejection record; a failure that says "not observed within N s" may mean your schedule is slower, so raise it. Only the first retries of your backoff schedule are observed.
- A restart in live mode restarts your process; it cannot simulate a power loss.
- The kit tests what it can observe. A conformant implementation must also meet the requirements the report lists as not covered.
- Found a case where the kit or a vector seems to contradict the spec? Open an issue. The spec text wins over the kit.

## Kit development

```bash
npm test --workspace conformance
```

The self-test runs the kit against the Node reference adapter and against [deliberately broken variants](test/mutant-adapter.js) of it, to show that the checks can fail.
