# Contributing

Thank you for helping with DAREP.

## Licenses

- Code, test vectors and the specification in `spec/` are licensed under the [Apache License 2.0](LICENSE).
- The explanatory documents listed in [LICENSE-docs](LICENSE-docs) are licensed under CC-BY-4.0.

By contributing, you agree that your contribution is licensed under the license that covers the file you change. There is **no copyright assignment** and no contributor license agreement: you keep the copyright in your contribution.

## Developer Certificate of Origin (DCO)

Every commit must be signed off under the [Developer Certificate of Origin 1.1](https://developercertificate.org/). The sign-off certifies that you wrote the change, or otherwise have the right to submit it under the project's licenses.

Sign off with `-s`:

```bash
git commit -s -m "Describe the change"
```

This adds a trailer with your name and email:

```text
Signed-off-by: Your Name <you@example.com>
```

To sign off commits you already made on your branch:

```bash
git rebase --signoff origin/main
```

Pull requests with commits that lack a `Signed-off-by` trailer are not merged.

## Before you open a pull request

Run the checks in the [README](README.md#run-the-vectors-and-tests). CI runs the same ones. A change to a generator must leave `npm run vectors:generate` byte-for-byte deterministic.

## Spec changes

Spec changes follow the change process in [GOVERNANCE.md](GOVERNANCE.md). In short:

- Editorial fixes (typos, broken links, clearer wording with no change in meaning) can go straight to a pull request.
- A normative change opens an issue first. A change that contradicts an accepted decision in [spec/decisions-wire-v2.md](spec/decisions-wire-v2.md) must propose a new decision that names the one it supersedes.
- Wire v2 is frozen. Any change to a string inside signed bytes is a breaking change and belongs to a new wire version.
