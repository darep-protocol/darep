# Governance

This document says who decides what goes into the DAREP specification, how a change is made, and where DAREP is headed.

## Spec editor

The specification has one named editor: **Kyle Hui**, for Rev.Vision.

The editor:

- keeps the specification, the test vectors and the decision record consistent with each other;
- runs the change process below in public and records each decision;
- merges editorial changes and decides normative ones after public review;
- can name additional editors. A change in editors is announced in this file and in [CHANGELOG.md](CHANGELOG.md).

The editor also operates a commercial hosted DAREP provider. The specification gives no provider, including that one, any privilege on the wire. A proposal that would favor one provider over others is reviewed on that basis.

## Change process

The change process happens in the open, in this repository's issues and pull requests, except for embargoed security handling under [SECURITY.md](SECURITY.md).

1. **Editorial changes** (typos, broken links, clearer wording that does not change meaning) go straight to a pull request. The editor merges them.
2. **Normative changes** start as an issue that states the problem, the proposed text, and whether the change touches signed bytes. The issue stays open for public comment for at least 14 days before the editor decides, unless the change fixes a security problem.
3. **Decisions.** An accepted normative change is recorded as a new decision with an ID, a rationale and what it constrains, in the decision record (for Wire v2: [spec/decisions-wire-v2.md](spec/decisions-wire-v2.md)). An accepted decision changes only through a new decision that names the one it supersedes. The editor gives the reason for every acceptance or rejection in the issue.
4. **Vectors and implementations.** A normative change is complete only when the test vectors cover it and both reference implementations pass every vector that applies to them.
5. **Versions.** Wire v2 is frozen. Any change to a string inside signed bytes is a breaking change and starts a new wire version. Errata that clarify the frozen text without changing what conforms are published as dated errata and listed in [CHANGELOG.md](CHANGELOG.md).
6. **Security reports** follow [SECURITY.md](SECURITY.md), including private reporting and coordinated disclosure.

## Commitment to a neutral body

**Rev.Vision is the current steward.** It holds the DAREP name, `darep.org`, the `darep-protocol` GitHub organisation, and stewardship of the specification.

The transition trigger is at least two independently built **and** independently operated production providers, built and operated by different organisations, demonstrably interoperating. The trigger must be supported by public interop evidence, such as a passing cross-provider exchange.

Within 90 days of that trigger, Rev.Vision will publish a transition proposal naming a candidate neutral body, such as a foundation or standards organisation. Transfer happens when a suitable neutral body accepts custody. Until then, the current editor and change process continue as interim governance. If no body accepts, Rev.Vision keeps stewardship, repeats the search at least yearly, and publishes status.

The transfer covers stewardship of the specification, the decision record and test vectors; the repository; `darep.org`; and the DAREP name. Contributors retain copyright in their contributions under the existing licenses. Those licenses remain in place and cannot be withdrawn from what is already published.

## Listing a provider

The README lists hosted providers neutrally, in the order they were added. To add yours, open a pull request that adds its name. A listing is a factual statement that the provider exists; it is not an endorsement or a certification. A provider that claims compatibility follows [TRADEMARK.md](TRADEMARK.md).
