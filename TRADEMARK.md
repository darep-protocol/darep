# Trademark policy

"DAREP" names this protocol. This policy says how you may use the name. Its goal is that anyone can say truthfully that their software works with DAREP, while nobody can suggest an endorsement they do not have.

Rev.Vision currently holds and stewards the "DAREP" name until a transfer under [GOVERNANCE.md](GOVERNANCE.md). Truthful compatibility claims remain allowed under this policy.

## You may, without asking

- Describe your product, service or library as **"compatible with DAREP"**, **"implements DAREP Wire v2"**, or **"interoperates with DAREP providers"**, when that is true. Conformance means meeting all applicable normative requirements of the claimed version (for example "DAREP Wire v2"), which you must identify. The vectors and runners are verification aids, not a complete conformance determination.
- Use the name to refer to the protocol in articles, documentation, talks, tutorials and comparisons.
- Use the name in the name of a library or tool that implements DAREP, in the form "<your name> for DAREP" or "<your name>-darep", as long as your own name comes first and is distinct.

## You may not

- Imply that the spec editor, Rev.Vision, or any future neutral body endorses, certifies or operates your product, unless they have said so in writing.
- Use "DAREP" alone, or as the leading part, of the name of a product, company, service or domain in a way that suggests it is the official DAREP project.
- Claim compatibility you have not tested, or keep claiming it for a version whose applicable normative requirements your implementation no longer meets.
- Use the name for a modified protocol that is not compatible with the published specification, unless you clearly say it is a modified or experimental variant.

## Conformance kit results

There is no certification program. The [conformance kit](conformance/README.md) is a verification aid: it runs a subset of the normative requirements locally and lists in every report what it does not cover.

If the kit's report says your implementation passes, you may say that it **"passes the DAREP v0.1 conformance kit (verification aid, not certification)"**, when:

- you use that wording, without shortening it;
- you name the roles that were tested (verifier, signer, receiver, sender), the kit version and the spec revision from the report, and link to the report or publish it where you can;
- the run was against the published specification and vectors, without local changes to them.

You may not describe a kit result as certification, compliance, approval or endorsement, for example "DAREP certified" or "officially conformant". A passing kit run is evidence for a compatibility claim under "You may, without asking" above; it does not replace meeting all applicable normative requirements.

## Questions and changes

Ask in an issue in this repository. This policy changes through the process in [GOVERNANCE.md](GOVERNANCE.md), and it moves to the neutral body together with the name. This policy is not legal advice, and it does not grant any right beyond what it says.
