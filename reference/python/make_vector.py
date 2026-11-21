"""Write vectors/handoff-v2.json: a Python-signed Wire v2 handoff and the Python receiver's receipt.

    reference/python/.venv/bin/python reference/python/make_vector.py
    node reference/python/check-vector.mjs

The receipt comes from the real receive pipeline (handle_inbox), not from a hand-built record. The identities are
fresh throwaway test identities under .test; their private keys are discarded. check-vector.mjs verifies both
records with the spec's reference verifier (vectors/v2/records/check.mjs), so Node checks Python's bytes offline.
"""

import json
import tempfile
from pathlib import Path

import mailbox_db
import wire
import work

HERE = Path(__file__).resolve().parent


def main():
    with tempfile.TemporaryDirectory(prefix="darep-vector-") as root:
        root = Path(root)
        mailbox_db.init(root / "c", "acct:carol@python.test", "http://127.0.0.1:4713")
        mailbox_db.init(root / "b", "acct:bob@python.test", "http://127.0.0.1:4714")
        carol, bob = mailbox_db.Mailbox(root / "c"), mailbox_db.Mailbox(root / "b")
        carol.trust(bob.card)
        bob.trust(carol.card)
        now = carol.now()
        record = wire.envelope(
            carol.owner, work.HANDOFF, [bob.owner],
            {"summary": "Python 簽署的交接 🗓", "nextStep": "Check the label «één».", "expectedResult": "One clear answer."},
            now, grant={"id": "grant-vector", "actor": "agent"}, required=[work.WORK],
        )
        kid, key = carol.signing_key("record", now)
        # Indented on purpose: verifiers must use the bytes as sent (NC1).
        payload = json.dumps(record, ensure_ascii=False, indent=2).encode() + b"\n"
        event = wire.sign(payload, key, kid, wire.TYP_EVENT)
        status, _, receipt = bob.handle_inbox(
            "POST", {"content-type": ["application/jose"], "darep-recipient": [bob.owner]}, event.encode()
        )
        assert status == 200, receipt
        vector = {
            "description": "Python-signed Wire v2 handoff and the Python receiver's storage receipt. TEST ONLY.",
            "generator": "reference/python/make_vector.py",
            "identities": [carol.document, bob.document],
            "event": {
                "jws": event,
                "payloadUtf8": payload.decode(),
                "payloadSha256": wire.digest(payload),
                "context": {"mode": "admission", "now": record["time"], "receiver": bob.owner,
                            "typ": wire.TYP_EVENT, "understood": list(work.UNDERSTOOD)},
            },
            "receipt": {
                "jws": receipt.decode(),
                "context": {"mode": "admission", "now": record["time"], "receiver": carol.owner,
                            "typ": wire.TYP_RECEIPT, "understood": [], "answered": event},
            },
        }
    out = HERE / "vectors" / "handoff-v2.json"
    out.write_text(json.dumps(vector, ensure_ascii=False, indent=2) + "\n")
    print("wrote", out)


if __name__ == "__main__":
    main()
