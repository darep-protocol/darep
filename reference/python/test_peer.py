import ipaddress
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import mailbox_db
import pairing
import peer
import run_vectors
import wire
import work
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def bound_ports(count):
    reserved = []
    try:
        for _ in range(count):
            s = socket.socket()
            s.bind(("127.0.0.1", 0))
            reserved.append(s)
        return [s.getsockname()[1] for s in reserved]
    finally:
        for s in reserved:
            s.close()


def tls_files(root):
    ca_key = ec.generate_private_key(ec.SECP256R1())
    key = ec.generate_private_key(ec.SECP256R1())
    at = datetime.now(timezone.utc)
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DAREP unit-test CA")])

    def builder(subject, pub):
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(pub)
            .serial_number(x509.random_serial_number())
            .not_valid_before(at - timedelta(minutes=1))
            .not_valid_after(at + timedelta(hours=1))
        )

    ca = (
        builder(issuer, ca_key.public_key())
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    leaf = (
        builder(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]), key.public_key())
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    for file, cert in [("ca.pem", ca), ("leaf.pem", leaf)]:
        (root / file).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (root / "leaf.key").write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )


class VectorTests(unittest.TestCase):
    """Every applicable vector in vectors/v2/records and vectors/v2/delivery (D8)."""

    def test_pin_validity_at_epoch_and_unknown_members(self):
        doc = run_vectors.load(run_vectors.RECORDS / "identities.json")["documents"][0]
        doc["extra"] = {"informational": True}
        doc["keys"] = [doc["keys"][0]]
        doc["keys"][0].update(validFrom="1960-01-01T00:00:00Z", validUntil="1970-01-01T00:00:00Z",
                              revoked="1959-01-01T00:00:00Z", extra=True)
        self.assertEqual(wire.validate_document(doc), doc)

    def test_wire_v2_vectors(self):
        if not run_vectors.VECTORS.is_dir():
            self.skipTest("vectors/v2 is not in this tree")
        skipped = []
        for name, case in run_vectors.all_cases():
            with self.subTest(vector=name):
                result = case()
                if result.startswith("SKIP"):
                    skipped.append((name, result))
        # Every vector in the tree is core or handoff/message today, so nothing may be skipped silently.
        self.assertEqual(skipped, [])


def http_transport(receiver):
    """Deliver through the receiver's binding entry point, in process, as the HTTPS handler would."""

    def send(url, body, headers):
        status, rheaders, rbody = receiver.handle_inbox("POST", {k.lower(): [v] for k, v in headers.items()}, body)
        if status == 200:
            receiver.apply_ready()  # as peer.Handler does, after the response
        return status, {k.lower(): v for k, v in rheaders.items()}, rbody

    return send


class PeerTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="agent-peer-test-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.a, self.b, self.c = [self.owner(n, p) for n, p in zip(("a", "b", "c"), bound_ports(3))]
        self.action = {"kind": "handoff", "summary": "已核准的摘要", "nextStep": "查看", "expectedResult": "回覆"}

    def owner(self, name, port, scheme="http"):
        folder = self.root / name
        mailbox_db.init(folder, "acct:" + name + "@" + name + ".test", f"{scheme}://127.0.0.1:{port}")
        return mailbox_db.Mailbox(folder)

    def grant(self, box, verbs=("read", "send", "commit")):
        return "Bearer " + box.grant(list(verbs), 1)["token"]

    def paired(self):
        self.a.trust(self.b.card)
        self.b.trust(self.a.card)

    @contextmanager
    def rejects(self, status):
        with self.assertRaises(mailbox_db.Problem) as raised:
            yield
        self.assertEqual(raised.exception.status, status)

    def signed(self, sender, record, key_purpose="record", typ=wire.TYP_EVENT, payload=None):
        kid, key = sender.signing_key(key_purpose, sender.now())
        return wire.sign(payload if payload is not None else wire.serialize(record), key, kid, typ)

    def opening(self, sender=None, recipient=None):
        sender, recipient = sender or self.a, recipient or self.b
        return wire.envelope(sender.owner, work.HANDOFF, [recipient.owner],
                             {k: v for k, v in self.action.items() if k != "kind"}, sender.now(),
                             grant={"id": "grant-test", "actor": "agent"}, required=[work.WORK])

    def post(self, receiver, jws, recipient=None):
        headers = {"content-type": ["application/jose"], "darep-recipient": [recipient or receiver.owner]}
        result = receiver.handle_inbox("POST", headers, jws.encode())
        if result[0] == 200:
            receiver.apply_ready()
        return result

    def flush(self, sender, receiver):
        for _ in range(10):  # a later record of a thread waits for the earlier one (§8.1)
            rows = sender.due()
            if not rows:
                return
            for row in rows:
                peer.attempt(sender, row, http_transport(receiver))

    def test_identity_document_and_card(self):
        doc = self.a.card["identity"]
        wire.validate_document(doc)
        self.assertEqual(doc["id"], "https://a.test/.well-known/darep/a")
        self.assertEqual({tuple(k["purpose"]) for k in doc["keys"]}, {("record",), ("provider",)})
        self.assertEqual(self.a.card["inbox"].split("/", 3)[3], "darep/v2/inbox")
        with self.rejects(400):
            self.a.trust({**self.b.card, "identity": {**self.b.card["identity"], "darep": "1"}})
        self.a.trust(self.b.card)
        stolen = {**self.c.card, "identity": {**self.c.card["identity"], "addresses": [self.b.owner]}}
        with self.rejects(409):
            self.a.trust(stolen)  # TA-4: one address, one pinned document

    def test_exact_bytes_dedupe_and_receipts_survive_restart(self):
        self.paired()
        record = self.opening()
        token = self.signed(self.a, record)
        status, _, first = self.post(self.b, token)
        self.assertEqual(status, 200)
        self.b = mailbox_db.Mailbox(self.root / "b")
        self.assertEqual(self.post(self.b, token)[2], first)
        # Re-signed, same payload bytes: still a duplicate, still the stored receipt.
        self.assertEqual(self.post(self.b, self.signed(self.a, record))[2], first)
        receipt = wire.verify_record(first.decode(), [wire.TYP_RECEIPT], wire.Pins([self.b.document]), mode="evidence",
                                     answered=token)
        self.assertEqual(receipt.record["data"]["sha256"], wire.digest(wire.payload_bytes(token)))
        indented = json.dumps(record, ensure_ascii=True, indent=1).encode()
        status, _, problem = self.post(self.b, self.signed(self.a, record, payload=indented))
        self.assertEqual((status, json.loads(problem)["code"]), (409, "id-conflict"))
        with self.b.connection() as db:
            rows = db.execute("SELECT jws,receipt FROM records WHERE direction='in'").fetchall()
        self.assertEqual([(r["jws"], r["receipt"]) for r in rows], [(token, first.decode())])

    def test_outgoing_record_is_signed_once_and_resent_as_same_bytes(self):
        self.paired()
        auth = self.grant(self.a)
        self.a.allow({"peer": self.b.owner, "action": self.action})
        args = {"peer": self.b.owner, "requestKey": "once", **{k: v for k, v in self.action.items() if k != "kind"}}
        self.a.tool("request_handoff", args, auth)
        sent = []

        def flaky(url, body, headers):
            sent.append(body)
            if len(sent) < 3:
                raise ConnectionResetError("dropped")
            return http_transport(self.b)(url, body, headers)

        for _ in range(3):
            row = self.a.due()[0] if self.a.due() else None
            if row is None:
                with self.a.connection(True) as db:
                    db.execute("UPDATE deliveries SET next_at=0")
                row = self.a.due()[0]
            peer.attempt(self.a, row, flaky)
        self.assertEqual(len(sent), 3)
        self.assertEqual(len(set(sent)), 1)
        with self.a.connection() as db:
            d = db.execute("SELECT * FROM deliveries").fetchone()
            attempts = db.execute("SELECT result FROM attempts ORDER BY id").fetchall()
        self.assertEqual(d["status"], "delivered")
        self.assertEqual([a["result"] for a in attempts], ["transient", "transient", "delivered"])

    def test_grants_use_verbs_and_close_instead_of_delete(self):
        self.paired()
        args = {"peer": self.b.owner, "requestKey": "one", **{k: v for k, v in self.action.items() if k != "kind"}}
        cap = self.a.grant(["read", "send"], 1)
        auth = "Bearer " + cap["token"]
        self.a.allow({"peer": self.b.owner, "action": self.action})
        with self.rejects(403):
            self.a.tool("request_handoff", {**args, "summary": "unapproved"}, auth)
        with self.rejects(403):
            self.a.tool("request_handoff", args, self.grant(self.a, ("read",)))
        opened = self.a.tool("request_handoff", args, auth)
        self.assertEqual(self.a.tool("request_handoff", args, auth)["threadId"], opened["threadId"])
        with self.rejects(403):
            self.a.tool("request_handoff", {**args, "requestKey": "another"}, auth)
        record = opened["history"][0]["record"]
        self.assertEqual(record["grant"], {"id": cap["id"], "actor": "agent"})
        self.a.revoke(cap["id"])
        with self.rejects(401):
            self.a.tool("list_handoffs", {}, auth)
        with self.a.connection() as db:
            grant = db.execute("SELECT closed_at,close_reason FROM grants WHERE id=?", (cap["id"],)).fetchone()
            approval = db.execute("SELECT close_reason,used_by FROM approvals").fetchone()
        self.assertEqual(grant["close_reason"], "revoked")
        self.assertEqual((approval["close_reason"], approval["used_by"]), ("used", record["id"]))
        # Accepting binds the owner: send alone is not enough (PV-3).
        self.flush(self.a, self.b)
        tid = opened["threadId"]
        head = self.b.tool("get_handoff", {"threadId": tid}, self.grant(self.b))["head"]
        with self.rejects(403):
            self.b.tool("respond_handoff", {"threadId": tid, "expectedHead": head, "action": {"kind": "accept"}},
                        self.grant(self.b, ("read", "send")))
        accepted = self.b.tool("respond_handoff", {"threadId": tid, "expectedHead": head, "action": {"kind": "accept"}},
                               self.grant(self.b, ("read", "commit")))
        self.assertEqual(accepted["status"], "accepted")

    def test_pre_store_codes_and_post_store_signed_rejections(self):
        self.paired()
        record = self.opening()

        def code(jws, recipient=None):
            status, _, body = self.post(self.b, jws, recipient)
            return status, json.loads(body)["code"] if status != 200 else "receipt"

        self.assertEqual(record["darep"], "2")
        without_version = {k: v for k, v in record.items() if k != "darep"}
        for invalid in (without_version, {**record, "darep": "9"}, {**without_version, 'ack': "2"}):
            self.assertEqual(code(self.signed(self.a, invalid)), (400, "unsupported-version"))
        # The old envelope member is not allowed alongside darep either.
        self.assertEqual(code(self.signed(self.a, {**record, 'ack': "2"})), (400, "malformed"))
        self.assertEqual(code(self.signed(self.c, record)), (403, "unknown-key"))
        self.b.trust(self.c.card)
        self.assertEqual(code(self.signed(self.c, record)), (403, "signer-mismatch"))
        self.assertEqual(code(self.signed(self.a, {**record, "to": [self.c.owner]})), (403, "wrong-recipient"))
        self.assertEqual(code(self.signed(self.a, record), self.c.owner), (403, "wrong-recipient"))
        real_clock = self.b.clock
        self.b.clock = lambda: real_clock() + 8 * 24 * 3600 * 1000
        self.assertEqual(code(self.signed(self.a, record)), (422, "expired"))
        self.b.clock = real_clock
        self.assertEqual(code(self.signed(self.a, record, key_purpose="provider")), (403, "key-not-valid"))
        self.assertEqual(code(self.signed(self.a, {**record, "required": ["https://x.test/ext/escrow/v1"]})),
                         (422, "unsupported-extension"))
        # Reply before the opening: stored, acked, pending; the opening releases it.
        accept = wire.envelope(self.a.owner, work.ACCEPT, [self.b.owner], {}, self.a.now(), thread=record["id"],
                               in_reply_to=record["id"], grant={"id": "g", "actor": "agent"})
        self.assertEqual(code(self.signed(self.a, accept)), (200, "receipt"))
        self.assertEqual(code(self.signed(self.a, record)), (200, "receipt"))
        with self.b.connection() as db:
            outcomes = dict(db.execute("SELECT rid,outcome_code FROM records WHERE direction='in'").fetchall())
            rejection = db.execute("SELECT * FROM records WHERE direction='out' AND typ=?",
                                   (wire.TYP_REJECTION,)).fetchone()
        # A accepting its own handoff is the wrong turn: refused after storage, with a signed rejection to A.
        self.assertEqual(outcomes, {accept["id"]: "wrong-turn", record["id"]: None})
        r = wire.verify_record(rejection["jws"], [wire.TYP_REJECTION], wire.Pins([self.b.document]), mode="evidence",
                               answered=self.signed(self.a, accept))
        self.assertEqual((r.record["data"]["code"], r.record["inReplyTo"], "grant" in r.record),
                         ("wrong-turn", accept["id"], False))

    def test_rejection_record_reaches_the_sender_and_marks_the_delivery_refused(self):
        self.paired()
        tid = self.open_thread()
        head = self.b.tool("get_handoff", {"threadId": tid}, self.grant(self.b))["head"]
        self.b.tool("respond_handoff", {"threadId": tid, "expectedHead": head, "action": {"kind": "accept"}},
                    self.grant(self.b))
        # A answers the opening after B already accepted it: the head moved, so B refuses it as stale.
        stale = wire.envelope(self.a.owner, work.DECLINE, [self.b.owner], {}, self.a.now(), thread=tid,
                              in_reply_to=tid, grant={"id": "g", "actor": "agent"})
        with self.a.connection(True) as db:
            self.a.store_outgoing(db, self.signed(self.a, stale), self.a.now())
        self.flush(self.b, self.a)
        self.flush(self.a, self.b)
        self.flush(self.b, self.a)
        with self.a.connection() as db:
            d = db.execute("SELECT d.* FROM deliveries d JOIN records r USING(seq) WHERE r.rid=?",
                           (stale["id"],)).fetchone()
        self.assertEqual((d["status"], d["refused_code"]), ("delivered", "stale-head"))

    def open_thread(self, sender=None, recipient=None):
        sender, recipient = sender or self.a, recipient or self.b
        sender.allow({"peer": recipient.owner, "action": self.action})
        args = {"peer": recipient.owner, "requestKey": "open-" + recipient.owner[5:6],
                **{k: v for k, v in self.action.items() if k != "kind"}}
        tid = sender.tool("request_handoff", args, self.grant(sender))["threadId"]
        self.flush(sender, recipient)
        return tid

    def test_full_handoff_lifecycle_and_unknown_type(self):
        self.paired()
        tid = self.open_thread()
        b_auth, a_auth = self.grant(self.b), self.grant(self.a)
        state = self.b.tool("get_handoff", {"threadId": tid}, b_auth)
        self.assertEqual((state["status"], state["turn"]), ("requested", self.b.owner))
        accepted = self.b.tool("respond_handoff", {"threadId": tid, "expectedHead": state["head"],
                                                   "action": {"kind": "accept"}}, b_auth)
        result = {"kind": "complete", "result": "做好了"}
        with self.rejects(403):
            self.b.tool("respond_handoff", {"threadId": tid, "expectedHead": accepted["head"], "action": result}, b_auth)
        self.b.allow({"peer": self.a.owner, "threadId": tid, "action": result})
        done = self.b.tool("respond_handoff", {"threadId": tid, "expectedHead": accepted["head"], "action": result}, b_auth)
        self.flush(self.b, self.a)
        final = self.a.tool("get_handoff", {"threadId": tid}, a_auth)
        self.assertEqual((final["status"], final["head"], final["result"]), ("completed", done["head"], "做好了"))
        self.assertEqual([h["kind"] for h in final["history"]], ["handoff", "accept", "complete"])
        self.assertTrue(all(h["delivery"] in ("delivered", "received") for h in final["history"]))
        unknown = wire.envelope(self.a.owner, "https://x.test/ext/poll/v1#vote", [self.b.owner], {"x": 1}, self.a.now(),
                                grant={"id": "g", "actor": "owner"})
        self.assertEqual(self.post(self.b, self.signed(self.a, unknown))[0], 200)
        with self.b.connection() as db:
            row = db.execute("SELECT outcome,outcome_code FROM records WHERE rid=?", (unknown["id"],)).fetchone()
        self.assertEqual((row["outcome"], row["outcome_code"]), ("unsupported", "unsupported-type"))

    def test_owner_message_type(self):
        self.paired()
        sent = self.a.message(self.b.owner, "你好 👋")
        self.flush(self.a, self.b)
        listed = self.b.tool("list_messages", {}, self.grant(self.b))["messages"]
        self.assertEqual([(m["record"]["data"]["text"], m["record"]["grant"]["actor"], m["outcome"]) for m in listed],
                         [("你好 👋", "owner", "applied")])
        self.assertEqual(listed[0]["record"]["id"], sent["id"])
        with self.a.connection() as db:
            act = db.execute("SELECT id FROM owner_acts").fetchone()
        self.assertEqual(listed[0]["record"]["grant"]["id"], act["id"])

    def test_pairing_pins_only_after_both_owners_approve(self):
        offer = pairing.invite(self.a)["code"]
        ai, bi = pairing.fingerprint(self.a.card), pairing.fingerprint(self.b.card)
        self.assertEqual(pairing.inspect(self.b, offer)["fingerprint"], ai)
        with self.rejects(400):
            pairing.approve(self.b, offer, "unverified")
        answer = pairing.approve(self.b, offer, ai)["code"]
        self.assertEqual(pairing.approve(self.b, offer, ai)["code"], answer)
        with self.rejects(404):
            self.b.contact(self.a.owner)
        with self.rejects(403):
            pairing.inspect(self.c, answer)
        finish = pairing.approve(self.a, answer, bi)["code"]
        self.assertEqual(pairing.approve(self.a, answer, bi)["code"], finish)
        with self.rejects(404):
            self.b.contact(self.a.owner)
        other_answer = pairing.approve(self.c, offer, ai)["code"]
        with self.rejects(409):
            pairing.approve(self.a, other_answer, pairing.fingerprint(self.c.card))
        self.assertEqual(pairing.approve(self.b, finish, ai)["phase"], "paired")
        self.assertEqual(pairing.approve(self.b, finish, ai)["phase"], "paired")
        with self.rejects(409):
            pairing.approve(self.b, offer, ai)
        self.assertEqual(self.a.contact(self.b.owner), self.b.card)
        self.assertEqual(self.b.contact(self.a.owner), self.a.card)
        with patch("pairing.time.time", return_value=time.time() + 1000):
            with self.rejects(410):
                pairing.inspect(self.b, offer)

    def test_unverified_success_is_queued_and_permanent_failure_is_visible(self):
        self.paired()
        self.a.trust(self.c.card)
        auth = self.grant(self.a)
        self.a.allow({"peer": self.c.owner, "action": self.action})
        args = {"peer": self.c.owner, "requestKey": "send", **{k: v for k, v in self.action.items() if k != "kind"}}
        tid = self.a.tool("request_handoff", args, auth)["threadId"]
        row = self.a.due()[0]
        self.assertEqual(peer.attempt(self.a, row, lambda *_: (200, {"content-type": "application/jose"}, b"unsigned")),
                         "receipt-mismatch")

        def current():
            return self.a.tool("get_handoff", {"threadId": tid}, auth)["history"][0]

        self.assertEqual((current()["delivery"], current()["attempts"], current()["deliveryError"]),
                         ("queued", 1, "malformed"))
        problem = b'{"type":"https://darep.org/problems/unknown-key","title":"x","status":403,"code":"unknown-key"}'
        peer.attempt(self.a, row, lambda *_: (403, {"content-type": "application/problem+json"}, problem))
        self.assertEqual((current()["delivery"], current()["attempts"], current()["deliveryError"]),
                         ("failed", 2, "unknown-key"))

    def test_http_binding_statuses_and_identity_document(self):
        server = peer.Server(("127.0.0.1", 0), peer.Handler)
        server.store = self.b
        import threading

        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = "http://127.0.0.1:" + str(server.server_address[1])
        with urllib.request.urlopen(base + "/.well-known/darep/b") as res:
            self.assertEqual(json.loads(res.read()), self.b.document)
        import http.client

        for method in ("OPTIONS", "TRACE", "CONNECT"):
            with self.subTest(method=method):
                conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
                try:
                    conn.request(method, "/darep/v2/inbox")
                    response = conn.getresponse()
                    self.assertEqual(response.status, 405)
                    self.assertEqual(response.getheader("Allow"), "POST")
                    self.assertEqual(response.getheader("Content-Type"), "application/problem+json")
                    problem = json.loads(response.read())
                    self.assertEqual(problem["code"], "method-not-allowed")
                    self.assertEqual(problem["status"], 405)
                    self.assertEqual(problem["type"], "https://darep.org/problems/method-not-allowed")
                finally:
                    conn.close()
        status, headers, body = peer.post(base + "/darep/v2/inbox", b"A" * 65_537,
                                          {"Content-Type": "application/jose", "Darep-Recipient": self.b.owner})
        self.assertEqual((status, json.loads(body)["code"]), (413, "too-large"))
        status, headers, body = peer.post(base + "/darep/v2/inbox", b"x.y.z",
                                          {"Content-Type": "application/jose", "Darep-Recipient": self.b.owner,
                                           "Content-Encoding": "gzip"})
        self.assertEqual((status, json.loads(body)["code"]), (415, "unsupported-media-type"))
        status, _, body = peer.post(base + "/federation/events", b"x", {"Content-Type": "application/jose"})
        self.assertEqual((status, body), (404, b""))

    def test_review_regressions(self):
        """Findings from an independent code review, each reproduced before the fix."""
        self.paired()
        # Pairing fingerprints cover key validity and revocation, so a revoked key cannot be re-presented.
        revoked = json.loads(json.dumps(self.a.card))
        revoked["identity"]["keys"][0]["revoked"] = "2026-01-01T00:00:00Z"
        self.assertNotEqual(pairing.fingerprint(revoked), pairing.fingerprint(self.a.card))
        # ASCII digits only in instants.
        self.assertIsNone(wire.instant_ms("２０２６-１１-２１T００:００:００Z"))
        # A problem body with a non-string code falls back to the status instead of crashing.
        self.assertEqual(peer.classify(400, {"content-type": "application/problem+json"}, b'{"code":[]}'),
                         ("permanent", None))
        self.assertEqual(peer.retry_after({"retry-after": "1000000"}), 1000000)
        # A message naming an unknown predecessor waits like any other record (§8.2), and a pending record past
        # its hold deadline is refused at apply time even if its predecessor arrives before the next tick().
        ghost = wire.new_id()
        msg = wire.envelope(self.a.owner, wire.MESSAGE, [self.b.owner], {"text": "re"}, self.a.now(), thread=ghost,
                            in_reply_to=ghost, grant={"id": "g", "actor": "owner"})
        msg["thread"] = wire.new_id()
        self.assertEqual(self.post(self.b, self.signed(self.a, msg))[0], 200)
        late = self.b.clock
        self.b.clock = lambda: late() + 8 * 24 * 3600 * 1000
        self.b.apply_ready()
        with self.b.connection() as db:
            row = db.execute("SELECT outcome,outcome_code FROM records WHERE rid=?", (msg["id"],)).fetchone()
        self.assertEqual(row["outcome"], "refused")
        self.assertIn(row["outcome_code"], ("expired-before-apply", "missing-predecessor"))
        self.b.clock = late

    def test_refusal_stops_a_delivery_whose_receipt_was_lost(self):
        self.paired()
        self.a.allow({"peer": self.b.owner, "action": self.action})
        args = {"peer": self.b.owner, "requestKey": "lost", **{k: v for k, v in self.action.items() if k != "kind"}}
        self.a.tool("request_handoff", args, self.grant(self.a))
        row = self.a.due()[0]
        status, _, _ = self.post(self.b, row["jws"])  # B stores it; A never sees the receipt
        self.assertEqual(status, 200)
        r = wire.strict_json(wire.payload_bytes(row["jws"]))
        rejection = wire.envelope(self.b.owner, wire.REJECTION, [self.a.owner], {"code": "policy-denied"}, self.b.now(),
                                  thread=r["thread"], in_reply_to=r["id"])
        self.assertEqual(self.post(self.a, self.signed(self.b, rejection, "provider", wire.TYP_REJECTION))[0], 200)
        self.assertEqual(peer.attempt(self.a, row, lambda *_: self.fail("resent a refused record")), "refused")
        self.assertEqual(self.a.due(), [])

    def test_retry_after_is_not_a_backoff_step(self):
        self.paired()
        self.a.message(self.b.owner, "retry timing")
        row = self.a.due()[0]
        now = self.a.now()
        self.a.clock = lambda: now
        with patch("mailbox_db.secrets.randbelow", return_value=0):
            self.a.record_attempt(row, "transient", retry_after=600)
            with self.a.connection() as db:
                first = db.execute("SELECT next_at,backoff_ms FROM deliveries").fetchone()
            self.assertEqual((first["next_at"], first["backoff_ms"]), (now + 600_000, 1000))
            now = first["next_at"]
            self.a.record_attempt(row, "transient")
            with self.a.connection() as db:
                second = db.execute("SELECT next_at,backoff_ms FROM deliveries").fetchone()
            self.assertEqual((second["next_at"], second["backoff_ms"]), (now + 2000, 2000))

    def test_backoff_never_shrinks_at_the_cap(self):
        self.paired()
        self.a.message(self.b.owner, "hi")
        row = self.a.due()[0]
        with self.a.connection(True) as db:
            db.execute("UPDATE deliveries SET attempts=20, backoff_ms=2_100_000")
        self.a.record_attempt(row, "transient")
        with self.a.connection() as db:
            self.assertGreaterEqual(db.execute("SELECT backoff_ms FROM deliveries").fetchone()[0], 2_100_000)

    def test_store_from_wire_v1_is_refused(self):
        legacy = self.root / "legacy"
        legacy.mkdir()
        db = sqlite3.connect(legacy / "peer.sqlite")
        db.execute("CREATE TABLE owner(card BLOB, private_pem BLOB)")
        db.commit()
        db.close()
        with self.rejects(400):
            mailbox_db.Mailbox(legacy)

    def test_native_https_in_both_directions_with_private_ca(self):
        tls_files(self.root)
        p, q = bound_ports(2)
        d, e = self.owner("d", p, "https"), self.owner("e", q, "https")
        d.trust(e.card)
        e.trust(d.card)
        cap = self.grant(d)
        env = {**os.environ, "SSL_CERT_FILE": str(self.root / "ca.pem")}
        processes = []
        try:
            for owner in ("d", "e"):
                argv = [sys.executable, str(Path(peer.__file__).resolve()), "serve", "--dir", str(self.root / owner),
                        "--tls-cert", str(self.root / "leaf.pem"), "--tls-key", str(self.root / "leaf.key")]
                processes.append(subprocess.Popen(argv, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            d.allow({"peer": e.owner, "action": self.action})
            args = {"peer": e.owner, "requestKey": "secure", **{k: v for k, v in self.action.items() if k != "kind"}}
            tid = d.tool("request_handoff", args, cap)["threadId"]
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if any(proc.poll() is not None for proc in processes):
                    self.fail("TLS provider exited")
                state = d.tool("get_handoff", {"threadId": tid}, cap)
                if state["history"][0]["delivery"] == "delivered":
                    break
                time.sleep(0.1)
            self.assertEqual(state["history"][0]["delivery"], "delivered")
            step = e.tool("get_handoff", {"threadId": tid}, self.grant(e))
            e.tool("respond_handoff", {"threadId": tid, "expectedHead": step["head"], "action": {"kind": "accept"}},
                   self.grant(e))
            deadline = time.monotonic() + 10
            while d.tool("get_handoff", {"threadId": tid}, cap)["status"] != "accepted" and time.monotonic() < deadline:
                time.sleep(0.1)
            self.assertEqual(d.tool("get_handoff", {"threadId": tid}, cap)["status"], "accepted")
        finally:
            for proc in processes:
                proc.terminate()
            for proc in processes:
                proc.wait(timeout=8)

    def test_concurrent_sessions_consume_one_disclosure_and_receive_one_record(self):
        self.paired()
        auth = self.grant(self.a)
        rule = {"peer": self.b.owner, "action": self.action}
        self.a.allow(rule)

        def ready():
            return self.a.tool("list_authorized_handoffs", {}, auth)["approvals"][0]["readyArguments"]

        original = ready()
        self.a.allow(rule)
        self.assertEqual(ready(), original)
        self.a = mailbox_db.Mailbox(self.root / "a")
        self.assertEqual(ready(), original)
        with ThreadPoolExecutor(8) as workers:
            opened = list(workers.map(lambda _: self.a.tool("request_handoff", original, auth), range(12)))
        self.assertEqual({x["threadId"] for x in opened}, {opened[0]["threadId"]})
        self.assertEqual(len(self.a.due()), 1)
        signed = self.a.due()[0]["jws"]
        with ThreadPoolExecutor(8) as workers:
            receipts = list(workers.map(lambda _: self.post(self.b, signed), range(12)))
        self.assertEqual({(s, body) for s, _, body in receipts}, {(200, receipts[0][2])})
        received = self.b.tool("get_handoff", {"threadId": opened[0]["threadId"]}, self.grant(self.b))
        self.assertEqual(len(received["history"]), 1)
        self.a.allow(rule)
        self.assertNotEqual(ready()["requestKey"], original["requestKey"])

    def test_distinct_contacts_disclosures_are_separate_and_text_matches_javascript(self):
        self.paired()
        self.a.trust(self.c.card)
        auth = self.grant(self.a)
        self.a.allow({"peer": self.b.owner, "action": self.action})
        allowed = self.a.tool("list_authorized_handoffs", {}, auth)["approvals"][0]
        with self.rejects(403):
            self.a.tool("request_handoff", {**allowed["readyArguments"], "peer": self.c.owner}, auth)
        self.assertEqual(work.action({**self.action, "summary": "﻿摘要　"})["summary"], "摘要")
        self.assertEqual(work.action({**self.action, "summary": "\u0085摘要"})["summary"], "\u0085摘要")
        self.assertEqual(work.action({**self.action, "summary": "🗓" * 1000})["summary"], "🗓" * 1000)
        with self.assertRaises(ValueError):
            work.action({**self.action, "summary": "🗓" * 1001})
        with self.assertRaises(ValueError):
            work.action({**self.action, "summary": "\ud800"})


class RecordsLayerTests(unittest.TestCase):
    def test_strict_json_rejects_parser_differentials(self):
        for bad in (b'{"a":1,"a":2}', b"\xef\xbb\xbf{}", b'{"a":"\\ud800"}', b'{"a":"\\ufdd0"}', b"{\"a\":1e400}",
                    b"{\"a\":NaN}", b"\xff", b'{"a":1} x'):
            with self.subTest(bad=bad), self.assertRaises(wire.Reject) as raised:
                wire.strict_json(bad)
            self.assertEqual(raised.exception.code, "malformed")
        self.assertEqual(wire.strict_json('{"a":"\\ud83d\\uddd3"}'.encode()), {"a": "🗓"})

    def test_kid_must_already_be_normalized(self):
        good = ["https://bob.vectors.test/.well-known/darep/bob#sig-1", "https://h.test:8443/a/b#k", "https://10.0.0.1/x#k"]
        bad = ["http://bob.test/x#k", "https://Bob.test/x#k", "https://bob.test#k", "https://bob.test:443/x#k",
               "https://u@bob.test/x#k", "https://bob.test/x", "https://bob.test/a/../x#k", "https://bob.test/x y#k",
               "https://bob.test/x#", "https://1.2.3/x#k", "https://bob.test/%7eé#k", "acct:bob@bob.test"]
        for kid in good:
            self.assertTrue(wire.https_uri(kid, fragment=True, max_len=2048, test_only=True), kid)
        for kid in bad:
            self.assertFalse(wire.https_uri(kid, fragment=True, max_len=2048, test_only=True), kid)

    def test_k1_host_grammar(self):
        good = ["a.test", "a-b.example", "xn--anything.test", "a" * 63 + ".test",
                ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 61])]
        bad = ["", "localhost", "-a.test", "a-.test", "a..test", "a.test.", "A.test", "a_b.test",
               "a.123", "a.0xff", "a.0x", "a" * 64 + ".test", ".".join(["a" * 63] * 3 + ["d" * 62]),
               "127.1", "0177.0.0.1", "0x7f.0.0.1", "256.0.0.1", "[::1]", "a.test\n"]
        for host in good:
            self.assertTrue(wire.is_uri_host(host), host)
        for host in bad:
            self.assertFalse(wire.is_uri_host(host, test_only=True), host)
        for host in ["127.0.0.1", "0.0.0.0", "255.255.255.255"]:
            self.assertFalse(wire.is_uri_host(host), host)
            self.assertTrue(wire.is_uri_host(host, test_only=True), host)

    def test_k1_uri_grammar(self):
        good = ["https://a.test/x^y#k", "https://a.test:1/x#k", "https://a.test:65535/x#k",
                "https://xn--zz.test/x#k", "https://a.test/x|y#k", "https://a.test/x#k{}",
                "https://a.test/x?a%27b#k", "https://a.test/x?#k", "https://a.test//x#k", "https://a.test/x%zz#k"]
        bad = ["https://a.test:0/x#k", "https://a.test:00/x#k", "https://a.test:443/x#k",
               "https://a.test:65536/x#k", "https://a.test:444\n/x#k", "https://[::1]/x#k",
               "https://a.test/x#k#l", "https://a.test/x#k`", "https://a.test/x?a'b#k",
               "https://a.test/./x#k", "https://a.test/%2E%2e/x#k", "https://a.test/.%2e/x#k",
               "https://a.test/%2e./x#k", "https://a.test/x\\y#k", "https://a.test/x#"]
        for uri in good:
            self.assertTrue(wire.https_uri(uri, fragment=True), uri)
        for uri in bad:
            self.assertFalse(wire.https_uri(uri, fragment=True), uri)
        self.assertFalse(wire.https_uri("https://a.test/x#", fragment=False))
        for suffix in ["?", "?v=1"]:
            self.assertFalse(wire.https_uri("https://a.test/x" + suffix, fragment=False, allow_query=False))

    def test_bad_kid_precedes_pin_lookup(self):
        for name in ["kid-hyphen-host", "kid-single-label-host", "kid-empty-fragment", "kid-default-port", "kid-userinfo"]:
            v = run_vectors.load(run_vectors.RECORDS / ("negative/" + name + ".json"))
            pins = wire.Pins([])
            with patch.object(pins, "resolve", side_effect=AssertionError("must not resolve a bad kid")):
                with self.assertRaises(wire.Reject) as raised:
                    wire.verify_jws(v["jws"], [wire.TYP_EVENT], pins)
                self.assertEqual(raised.exception.code, "bad-header")


if __name__ == "__main__":
    unittest.main(verbosity=2)
