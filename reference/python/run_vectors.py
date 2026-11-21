"""Run every applicable Wire v2 vector against the Python peer.

    reference/python/.venv/bin/python reference/python/run_vectors.py        # summary, exit 1 on any failure
    reference/python/.venv/bin/python reference/python/test_peer.py          # also runs these as unit tests

Records vectors (vectors/v2/records/) go through wire.verify_record. Receiver delivery vectors are POSTed to
the real HTTP handler on loopback with the receiver's clock injected per step. Sender delivery vectors drive
peer.attempt() with each scripted response in place of the network. Under D8 a vector is skipped only when it
needs a type outside core/v2, work/v2 and message, and the skip is reported with its reason.
"""

from contextlib import nullcontext
import http.client
import json
import sqlite3
import sys
import tempfile
import threading
from pathlib import Path
from unittest.mock import patch

import mailbox_db
import peer
import wire
import work

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent.parent / "vectors" / "v2"
RECORDS = VECTORS / "records"
DELIVERY = VECTORS / "delivery"
D8_TYPES = (wire.CORE + "#", work.WORK + "#")


class Failure(AssertionError):
    pass


def check(condition, why):
    if not condition:
        raise Failure(why)


def load(path):
    return json.loads(Path(path).read_text(encoding="utf8"))


# ---------- records ----------


def run_record(name, identities):
    v = load(RECORDS / (name + ".json"))
    c = v["context"]
    typs = c["typ"] if isinstance(c["typ"], list) else [c["typ"]]
    pins = wire.Pins(identities)
    try:
        out = wire.verify_record(v["jws"], typs, pins, c["mode"], wire.instant_ms(c["now"]), c.get("receiver"),
                                 c.get("understood", []), c.get("answered"))
    except wire.Reject as err:
        check(v["expected"]["verdict"] == "reject", f"rejected {err.code} ({err}) but expected accept")
        check(err.code == v["expected"]["code"], f"code {err.code} ({err}), expected {v['expected']['code']}")
        return "reject " + err.code
    exp = v["expected"]
    check(exp["verdict"] == "accept", f"accepted but expected {exp.get('code')}")
    check(out.header["kid"] == exp["kid"], "kid")
    check(out.record == exp["record"], "parsed record differs")
    check(out.sha256 == v["payloadSha256"], "payload digest")
    if v["payloadUtf8"] is not None:
        check(out.payload == v["payloadUtf8"].encode("utf8"), "payload bytes differ from payloadUtf8")
    if "receiptFor" in exp:
        target = load(RECORDS / (exp["receiptFor"] + ".json"))
        check(out.record["data"]["sha256"] == target["payloadSha256"], "receipt digest")
        check(out.record["inReplyTo"] == target["expected"]["record"]["id"], "receipt inReplyTo")
        check(out.record["to"] == [target["expected"]["record"]["source"]], "receipt to")
    return "accept"


def run_invalid_identity(case):
    try:
        wire.Pins([case["document"]])
    except wire.PinError:
        return "reject P-0"
    raise Failure("accepted invalid identity " + case["name"])


def records_cases():
    identities = load(RECORDS / "identities.json")["documents"]
    for case in load(RECORDS / "invalid-identities.json")["cases"]:
        yield "identities/" + case["name"], lambda c=case: run_invalid_identity(c)
    for entry in load(RECORDS / "index.json")["vectors"]:
        yield "records/" + entry["name"], lambda n=entry["name"]: run_record(n, identities)


# ---------- delivery fixtures ----------


class Fixture:
    def __init__(self, vector, root):
        self.vector = vector
        ids = load(DELIVERY / "identities.json")
        keys = load(DELIVERY / "test-keys.json")["keys"]
        self.documents = {a: d for d in ids["documents"] for a in d["addresses"]}
        party = vector.get("receiver") or vector.get("sender")
        self.address = party["address"]
        self.document = self.documents[self.address]
        mailbox_db.init(root, self.address, "http://127.0.0.1:9", document=self.document,
                        private_jwks={k: keys[k] for k in party["signingKeys"]},
                        inbox=ids["inboxes"][self.address])
        self.store = mailbox_db.Mailbox(root)
        self.clock = [0]
        self.store.clock = lambda: self.clock[0]
        for address in party["pinned"]:
            self.store.trust({"identity": self.documents[address], "inbox": ids["inboxes"][address]})
        for ext in party.get("extensions", []):
            check(ext in work.UNDERSTOOD, "receiver vector needs extension " + ext)

    def at(self, instant):
        self.clock[0] = wire.instant_ms(instant)

    def rows(self, sql, *params):
        with self.store.connection() as db:
            return db.execute(sql, params).fetchall()

    def record_row(self, rid, direction=None):
        rows = [r for r in self.rows("SELECT * FROM records WHERE rid=? ORDER BY seq", rid)
                if direction is None or r["direction"] == direction]
        return rows[0] if rows else None


def skip_reason(vector):
    for rec in vector.get("records", {}).values():
        t = rec["envelope"].get("type", "")
        if not t.startswith(D8_TYPES) and "reschedule" in t:
            return "uses " + t + ", which D8 leaves Node-only"
    return None


class Inbox:
    """The real peer.Handler on 127.0.0.1, bound to one fixture's store."""

    def __init__(self, store):
        self.server = peer.Server(("127.0.0.1", 0), peer.Handler)
        self.server.store = store
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def request(self, req, body):
        from urllib.parse import urlsplit

        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=10)
        try:
            conn.putrequest(req["method"], urlsplit(req["url"]).path, skip_accept_encoding=True)
            for name, value in req.get("headers", {}).items():
                conn.putheader(name, value)
            if body is not None:
                conn.putheader("Content-Length", str(len(body)))
            conn.endheaders(body)
            res = conn.getresponse()
            return res.status, {k.lower(): v for k, v in res.getheaders()}, res.read()
        finally:
            conn.close()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def dotted(record, path):
    value = record
    for part in path.split("."):
        value = value[part]
    return value


def check_signed_rejection(fx, exp, answered_row):
    rows = fx.rows("SELECT * FROM records WHERE direction='out' AND typ=? AND in_reply_to=?", wire.TYP_REJECTION,
                   answered_row["rid"])
    if not rows and exp.get("optional"):
        return "no optional rejection"
    check(len(rows) == 1, f"expected one rejection record, found {len(rows)}")
    v = wire.verify_record(rows[0]["jws"], [exp["typ"]], wire.Pins([fx.document]), mode="evidence",
                           answered=wire.payload_bytes(answered_row["jws"]))
    check("provider" in v.key["purpose"], "rejection not signed with a provider key")
    for path, value in exp["equals"].items():
        check(dotted(v.record, path) == value, "rejection " + path)
    for member in exp.get("absent", []):
        check(member not in v.record, "rejection has " + member)
    for member in exp.get("present", []):
        check(member in v.record, "rejection lacks " + member)
    deliveries = fx.rows("SELECT * FROM deliveries WHERE seq=?", rows[0]["seq"])
    check([d["recipient"] for d in deliveries] == [exp["deliveredTo"]], "rejection outbox recipient")
    return "rejection " + v.record["data"]["code"]


def run_receiver(path):
    vector = load(path)
    reason = skip_reason(vector)
    if reason:
        return "SKIP " + reason
    with tempfile.TemporaryDirectory(prefix="darep-vector-") as root:
        fx = Fixture(vector, Path(root) / "peer")
        names = {r["recordBytes"]: n for n, r in vector["records"].items()}
        for prior in vector.get("priorState", []):
            check(prior["direction"] == "outgoing" and prior["applyOutcome"] == "applied", "unsupported priorState")
            fx.store.restore_outgoing(vector["records"][prior["record"]]["recordBytes"])
        pre = vector.get("precondition", "")
        patches = []
        if "quota" in pre:
            fx.store.capacity = lambda source, now: 60 if source == "acct:bob@vectors.test" else None
        if "commit is forced to fail" in pre:
            def broken(*_args):
                raise sqlite3.OperationalError("disk I/O error (forced by vector)")

            patches.append(patch.object(fx.store, "store_delivery", broken))
        for p in patches:
            p.start()
        inbox = Inbox(fx.store)
        notes = []
        try:
            receipts, last = [], None
            for i, step in enumerate(vector["steps"]):
                fx.at(step["at"])
                exp = step["expect"]
                req = step.get("request")
                body = None
                if req:
                    if req.get("bodyFill"):
                        body = req["bodyFill"]["octet"].encode() * req["bodyFill"]["length"]
                    elif req.get("body") is not None:
                        body = req["body"].encode("ascii")
                    before = len(fx.rows("SELECT seq FROM records WHERE direction='in'"))
                    status, headers, rbody = inbox.request(req, body)
                    # The handler applies after it has sent the response; wait for that (serialized by SQLite).
                    fx.store.apply_ready()
                    receipts.append(rbody if status == 200 else None)
                    check(status == exp["status"], f"step {i}: status {status} {rbody[:200]!r}, expected {exp['status']}")
                    check(headers.get("content-type", "").startswith(exp["contentType"]), f"step {i}: content type")
                    for name, value in exp.get("headers", {}).items():
                        got = headers.get(name)
                        if value.startswith("<integer"):
                            check(got is not None and got.isdigit(), f"step {i}: {name} header")
                        else:
                            check(got == value, f"step {i}: {name} header {got!r}")
                    if "problem" in exp:
                        problem = json.loads(rbody)
                        for k, val in exp["problem"].items():
                            check(problem.get(k) == val, f"step {i}: problem {k}")
                        check(set(problem) <= {"type", "title", "status", "code", "detail", "record"}, "problem members")
                    after = len(fx.rows("SELECT seq FROM records WHERE direction='in'"))
                    stored = exp.get("stored")
                    if stored is False or stored == "unchanged":
                        check(after == before, f"step {i}: something was stored")
                    if body and status == 200 or stored is True:
                        r = wire.strict_json(wire.payload_bytes(body.decode()))
                        last = fx.record_row(r["id"], "in")
                    if stored is True:
                        check(after == before + 1 and last is not None and last["jws"] == body.decode(),
                              f"step {i}: record bytes not stored exactly")
                    if stored == "unchanged" and last is not None:
                        check(last["jws"] == vector["steps"][0]["request"]["body"], "first record bytes replaced")
                    if exp.get("receipt"):
                        er = exp["receipt"]
                        v = wire.verify_record(rbody.decode(), [er["typ"]], wire.Pins([fx.document]), mode="evidence",
                                               answered=body.decode())
                        check("provider" in v.key["purpose"], "receipt key purpose")
                        check(set(v.record) == set(er["members"]), f"step {i}: receipt members {sorted(v.record)}")
                        for k, val in er["equals"].items():
                            check(v.record[k] == val, f"step {i}: receipt {k} = {v.record[k]!r}")
                        check(wire.instant_ms(v.record["time"]) >= wire.instant_ms(er["timeAtOrAfter"]), "receipt time")
                        check(last["receipt"] == rbody.decode(), "issued receipt not stored")
                        retained = wire.instant_ms(v.record["data"]["storedAt"]) + mailbox_db.RETENTION_MS
                        check(retained == wire.instant_ms(er["retainedAtLeastUntil"]), "retention promise")
                    if exp.get("receipt") is None and "receipt" in exp:
                        check(status != 200, "a receipt was returned")
                    if "receiptBytesEqualStep" in exp:
                        check(rbody == receipts[exp["receiptBytesEqualStep"]], f"step {i}: receipt bytes differ")
                else:
                    fx.store.tick()
                    last = fx.record_row(last["rid"], "in")
                if "applyOutcome" in exp:
                    last = fx.record_row(last["rid"], "in")
                    check(last["outcome"] == exp["applyOutcome"],
                          f"step {i}: outcome {last['outcome']} ({last['outcome_code']}), expected {exp['applyOutcome']}")
                if "applyCount" in exp:
                    check(fx.record_row(last["rid"], "in")["apply_count"] == exp["applyCount"], f"step {i}: applyCount")
                for item in exp.get("afterApply", []):
                    dependent = fx.record_row(item["record"], "in")
                    check(dependent["outcome"] == item["applyOutcome"], "afterApply")
                    if "rejectionRecord" in item:
                        notes.append(check_signed_rejection(fx, item["rejectionRecord"], dependent))
                if "rejectionRecord" in exp:
                    notes.append(check_signed_rejection(fx, exp["rejectionRecord"], fx.record_row(last["rid"], "in")))
            final = vector.get("finalState")
            if final:
                thread = last["thread"]
                with fx.store.connection() as db:
                    state = fx.store.state(db, thread)
                if "threadHead" in final:
                    check(state["head"] == final["threadHead"], "thread head")
                if "applyOrder" in final:
                    order = [r["rid"] for r in fx.rows(
                        "SELECT r.rid FROM apply_log l JOIN records r USING(seq) WHERE l.outcome='applied' AND r.thread=? "
                        "ORDER BY l.id", thread)]
                    check(order == final["applyOrder"], f"apply order {order}")
                if "stored" in final:
                    rids = {r["rid"] for r in fx.rows("SELECT rid FROM records WHERE typ=?", wire.TYP_EVENT)}
                    check(set(final["stored"]) <= rids, "stored records")
                if "rejectionRecords" in final:
                    n = len(fx.rows("SELECT seq FROM records WHERE direction='out' AND typ=?", wire.TYP_REJECTION))
                    check(n == final["rejectionRecords"], "rejection record count")
                if "outbox" in final:
                    n = len(fx.rows("SELECT d.seq FROM deliveries d JOIN records r USING(seq) WHERE r.typ=? AND "
                                    "d.status='queued'", wire.TYP_REJECTION))
                    check(n == len(final["outbox"]), "outbox")
        finally:
            inbox.close()
            for p in patches:
                p.stop()
        del names
        return "ok" + (" (" + ", ".join(notes) + ")" if notes else "")


# ---------- sender ----------


def fake_send(respond, expected, calls):
    def send(url, body, headers):
        calls.append((url, body, headers))
        check(url == expected["url"], "sender used " + url)
        for name, value in expected["headers"].items():
            got = {k.lower(): v for k, v in headers.items()}.get(name)
            check(got == value, f"sender header {name} = {got!r}")
        if "connection" in respond:
            raise ConnectionResetError(respond["connection"])
        rbody = respond.get("body", "").encode()
        return respond["status"], {k.lower(): v for k, v in respond.get("headers", {}).items()}, rbody

    return send


def sender_fixture(vector, root):
    fx = Fixture(vector, root)
    for rec in vector["records"].values():
        with fx.store.connection(True) as db:
            fx.store.store_outgoing(db, rec["recordBytes"], wire.instant_ms(rec["envelope"]["time"]))
    return fx


def delivery_row(fx, rid, recipient):
    seq = fx.record_row(rid, "out")["seq"]
    with fx.store.connection() as db:
        return db.execute(
            "SELECT d.*,r.jws,r.sha256,r.thread,r.rid,r.expires FROM deliveries d JOIN records r USING(seq) "
            "WHERE d.seq=? AND d.recipient=?", (seq, recipient)).fetchone()


def run_sender(path):
    vector = load(path)
    reason = skip_reason(vector)
    if reason:
        return "SKIP " + reason
    out = vector["records"]["out"]
    rid = out["envelope"]["id"]
    notes = []
    if "cases" in vector:
        for i, case in enumerate(vector["cases"]):
            with tempfile.TemporaryDirectory(prefix="darep-vector-") as root:
                fx = sender_fixture(vector, Path(root) / "peer")
                fx.at(out["envelope"]["time"])
                fx.clock[0] += 30_000
                row = delivery_row(fx, rid, out["envelope"]["to"][0])
                calls = []
                expected = {"url": load(DELIVERY / "identities.json")["inboxes"][row["recipient"]],
                            "headers": {"content-type": "application/jose", "darep-recipient": row["recipient"]}}
                got = peer.attempt(fx.store, row, fake_send(case["respond"], expected, calls))
                check(got == case["expect"]["attemptResult"], f"case {i}: {got}, expected {case['expect']['attemptResult']}")
        return "ok (" + str(len(vector["cases"])) + " cases)"
    with tempfile.TemporaryDirectory(prefix="darep-vector-") as root:
        fx = sender_fixture(vector, Path(root) / "peer")
        previous_backoff = 0
        for i, step in enumerate(vector["steps"]):
            fx.at(step["at"])
            exp = step["expect"]
            req = step.get("request")
            if req:
                name = req["bodyEqualsRecord"]
                recipient = req["headers"]["darep-recipient"]
                row = delivery_row(fx, vector["records"][name]["envelope"]["id"], recipient)
                # Scripted attempt clocks are stimuli, not assertions about the sender's computed schedule.
                # Check the mandatory bounds and report the optional profile separately below.
                check(row["status"] == "queued", f"step {i}: delivery is {row['status']}")
                if row["next_at"] > fx.clock[0]:
                    notes.append(f"step {i} forced {(row['next_at'] - fx.clock[0]) / 1000:.1f}s before our backoff")
                check(row["jws"] == vector["records"][name]["recordBytes"], f"step {i}: stored bytes changed")
                calls = []
                if exp.get("recordsVerdict") == "accept":
                    with fx.store.connection() as db:
                        pins = fx.store.pins(db)
                    wire.verify_record(step["respond"]["body"], (wire.TYP_RECEIPT,), pins,
                                       now=fx.clock[0], receiver=fx.address, answered=row["jws"])
                zero_jitter = vector.get("retryProfile", {}).get("jitterPercent") == 0
                with patch("mailbox_db.secrets.randbelow", return_value=0) if zero_jitter else nullcontext():
                    got = peer.attempt(fx.store, row, fake_send(step["respond"], req, calls))
                check(len(calls) == 1 and calls[0][1] == vector["records"][name]["recordBytes"].encode(),
                      f"step {i}: did not send the stored bytes exactly once")
                check(got == exp.get("attemptResult", got), f"step {i}: attempt {got}, expected {exp.get('attemptResult')}")
                attempt = fx.rows("SELECT * FROM attempts WHERE seq=? ORDER BY id DESC LIMIT 1", row["seq"])[0]
                if "verifyCode" in exp:
                    check(attempt["code"] == exp["verifyCode"], f"step {i}: verify code {attempt['code']}, expected {exp['verifyCode']}")
                if "evidenceKept" in exp:
                    kept = exp["evidenceKept"]
                    if "body" in kept or "receipt bytes" in kept:
                        check(attempt["body"] == step["respond"]["body"].encode(), f"step {i}: response body not kept")
                    if "status" in kept:
                        check(attempt["status"] == step["respond"]["status"], f"step {i}: status not kept")
                    if "retry-after" in kept:
                        check(json.loads(attempt["headers"]).get("retry-after") == step["respond"]["headers"]["retry-after"],
                              f"step {i}: retry-after not kept")
            else:
                fx.store.tick()
            row = delivery_row(fx, rid, out["envelope"]["to"][0])
            if "delivery" in exp:
                check(row["status"] == exp["delivery"], f"step {i}: delivery {row['status']}, expected {exp['delivery']}")
            if "nextAttemptNotBefore" in exp:
                check(row["next_at"] >= wire.instant_ms(exp["nextAttemptNotBefore"]), f"step {i}: retried too early")
            if "backoff" in exp:
                check(row["backoff_ms"] >= exp["backoff"]["minimumSeconds"] * 1000, f"step {i}: backoff below minimum")
                if exp["backoff"].get("nonDecreasing"):
                    check(row["backoff_ms"] >= previous_backoff, f"step {i}: backoff decreased")
                check(row["next_at"] >= fx.clock[0] + row["backoff_ms"], f"step {i}: schedule precedes backoff")
                previous_backoff = row["backoff_ms"]
            if "backoffSeconds" in exp.get("should", {}):
                recommended = exp["should"]
                met = (row["backoff_ms"] == recommended["backoffSeconds"] * 1000
                       and row["next_at"] == wire.instant_ms(recommended["nextAttemptAt"]))
                notes.append(("SHOULD met: " if met else "SHOULD not met: ")
                             + f"zero-jitter profile backoff {recommended['backoffSeconds']}s")
            if exp.get("furtherAttempts") == 0:
                fx.clock[0] += 3600_000
                check(all(d["seq"] != row["seq"] for d in fx.store.due()), f"step {i}: further attempts are due")
            if "receiptStored" in exp:
                check(row["receipt"] == step["respond"]["body"], f"step {i}: receipt not stored byte for byte")
            if "followedRedirect" in exp:
                check(len(calls) == 1, "followed a redirect")
            for dep_id, dep in exp.get("dependentRecords", {}).items():
                drow = delivery_row(fx, dep_id, out["envelope"]["to"][0])
                if "should" in dep:
                    ok = drow["status"] == "failed" and drow["attempts"] == 0
                    notes.append(("SHOULD met: " if ok else "SHOULD not met: ") + dep["should"])
    return "ok" + (" (" + "; ".join(notes) + ")" if notes else "")


def delivery_cases():
    for role, runner in (("receiver", run_receiver), ("sender", run_sender)):
        for path in sorted((DELIVERY / role).glob("*.json")):
            yield "delivery/" + role + "/" + path.stem, lambda p=path, r=runner: r(p)


def all_cases():
    yield from records_cases()
    yield from delivery_cases()


def main():
    counts = {"pass": 0, "fail": 0, "skip": 0}
    for name, case in all_cases():
        try:
            result = case()
        except (Failure, wire.Reject, AssertionError, KeyError) as err:
            counts["fail"] += 1
            print(f"FAIL {name}: {type(err).__name__}: {err}")
            continue
        if result.startswith("SKIP"):
            counts["skip"] += 1
            print(f"skip {name}: {result[5:]}")
        else:
            counts["pass"] += 1
            print(f"ok   {name}: {result}")
    print(f"{counts['pass']} passed, {counts['fail']} failed, {counts['skip']} skipped")
    return 1 if counts["fail"] else 0


if __name__ == "__main__":
    sys.exit(main())
