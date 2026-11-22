"""Conformance-kit adapter for the Python reference peer (reference/python).

It speaks the adapter contract in ../../ADAPTER.md: one JSON request per line on stdin, one answer per line on stdout.
Run it with the peer's own environment:

    reference/python/.venv/bin/python conformance/adapters/python/adapter.py
"""

import json
import shutil
import socket
import sqlite3
import sys
import tempfile
import threading
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "reference" / "python"))

import mailbox_db  # noqa: E402
import peer  # noqa: E402
import wire  # noqa: E402


class Unsupported(Exception):
    pass


STATE = {"mode": None}


def out(message):
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def text(value):
    if value is None:
        return None
    return value.decode("utf-8", "replace") if isinstance(value, (bytes, bytearray)) else value


def store():
    s = STATE.get("store")
    if s is None:
        raise RuntimeError("call reset or liveStart first")
    return s


def rows(sql, *params):
    with store().connection() as db:
        return db.execute(sql, params).fetchall()


def serve(s, port=0):
    server = peer.Server(("127.0.0.1", port), peer.Handler)
    server.store = s
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    return server


def stop_all():
    for p in STATE.pop("patches", []):
        p.stop()
    if STATE.get("worker_stop"):
        STATE["worker_stop"].set()
        STATE.pop("worker").join(5)
        STATE.pop("worker_stop")
    server = STATE.pop("server", None)
    if server:
        server.shutdown()
        server.server_close()
    STATE.pop("store", None)
    root = STATE.pop("root", None)
    if root:
        shutil.rmtree(root, ignore_errors=True)
    STATE["mode"] = None


def describe(_):
    return {"name": "darep-reference-python", "version": "0.1.0", "roles": ["verifier", "signer", "receiver", "sender"],
            "live": True, "extensions": [wire.CORE, "https://darep.org/ext/work/v2"]}


# ---------- verifier and signer ----------


def verify(p):
    c = p["context"]
    try:
        v = wire.verify_record(p["jws"], c["typ"], wire.Pins(p["identities"]), c["mode"], wire.instant_ms(c["now"]),
                               c.get("receiver"), c.get("understood") or [], c.get("answered"))
    except wire.Reject as err:
        return {"verdict": "reject", "code": err.code}
    return {"verdict": "accept", "kid": v.header["kid"], "record": v.record, "payloadSha256": v.sha256}


def validate_identity(p):
    try:
        wire.Pins([p["document"]])
    except (wire.PinError, wire.Reject):
        return {"verdict": "reject"}
    return {"verdict": "accept"}


def sign(p):
    key = mailbox_db.private_key_from_jwk(p["privateJwk"])
    return {"jws": wire.sign(wire.serialize(p["payload"]), key, p["kid"], p["typ"])}


# ---------- offline receiver and sender, with an injected clock ----------


def reset(p):
    stop_all()
    root = Path(tempfile.mkdtemp(prefix="darep-python-adapter-"))
    STATE["root"] = root
    mailbox_db.init(root / "peer", p["address"], "http://127.0.0.1:9", document=p["document"],
                    private_jwks=p["privateKeys"], inbox="http://127.0.0.1:9" + mailbox_db.INBOX_PATH)
    s = mailbox_db.Mailbox(root / "peer")
    clock = [wire.instant_ms(p["now"])]
    s.clock = lambda: clock[0]
    STATE["clock"] = clock
    for pin in p["pins"]:
        s.trust(pin)
    STATE["patches"] = []
    if p.get("jitter") is False:
        jitter = patch("mailbox_db.secrets.randbelow", return_value=0)
        jitter.start()
        STATE["patches"].append(jitter)
    STATE["store"] = s
    STATE["mode"] = "offline"
    if p["role"] != "receiver":
        return {}
    STATE["server"] = serve(s)
    return {"inbox": "http://127.0.0.1:%d%s" % (STATE["server"].server_address[1], mailbox_db.INBOX_PATH)}


def set_clock(p):
    if STATE["mode"] != "offline":
        raise Unsupported("setClock is for offline mode")
    STATE["clock"][0] = wire.instant_ms(p["now"])
    return {}


def fault(p):
    s = store()
    if p["kind"] == "rate-limited":
        s.capacity = lambda source, now: 60
    elif p["kind"] == "unavailable":
        def broken(*_args):
            raise sqlite3.OperationalError("disk I/O error (injected)")
        s.store_delivery = broken
    else:
        raise Unsupported("unknown fault " + p["kind"])
    return {}


def seed_outgoing(p):
    store().restore_outgoing(p["recordBytes"])
    return {}


def tick(_):
    store().tick()
    return {}


def stats(_):
    return {
        "incoming": rows("SELECT count(*) AS n FROM records WHERE direction='in'")[0]["n"],
        "rejections": rows("SELECT count(*) AS n FROM records WHERE direction='out' AND typ=?", wire.TYP_REJECTION)[0]["n"],
    }


def inspect_incoming(p):
    found = rows("SELECT * FROM records WHERE direction='in' AND source=? AND rid=?", p["source"], p["id"])
    if not found:
        return {"found": False}
    row = found[0]
    rejection = None
    if row["rejection_seq"]:
        rej = rows("SELECT * FROM records WHERE seq=?", row["rejection_seq"])[0]
        recipients = [d["recipient"] for d in rows("SELECT recipient FROM deliveries WHERE seq=?", rej["seq"])]
        rejection = {"recordBytes": rej["jws"], "deliverTo": recipients}
    return {"found": True, "recordBytes": row["jws"], "receipt": row["receipt"], "outcome": row["outcome"],
            "applyCount": row["apply_count"], "storedAt": row["stored_at"], "rejection": rejection}


def inspect_thread(p):
    if STATE["mode"] != "offline":
        raise Unsupported("inspectThread is for offline mode")
    s = store()
    with s.connection() as db:
        state = s.state(db, p["thread"])
    order = [r["rid"] for r in rows(
        "SELECT r.rid FROM apply_log l JOIN records r USING(seq) WHERE l.outcome='applied' AND r.thread=? "
        "AND r.typ=? ORDER BY l.id", p["thread"], wire.TYP_EVENT)]
    return {"head": (state or {}).get("head"), "applyOrder": order}


def queue_signed(p):
    s = store()
    envelope = wire.strict_json(wire.payload_bytes(p["recordBytes"]))
    with s.connection(True) as db:
        s.store_outgoing(db, p["recordBytes"], wire.instant_ms(envelope["time"]))
    return {}


def delivery_row(rid, recipient):
    found = rows(
        "SELECT d.*,r.jws,r.sha256,r.thread,r.rid,r.expires FROM deliveries d JOIN records r USING(seq) "
        "WHERE r.direction='out' AND r.rid=? AND d.recipient=?", rid, recipient)
    return found[0] if found else None


def attempt(p):
    row = delivery_row(p["id"], p["recipient"])
    if row is None:
        raise RuntimeError("no such outgoing delivery")
    return {"result": peer.attempt(store(), row)}


def inspect_outgoing(p):
    row = delivery_row(p["id"], p["recipient"])
    if row is None:
        return {"found": False}
    attempts = [{"at": a["at"], "result": a["result"], "code": a["code"], "status": a["status"],
                 "headers": json.loads(text(a["headers"]) or "{}"), "body": text(a["body"])}
                for a in rows("SELECT * FROM attempts WHERE seq=? AND recipient=? ORDER BY id", row["seq"], row["recipient"])]
    return {"found": True, "status": row["status"], "recordBytes": row["jws"], "receipt": row["receipt"],
            "attempts": attempts, "backoffMs": row["backoff_ms"], "nextAttemptAt": wire.format_instant(row["next_at"]),
            "refusal": {"code": row["refused_code"]} if row["refused_code"] else None}


def due(_):
    return {"deliveries": [{"id": r["rid"], "recipient": r["recipient"]} for r in store().due()]}


# ---------- live: a real peer on loopback with the real clock and its own outbox worker ----------


def start_worker(s):
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            try:
                s.tick()
                for row in s.due():
                    if stop.is_set():
                        break
                    peer.attempt(s, row)
            except Exception as err:  # keep the worker alive, as peer.serve does
                print("Worker failed:", type(err).__name__, err, file=sys.stderr, flush=True)
            stop.wait(0.2)

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    STATE["worker"], STATE["worker_stop"] = thread, stop


def live_start(p):
    stop_all()
    root = Path(tempfile.mkdtemp(prefix="darep-python-live-"))
    STATE["root"] = root
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    address = p.get("addressHint") or "acct:impl@impl.conformance.test"
    card = mailbox_db.init(root / "peer", address, "http://127.0.0.1:%d" % port)
    s = mailbox_db.Mailbox(root / "peer")
    s.trust(p["kitCard"])
    STATE.update(store=s, mode="live", port=port, server=serve(s, port))
    start_worker(s)
    return {"card": card}


def send(p):
    if STATE["mode"] != "live":
        raise Unsupported("send is for live mode")
    s = store()
    with s.connection(True) as db:
        grant = s.owner_act(db, "conformance kit message to " + p["to"])
        record, _ = s.send(db, p["type"], [p["to"]], p["data"], grant)
    return {"id": record["id"]}


def restart(_):
    if STATE["mode"] != "live":
        raise Unsupported("restart is for live mode")
    STATE["worker_stop"].set()
    STATE.pop("worker").join(5)
    STATE.pop("worker_stop")
    server = STATE.pop("server")
    server.shutdown()
    server.server_close()
    s = mailbox_db.Mailbox(STATE["root"] / "peer")
    STATE["store"] = s
    STATE["server"] = serve(s, STATE["port"])
    start_worker(s)
    return {"inbox": "http://127.0.0.1:%d%s" % (STATE["port"], mailbox_db.INBOX_PATH)}


def stop(_):
    stop_all()
    return {}


OPS = {
    "describe": describe, "verify": verify, "validateIdentity": validate_identity, "sign": sign, "reset": reset,
    "setClock": set_clock, "fault": fault, "seedOutgoing": seed_outgoing, "tick": tick, "stats": stats,
    "inspectIncoming": inspect_incoming, "inspectThread": inspect_thread, "queueSigned": queue_signed,
    "attempt": attempt, "inspectOutgoing": inspect_outgoing, "due": due, "liveStart": live_start, "send": send,
    "restart": restart, "stop": stop,
}


def main():
    for line in sys.stdin:
        try:
            request = json.loads(line)
        except ValueError:
            continue
        op = OPS.get(request.get("op"))
        if op is None:
            out({"id": request.get("id"), "error": {"code": "unsupported", "message": "unknown op %s" % request.get("op")}})
            continue
        try:
            out({"id": request["id"], "result": op(request.get("params") or {})})
        except Unsupported as err:
            out({"id": request["id"], "error": {"code": "unsupported", "message": str(err)}})
        except Exception as err:  # report, keep serving
            out({"id": request["id"], "error": {"code": "failed", "message": "%s: %s" % (type(err).__name__, err)}})
    stop_all()


if __name__ == "__main__":
    main()
