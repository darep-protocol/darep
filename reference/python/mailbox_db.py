"""Operator-owned SQLite state for the Wire v2 Python provider.

Receive is verify → store → ack → apply (delivery.md §3). Records are stored as the exact signed bytes,
outgoing records are signed once and resent as the same bytes (§7.1), every issued receipt is stored so a
duplicate gets it back byte for byte (§6), and grants and approvals are closed, never deleted (§9.4).
"""

import hmac
import json
import os
import re
import secrets
import sqlite3
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

import wire
import work
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

SCHEMA_VERSION = 2  # PRAGMA user_version. Version 1 was the Wire v1 schema; A1 wipes it (no migration).
MAX_RECORD = 65_536  # delivery.md §3.4
HOLD_MS = 7 * 24 * 3600 * 1000  # delivery.md §2 hold window
RETENTION_MS = 30 * 24 * 3600 * 1000  # D4
BACKOFF_CAP_S = 1800
INBOX_PATH = "/darep/v2/inbox"
GRANT_VERBS = ("read", "send", "commit")  # records.md §1.3; manage is never granted to an agent (PV-2)

SCHEMA = """
CREATE TABLE identity(address TEXT NOT NULL, document BLOB NOT NULL, inbox TEXT NOT NULL, origin TEXT NOT NULL);
CREATE TABLE keys(kid TEXT PRIMARY KEY, purpose TEXT NOT NULL, private_pem BLOB NOT NULL);
CREATE TABLE contacts(doc_id TEXT PRIMARY KEY, document BLOB NOT NULL, inbox TEXT NOT NULL, pinned_at TEXT NOT NULL);
CREATE TABLE contact_addresses(address TEXT PRIMARY KEY, doc_id TEXT NOT NULL REFERENCES contacts(doc_id));
CREATE TABLE grants(id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, verbs TEXT NOT NULL, created_at TEXT NOT NULL,
    expires_at INTEGER NOT NULL, closed_at TEXT, close_reason TEXT);
CREATE TABLE owner_acts(id TEXT PRIMARY KEY, at TEXT NOT NULL, what TEXT NOT NULL);
CREATE TABLE approvals(id INTEGER PRIMARY KEY, peer TEXT NOT NULL, thread TEXT NOT NULL, action BLOB NOT NULL,
    request_key TEXT NOT NULL, created_at TEXT NOT NULL, closed_at TEXT, close_reason TEXT, used_by TEXT);
CREATE UNIQUE INDEX open_approval ON approvals(peer,thread,action) WHERE closed_at IS NULL;
CREATE TABLE records(seq INTEGER PRIMARY KEY, direction TEXT NOT NULL CHECK(direction IN ('in','out')),
    recipient TEXT, source TEXT NOT NULL, rid TEXT NOT NULL, thread TEXT NOT NULL, in_reply_to TEXT,
    type TEXT NOT NULL, typ TEXT NOT NULL, jws TEXT NOT NULL, sha256 TEXT NOT NULL, time TEXT NOT NULL,
    expires TEXT, stored_at TEXT NOT NULL, stored_ms INTEGER NOT NULL, grant_id TEXT, actor TEXT, receipt TEXT,
    outcome TEXT, outcome_at TEXT, outcome_code TEXT, rejection_seq INTEGER, apply_count INTEGER NOT NULL DEFAULT 0);
CREATE UNIQUE INDEX inbound_key ON records(recipient,source,rid) WHERE direction='in';
CREATE UNIQUE INDEX outbound_key ON records(source,rid) WHERE direction='out';
CREATE INDEX by_thread ON records(thread,seq);
CREATE INDEX by_rid ON records(rid);
CREATE INDEX by_outcome ON records(outcome,seq);
CREATE TABLE deliveries(seq INTEGER NOT NULL REFERENCES records(seq), recipient TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued', attempts INTEGER NOT NULL DEFAULT 0, next_at INTEGER NOT NULL DEFAULT 0,
    last_result TEXT, last_code TEXT, backoff_ms INTEGER NOT NULL DEFAULT 0, receipt TEXT, delivered_at TEXT, refused_code TEXT, refusal_seq INTEGER,
    PRIMARY KEY(seq,recipient));
CREATE INDEX retry_queue ON deliveries(status,next_at,seq);
CREATE TABLE attempts(id INTEGER PRIMARY KEY, seq INTEGER NOT NULL, recipient TEXT NOT NULL, at TEXT NOT NULL,
    result TEXT NOT NULL, code TEXT, status INTEGER, headers BLOB, body BLOB);
CREATE TABLE apply_log(id INTEGER PRIMARY KEY, seq INTEGER NOT NULL, outcome TEXT NOT NULL, at TEXT NOT NULL);
CREATE TABLE threads(id TEXT PRIMARY KEY, state BLOB NOT NULL, cursor INTEGER NOT NULL);
CREATE TABLE requests(key TEXT PRIMARY KEY, params BLOB NOT NULL, thread TEXT NOT NULL);
CREATE TABLE pairings(side TEXT NOT NULL, nonce TEXT NOT NULL, offer TEXT NOT NULL, answer TEXT, reply TEXT,
    peer_digest TEXT, expires INTEGER NOT NULL, done INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(side,nonce));
"""


class Problem(Exception):
    """A local (owner/agent API) error with an HTTP-like status. Never used on the federation inbox."""

    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def ensure(condition, status, message):
    if not condition:
        raise Problem(status, message)


def json_bytes(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def from_json(data):
    try:
        return wire.strict_json(data if isinstance(data, bytes) else data.encode())
    except wire.Reject as err:
        raise Problem(400, "Expected a strict UTF-8 JSON document") from err


def pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def private_key_from_jwk(jwk):
    key = ec.derive_private_key(int.from_bytes(wire.b64decode(jwk["d"]), "big"), ec.SECP256R1())
    ensure(wire.jwk_from_public_key(key.public_key()) == {k: jwk[k] for k in ("kty", "crv", "x", "y")}, 400, "Key mismatch")
    return key


def origin(value):
    """A provider origin for listening and for the default inbox URL (https-binding.md §1.3)."""
    ensure(isinstance(value, str) and len(value) <= 2048, 400, "Invalid provider origin")
    try:
        url = urlsplit(value)
        port = url.port
    except ValueError as err:
        raise Problem(400, "Invalid provider origin") from err
    ensure(url.hostname and not url.username and not url.password and url.path in ("", "/") and not url.query
           and not url.fragment, 400, "Expected a provider origin")
    ensure(url.scheme == "https" or (url.scheme == "http" and url.hostname in ("127.0.0.1", "::1", "localhost")),
           400, "HTTP is restricted to loopback")
    host = "[" + url.hostname + "]" if ":" in url.hostname else url.hostname
    if port is not None and port != (443 if url.scheme == "https" else 80):
        host += ":" + str(port)
    return url.scheme + "://" + host


def inbox_url(value):
    ensure(isinstance(value, str) and len(value) <= 2048, 400, "Invalid inbox URL")
    url = urlsplit(value)
    ensure(not url.query and not url.fragment and url.path.startswith("/"), 400, "Invalid inbox URL")
    origin(url.scheme + "://" + url.netloc)
    return value


def contact(value):
    """An out-of-band contact: a pinned identity-document snapshot plus its inbox URL (https-binding.md §1.1)."""
    ensure(isinstance(value, dict) and set(value) == {"identity", "inbox"}, 400, "Expected {identity, inbox}")
    try:
        wire.validate_document(value["identity"])
    except wire.PinError as err:
        raise Problem(400, "Invalid identity document: " + str(err)) from err
    return {"identity": value["identity"], "inbox": inbox_url(value["inbox"])}


def init(directory, address, provider_origin, doc_id=None, document=None, private_jwks=None, inbox=None):
    """Create a fresh identity. Without `document`, mint one with a record key and a provider key."""
    ensure(wire.is_account(address), 400, "Invalid account identity")
    root = Path(directory)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    provider_origin = origin(provider_origin)
    inbox = inbox_url(inbox or provider_origin + INBOX_PATH)
    keys = []
    if document is None:
        name, domain = address[5:].split("@")
        doc_id = doc_id or "https://" + domain + "/.well-known/darep/" + name
        stamp = time.strftime("%Y-%m", time.gmtime())
        valid = wire.format_instant(wire.now_ms() // 1000 * 1000)
        entries = []
        for purpose in ("record", "provider"):
            key = ec.generate_private_key(ec.SECP256R1())
            kid = doc_id + "#" + purpose + "-" + stamp
            keys.append((kid, purpose, pem(key)))
            entries.append({"id": kid, "purpose": [purpose], "publicKeyJwk": wire.jwk_from_public_key(key.public_key()),
                            "validFrom": valid})
        document = {"darep": "2", "id": doc_id, "addresses": [address], "updated": valid, "keys": entries}
    else:
        for entry in document["keys"]:
            jwk = (private_jwks or {}).get(entry["id"])
            if jwk:
                keys.append((entry["id"], ",".join(entry["purpose"]), pem(private_key_from_jwk(jwk))))
    try:
        wire.validate_document(document)
    except wire.PinError as err:
        raise Problem(400, "Invalid identity document: " + str(err)) from err
    ensure(address in document["addresses"], 400, "The identity document must list the address")
    # Linking the fully committed, closed DB gives exclusive, atomic publication of identity and schema.
    with tempfile.TemporaryDirectory(dir=root) as temp:
        f = Path(temp) / "peer.sqlite"
        db = sqlite3.connect(f)
        try:
            db.executescript(SCHEMA)
            db.execute("PRAGMA user_version=" + str(SCHEMA_VERSION))
            db.execute("INSERT INTO identity VALUES (?,?,?,?)", (address, json_bytes(document), inbox, provider_origin))
            db.executemany("INSERT INTO keys VALUES (?,?,?)", keys)
            db.commit()
        finally:
            db.close()
        f.chmod(0o600)
        os.link(f, root / "peer.sqlite")
    return {"identity": document, "inbox": inbox}


def write_secret(path, value):
    path = Path(path)
    with tempfile.NamedTemporaryFile(dir=path.parent, mode="wb", delete=False) as file:
        tmp = Path(file.name)
        try:
            file.write(json_bytes(value) + b"\n")
            file.flush()
            os.fsync(file.fileno())
            os.link(tmp, path)
        finally:
            tmp.unlink(missing_ok=True)


def problem_response(code, retry_after=None):
    """https-binding.md §2.3 / §3."""
    status = STATUS[code]
    body = json.dumps(
        {"type": "https://darep.org/problems/" + code, "title": TITLES[code], "status": status, "code": code},
        separators=(",", ":"),
    ).encode()
    headers = {"Content-Type": "application/problem+json", "Cache-Control": "no-store"}
    if code == "method-not-allowed":
        headers["Allow"] = "POST"
    if retry_after is not None:
        headers["Retry-After"] = str(int(retry_after))
    return status, headers, body


STATUS = {
    "malformed": 400, "bad-header": 400, "unsupported-alg": 400, "bad-signature": 400, "unsupported-version": 400,
    "unknown-key": 403, "signer-mismatch": 403, "key-not-valid": 403, "wrong-recipient": 403,
    "method-not-allowed": 405, "id-conflict": 409, "too-large": 413, "unsupported-media-type": 415,
    "expired": 422, "unsupported-extension": 422, "not-yet-valid": 425, "rate-limited": 429, "unavailable": 503,
}
TITLES = {code: code.replace("-", " ").capitalize() for code in STATUS}
# delivery.md §5.1 classes. Everything not listed is permanent.
TRANSIENT_CODES = {"not-yet-valid", "rate-limited", "unavailable"}


class RateLimiter:
    """A small per-source window for check C3 (delivery.md §3.1). Configurable, in memory."""

    def __init__(self, limit=600, window_s=60):
        self.limit, self.window_s = limit, window_s
        self.hits = {}
        self.lock = threading.Lock()

    def __call__(self, source, now_ms):
        with self.lock:
            start = now_ms - self.window_s * 1000
            recent = [t for t in self.hits.get(source, []) if t > start]
            if len(recent) >= self.limit:
                self.hits[source] = recent
                return max(1, (recent[0] - start) // 1000 + 1)
            recent.append(now_ms)
            self.hits[source] = recent
            return None


class Mailbox:
    def __init__(self, directory):
        self.uri = (Path(directory).resolve() / "peer.sqlite").as_uri() + "?mode=rw"
        self.clock = wire.now_ms
        self.capacity = RateLimiter()
        db = self.open()
        try:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            ensure(version == SCHEMA_VERSION, 400, "This store predates Wire v2; create a fresh one with init")
            db.execute("PRAGMA journal_mode=WAL")
            row = db.execute("SELECT * FROM identity").fetchone()
            self.owner = row["address"]
            self.document = wire.strict_json(row["document"])
            self.inbox = row["inbox"]
            self.origin = row["origin"]
            self.keys = {}
            for k in db.execute("SELECT * FROM keys"):
                self.keys[k["kid"]] = serialization.load_pem_private_key(k["private_pem"], password=None)
        finally:
            db.close()
        self.card = {"identity": self.document, "inbox": self.inbox}

    # ---------- storage ----------

    def open(self):
        db = sqlite3.connect(self.uri, uri=True, isolation_level=None, timeout=5, check_same_thread=False)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA synchronous=FULL")  # delivery.md §4.1: a committed transaction survives power loss
        return db

    @contextmanager
    def connection(self, write=False):
        db = self.open()
        try:
            db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def now(self):
        return self.clock()

    def signing_key(self, purpose, at_ms):
        """A key of this identity's document with `purpose`, valid and unrevoked at `at_ms`."""
        for entry in self.document["keys"]:
            if (
                purpose in entry["purpose"]
                and entry["id"] in self.keys
                and "revoked" not in entry
                and wire.instant_ms(entry["validFrom"]) <= at_ms
                and ("validUntil" not in entry or at_ms < wire.instant_ms(entry["validUntil"]))
            ):
                return entry["id"], self.keys[entry["id"]]
        raise Problem(500, "No usable " + purpose + " key")

    def pins(self, db):
        """Pinned contacts plus this identity's own document (to verify our own stored records)."""
        pins = wire.Pins()
        for row in db.execute("SELECT document FROM contacts"):
            pins.add(wire.strict_json(row["document"]))
        return pins

    # ---------- contacts (TA-2, P-0, §5.5) ----------

    def trust(self, value):
        c = contact(value)
        with self.connection(True) as db:
            self.pin(db, c)
        return {"trusted": c["identity"]["addresses"], "id": c["identity"]["id"]}

    def pin(self, db, c):
        doc = c["identity"]
        ensure(self.owner not in doc["addresses"] and doc["id"] != self.document["id"], 400, "Cannot pin this identity")
        row = db.execute("SELECT document FROM contacts WHERE doc_id=?", (doc["id"],)).fetchone()
        if row:
            old = wire.strict_json(row["document"])
            ensure(wire.is_monotonic_update(old, doc), 409, "Not a monotonic update; unpin first (records.md §5.5)")
        for address in doc["addresses"]:
            other = db.execute("SELECT doc_id FROM contact_addresses WHERE address=?", (address,)).fetchone()
            ensure(not other or other["doc_id"] == doc["id"], 409, "Address already belongs to another pinned document")
        db.execute(
            "INSERT INTO contacts VALUES (?,?,?,?) ON CONFLICT(doc_id) DO UPDATE SET document=excluded.document,"
            "inbox=excluded.inbox",
            (doc["id"], json_bytes(doc), c["inbox"], wire.format_instant(self.now())),
        )
        db.executemany("INSERT OR IGNORE INTO contact_addresses VALUES (?,?)", [(a, doc["id"]) for a in doc["addresses"]])

    def contact_for(self, db, address):
        row = db.execute(
            "SELECT c.document,c.inbox FROM contact_addresses a JOIN contacts c USING(doc_id) WHERE a.address=?",
            (address,),
        ).fetchone()
        ensure(row, 404, "Unpaired identity")
        return {"identity": wire.strict_json(row["document"]), "inbox": row["inbox"]}

    def contact(self, address):
        with self.connection() as db:
            return self.contact_for(db, address)

    # ---------- grants (PV-1..PV-5, D5) ----------

    def grant(self, verbs, hours):
        ensure("read" in verbs and set(verbs) <= set(GRANT_VERBS) and 1 <= hours <= 720, 400, "Invalid grant")
        token, grant_id = secrets.token_urlsafe(32), str(uuid.uuid4())
        expires = int(time.time() + hours * 3600)
        with self.connection(True) as db:
            db.execute(
                "INSERT INTO grants(id,token_hash,verbs,created_at,expires_at) VALUES (?,?,?,?,?)",
                (grant_id, wire.digest(token.encode()), ",".join(verbs), wire.format_instant(self.now()), expires),
            )
        return {"id": grant_id, "token": token, "verbs": list(verbs), "url": self.origin + "/local/tools", "expiresAt": expires}

    def revoke(self, grant_id):
        with self.connection(True) as db:
            closed = db.execute(
                "UPDATE grants SET closed_at=?,close_reason='revoked' WHERE id=? AND closed_at IS NULL",
                (wire.format_instant(self.now()), grant_id),
            ).rowcount
        return {"revoked": closed == 1}

    @staticmethod
    def authorize(db, bearer, verb):
        ensure(isinstance(bearer, str) and re.fullmatch(r"Bearer [A-Za-z0-9_-]{43}", bearer), 401, "Valid grant required")
        row = db.execute(
            "SELECT id,verbs FROM grants WHERE token_hash=? AND expires_at>? AND closed_at IS NULL",
            (wire.digest(bearer[7:].encode()), time.time()),
        ).fetchone()
        ensure(row, 401, "Valid grant required")
        wanted = (verb,) if isinstance(verb, str) else verb
        ensure(set(wanted) & set(row["verbs"].split(",")), 403, "Grant lacks the " + " or ".join(wanted) + " verb")
        return row["id"]

    def owner_act(self, db, what):
        act = "owner-" + str(uuid.uuid4())
        db.execute("INSERT INTO owner_acts VALUES (?,?,?)", (act, wire.format_instant(self.now()), what))
        return {"id": act, "actor": "owner"}

    # ---------- receive: verify → store → ack → apply (delivery.md §3) ----------

    def handle_inbox(self, method, headers, body):
        """One delivery under the HTTPS binding. `headers` maps lowercase names to lists of values.

        `body` is the request body, or None when the sender exceeded the size limit. Returns
        (status, headers, body). The receipt is committed before this returns 200.
        """
        # C1. Carrier: method, media type, encoding, exactly one recipient address.
        if method != "POST":
            return problem_response("method-not-allowed")
        types = headers.get("content-type", [])
        if len(types) != 1 or types[0].split(";", 1)[0].strip().lower() != "application/jose":
            return problem_response("unsupported-media-type")
        if any(v.strip().lower() != "identity" for v in headers.get("content-encoding", [])):
            return problem_response("unsupported-media-type")
        recipients = headers.get("darep-recipient", [])
        if len(recipients) != 1 or not wire.is_account(recipients[0]):
            return problem_response("wrong-recipient")
        recipient = recipients[0]
        # C2. Size.
        if body is None or len(body) > MAX_RECORD:
            return problem_response("too-large")
        try:
            jws = body.decode("ascii")
        except UnicodeDecodeError:
            return problem_response("malformed")
        now = self.now()
        try:
            with self.connection() as db:
                pins = self.pins(db)
            # R1–R12 (records.md §8 steps 1–12), then "hosted by this receiver" at R12.
            v = wire.verify_record(jws, (wire.TYP_EVENT, wire.TYP_REJECTION), pins, receiver=recipient, stop_after=12)
            wire.must(recipient == self.owner, "wrong-recipient", "not hosted here")
        except wire.Reject as err:
            return problem_response(err.code)
        try:
            with self.connection(True) as db:
                result = self.store_delivery(db, v, jws, recipient, now)
        except wire.Reject as err:
            return problem_response(err.code)
        except RateLimited as err:
            return problem_response("rate-limited", err.retry_after)
        except sqlite3.Error:
            return problem_response("unavailable", 5)
        # Apply runs only after the response is sent (peer.Handler) or from tick(): never before the ack (§3).
        return 200, {"Content-Type": "application/jose", "Cache-Control": "no-store"}, result["receipt"].encode("ascii")

    def store_delivery(self, db, v, jws, recipient, now):
        r = v.record
        # D. Deduplication on (recipient, source, id), payload digest only (delivery.md §6).
        prior = db.execute(
            "SELECT sha256,receipt FROM records WHERE direction='in' AND recipient=? AND source=? AND rid=?",
            (recipient, r["source"], r["id"]),
        ).fetchone()
        if prior:
            wire.must(hmac.compare_digest(prior["sha256"], v.sha256), "id-conflict", "same id, different payload")
            return {"new": False, "receipt": prior["receipt"]}
        # R13–R14.
        wire.admit_tail(v, now, work.UNDERSTOOD)
        # C3. Capacity.
        retry = self.capacity(r["source"], now)
        if retry is not None:
            raise RateLimited(retry)
        stored_at = wire.format_instant(now)
        receipt_payload = wire.serialize(
            wire.envelope(
                recipient, wire.RECEIPT, [r["source"]], {"sha256": v.sha256, "storedAt": stored_at}, now,
                thread=r["thread"], in_reply_to=r["id"], expires=False,
            )
        )
        kid, key = self.signing_key("provider", now)
        receipt = wire.sign(receipt_payload, key, kid, wire.TYP_RECEIPT)
        grant = r.get("grant") or {}
        db.execute(
            "INSERT INTO records(direction,recipient,source,rid,thread,in_reply_to,type,typ,jws,sha256,time,expires,"
            "stored_at,stored_ms,grant_id,actor,receipt) VALUES ('in',?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (recipient, r["source"], r["id"], r["thread"], r["inReplyTo"], r["type"], v.header["typ"], jws, v.sha256,
             r["time"], r.get("expires"), stored_at, now, grant.get("id"), grant.get("actor"), receipt),
        )
        return {"new": True, "receipt": receipt}

    def apply_ready(self):
        """Apply stored records that have no final outcome yet, in storage order, until nothing changes."""
        with self.connection(True) as db:
            progressed = True
            while progressed:  # a newly applied record can release records that wait on it (§8.2)
                progressed = False
                rows = db.execute(
                    "SELECT * FROM records WHERE direction='in' AND (outcome IS NULL OR outcome='pending') ORDER BY seq"
                ).fetchall()
                for row in rows:
                    if self.apply_one(db, row) != "pending":
                        progressed = True

    def set_outcome(self, db, row, outcome, code=None, detail=None):
        rejection = None
        if outcome == "refused" or (outcome == "unsupported" and code):
            rejection = self.emit_rejection(db, row, code, detail)
        db.execute(
            "UPDATE records SET outcome=?,outcome_at=?,outcome_code=?,rejection_seq=?,"
            "apply_count=apply_count+? WHERE seq=?",
            (outcome, wire.format_instant(self.now()), code, rejection, 0 if outcome == "pending" else 1, row["seq"]),
        )
        if outcome != "pending":
            self.log_apply(db, row["seq"], outcome)
        return outcome

    def log_apply(self, db, seq, outcome):
        db.execute("INSERT INTO apply_log(seq,outcome,at) VALUES (?,?,?)", (seq, outcome, wire.format_instant(self.now())))

    def apply_one(self, db, row):
        r = wire.strict_json(wire.payload_bytes(row["jws"]))
        if row["typ"] == wire.TYP_REJECTION:
            self.apply_rejection(db, row, r)
            return self.set_outcome(db, row, "applied")
        # Causal order for every type: wait until the record named by inReplyTo is stored and applied (§8.2, §8.4).
        if r["inReplyTo"] is not None:
            pred = self.find_record(db, r["inReplyTo"], r["thread"])
            waiting = pred is None or pred["outcome"] in (None, "pending")
            if waiting or row["outcome"] == "pending":
                code = self.hold_expired(row)
                if code:
                    return self.set_outcome(db, row, "refused", code)
            if waiting:
                return "pending" if row["outcome"] == "pending" else self.set_outcome(db, row, "pending")
        if r["type"] == wire.MESSAGE:
            try:
                work.check_message(r["data"])
            except work.Refusal as err:
                return self.set_outcome(db, row, "refused", err.code, err.detail)
            return self.set_outcome(db, row, "applied")
        if r["type"] not in work.KINDS:
            return self.set_outcome(db, row, "unsupported", "unsupported-type")
        state = self.state(db, r["thread"])
        try:
            if KIND(r) != "handoff":
                work.refuse_unless(r["inReplyTo"] is not None, "invalid-transition", "a reply names its predecessor")
                work.refuse_unless(state is not None, "invalid-transition", "no open handoff in this thread")
                work.refuse_unless(r["inReplyTo"] == state["head"], "stale-head", "inReplyTo is not the thread head")
            new_state = work.transition(state, r, self.owner)
        except work.Refusal as err:
            return self.set_outcome(db, row, "refused", err.code, err.detail)
        self.save_state(db, new_state, row["seq"])
        return self.set_outcome(db, row, "applied")

    def find_record(self, db, rid, thread):
        """A record this provider holds, received for this address or sent by it (§8.2), same thread first."""
        return db.execute(
            "SELECT * FROM records WHERE rid=? AND ((direction='in' AND recipient=?) OR direction='out') "
            "AND typ=? ORDER BY thread=? DESC, seq LIMIT 1",
            (rid, self.owner, wire.TYP_EVENT, thread),
        ).fetchone()

    def hold_expired(self, row):
        """The refusal code once a pending record's hold deadline has passed (§8.2), else None."""
        expires = wire.instant_ms(row["expires"])
        hold = row["stored_ms"] + HOLD_MS
        if self.now() < min(expires, hold):
            return None
        return "expired-before-apply" if expires < hold else "missing-predecessor"

    def apply_rejection(self, db, row, r):
        """delivery.md §7.5: record a refusal against our outgoing record if RC-1 holds; otherwise keep as evidence."""
        out = db.execute(
            "SELECT * FROM records WHERE direction='out' AND source=? AND rid=? AND typ=?",
            (self.owner, r["inReplyTo"], wire.TYP_EVENT),
        ).fetchone()
        if not out:
            return
        try:
            wire.correlate(r, wire.TYP_REJECTION, wire.payload_bytes(out["jws"]), "evidence", None)
        except wire.Reject:
            return
        db.execute(
            "UPDATE deliveries SET refused_code=?,refusal_seq=?,status=CASE status WHEN 'queued' THEN 'refused' "
            "ELSE status END WHERE seq=? AND recipient=? AND refusal_seq IS NULL",
            (r["data"]["code"], row["seq"], out["seq"], r["source"]),
        )

    def emit_rejection(self, db, row, code, detail):
        """delivery.md §5.3: one signed rejection per stored record, stored before it is sent."""
        now = self.now()
        data = {"code": code}
        if detail:
            data["detail"] = detail[:1000]
        payload = wire.serialize(
            wire.envelope(row["recipient"], wire.REJECTION, [row["source"]], data, now,
                          thread=row["thread"], in_reply_to=row["rid"])
        )
        kid, key = self.signing_key("provider", now)
        return self.store_outgoing(db, wire.sign(payload, key, kid, wire.TYP_REJECTION), now)

    def tick(self):
        """Hold deadlines (§8.2), give-up at expiry (§7.3), and any apply left after a crash (§3)."""
        now = self.now()
        with self.connection(True) as db:
            for row in db.execute("SELECT * FROM records WHERE direction='in' AND outcome='pending'").fetchall():
                code = self.hold_expired(row)
                if code:
                    self.set_outcome(db, row, "refused", code)
            self.expire_deliveries(db, now)
        self.apply_ready()

    # ---------- send: store once, resend the same bytes (delivery.md §7) ----------

    def store_outgoing(self, db, jws, now, outcome="applied"):
        """Store signed bytes once with one outbox entry per recipient address (§7.1)."""
        v = wire.verify_jws(jws, (wire.TYP_EVENT, wire.TYP_REJECTION), self.own_pins())
        r = v.record
        grant = r.get("grant") or {}
        seq = db.execute(
            "INSERT INTO records(direction,source,rid,thread,in_reply_to,type,typ,jws,sha256,time,expires,stored_at,"
            "stored_ms,grant_id,actor,outcome,outcome_at) VALUES ('out',?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (r["source"], r["id"], r["thread"], r["inReplyTo"], r["type"], v.header["typ"], jws, v.sha256, r["time"],
             r.get("expires"), wire.format_instant(now), now, grant.get("id"), grant.get("actor"), outcome,
             wire.format_instant(now)),
        ).lastrowid
        db.executemany("INSERT INTO deliveries(seq,recipient) VALUES (?,?)", [(seq, to) for to in r["to"]])
        if v.header["typ"] == wire.TYP_EVENT:
            self.log_apply(db, seq, outcome)
        return seq

    def restore_outgoing(self, jws):
        """Store a record this identity already signed (for example from a backup) and apply it locally."""
        with self.connection(True) as db:
            r = wire.verify_jws(jws, (wire.TYP_EVENT,), self.own_pins()).record
            state = self.state(db, r["thread"])
            seq = self.store_outgoing(db, jws, self.now())
            if r["type"] in work.KINDS:
                self.save_state(db, work.transition(state, r, self.owner), seq)
        return seq

    def own_pins(self):
        return wire.Pins([self.document])

    def send(self, db, record_type, to, data, grant, thread=None, in_reply_to=None, required=()):
        now = self.now()
        record = wire.envelope(self.owner, record_type, to, data, now, thread=thread, in_reply_to=in_reply_to,
                               grant=grant, required=required)
        kid, key = self.signing_key("record", now)
        jws = wire.sign(wire.serialize(record), key, kid, wire.TYP_EVENT)
        return record, self.store_outgoing(db, jws, now)

    def due(self):
        """Queued deliveries whose time has come. A record waits for earlier records of its thread to the same
        recipient to be delivered or failed (§8.1)."""
        now = self.now()
        with self.connection() as db:
            return db.execute(
                "SELECT d.*,r.jws,r.sha256,r.thread,r.rid,r.expires FROM deliveries d JOIN records r USING(seq) "
                "WHERE d.status='queued' AND d.next_at<=? AND NOT EXISTS (SELECT 1 FROM deliveries p JOIN records pr "
                "USING(seq) WHERE pr.thread=r.thread AND p.recipient=d.recipient AND pr.seq<r.seq AND p.status='queued') "
                "ORDER BY d.next_at,d.seq LIMIT 8",
                (now,),
            ).fetchall()

    def expire_deliveries(self, db, now):
        for row in db.execute(
            "SELECT d.seq,d.recipient,r.expires FROM deliveries d JOIN records r USING(seq) WHERE d.status='queued'"
        ).fetchall():
            if now >= wire.instant_ms(row["expires"]) + wire.SKEW_MS:
                self.fail_delivery(db, row["seq"], row["recipient"], "expired")

    def fail_delivery(self, db, seq, recipient, code):
        """Mark one delivery failed, and the queued records of its thread to the same recipient whose inReplyTo
        chain depends on it, without attempting them (§7.3 SHOULD)."""
        db.execute(
            "UPDATE deliveries SET status='failed',last_code=? WHERE seq=? AND recipient=? AND status='queued'",
            (code, seq, recipient),
        )
        base = db.execute("SELECT rid,thread FROM records WHERE seq=?", (seq,)).fetchone()
        failed = {base["rid"]}
        for row in db.execute(
            "SELECT r.seq,r.rid,r.in_reply_to FROM deliveries d JOIN records r USING(seq) WHERE r.thread=? "
            "AND d.recipient=? AND d.status='queued' AND r.seq>? ORDER BY r.seq",
            (base["thread"], recipient, seq),
        ).fetchall():
            if row["in_reply_to"] in failed:
                failed.add(row["rid"])
                db.execute(
                    "UPDATE deliveries SET status='failed',last_code='dependency-failed' WHERE seq=? AND recipient=?",
                    (row["seq"], recipient),
                )

    def record_attempt(self, row, result, code=None, status=None, headers=None, body=None, receipt=None, retry_after=None):
        """Store one attempt and its evidence (delivery.md §9.2), then update the delivery (§7.2)."""
        now = self.now()
        with self.connection(True) as db:
            current = db.execute(
                "SELECT status,attempts,backoff_ms FROM deliveries WHERE seq=? AND recipient=?", (row["seq"], row["recipient"])
            ).fetchone()
            if current is None or current["status"] != "queued":
                return
            db.execute(
                "INSERT INTO attempts(seq,recipient,at,result,code,status,headers,body) VALUES (?,?,?,?,?,?,?,?)",
                (row["seq"], row["recipient"], wire.format_instant(now), result, code, status,
                 json_bytes(headers or {}), body),
            )
            attempts = current["attempts"] + 1
            if result == "delivered":
                db.execute(
                    "UPDATE deliveries SET status='delivered',attempts=?,last_result=?,last_code=NULL,receipt=?,"
                    "delivered_at=? WHERE seq=? AND recipient=?",
                    (attempts, result, receipt, wire.format_instant(now), row["seq"], row["recipient"]),
                )
            elif result == "permanent":
                db.execute(
                    "UPDATE deliveries SET attempts=?,last_result=? WHERE seq=? AND recipient=?",
                    (attempts, result, row["seq"], row["recipient"]),
                )
                self.fail_delivery(db, row["seq"], row["recipient"], code or "permanent")
            else:
                # Exponential backoff from 1 s, doubling, capped at 30 min, up to 20% jitter, and never shorter than
                # the previous backoff (§7.2). Retry-After only pushes one attempt later; it is not part of the sequence.
                base = min(BACKOFF_CAP_S, 2 ** min(11, attempts - 1)) * 1000
                delay = max(current["backoff_ms"], base + base * secrets.randbelow(201) // 1000)
                next_at = now + delay
                if retry_after is not None:
                    next_at = max(next_at, now + int(retry_after) * 1000)
                db.execute(
                    "UPDATE deliveries SET attempts=?,last_result=?,last_code=?,next_at=?,backoff_ms=? "
                    "WHERE seq=? AND recipient=?",
                    (attempts, result, code, next_at, delay, row["seq"], row["recipient"]),
                )
                self.expire_deliveries(db, now)

    def check_receipt(self, row, token):
        """delivery.md §7.4: records.md §8 in admission mode plus receipt.source == this delivery's recipient."""
        with self.connection() as db:
            pins = self.pins(db)
        v = wire.verify_record(
            token, (wire.TYP_RECEIPT,), pins, receiver=self.owner, now=self.now(), understood=(),
            answered=wire.payload_bytes(row["jws"]),
        )
        wire.must(v.record["source"] == row["recipient"], "receipt-mismatch", "receipt from another recipient address")
        return v

    # ---------- the handoff application (work/v2) ----------

    @staticmethod
    def state(db, thread):
        row = db.execute("SELECT state FROM threads WHERE id=?", (thread,)).fetchone()
        return {"workflow": work.WORK, **wire.strict_json(row["state"])} if row else None

    @staticmethod
    def save_state(db, state, seq):
        view = {k: v for k, v in state.items() if k != "workflow"}
        db.execute(
            "INSERT INTO threads VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state,cursor=excluded.cursor",
            (state["threadId"], json_bytes(view), seq),
        )

    def allow(self, rule, withdraw=False):
        ensure(isinstance(rule, dict) and isinstance(rule.get("action"), dict), 400, "Expected an approval")
        try:
            a = work.action(rule["action"])
        except ValueError as err:
            raise Problem(400, str(err)) from err
        ensure(a["kind"] in ("handoff", "complete"), 400, "Only disclosure actions require approval")
        completion = a["kind"] == "complete"
        ensure(set(rule) == ({"peer", "threadId", "action"} if completion else {"peer", "action"}), 400,
               "Unexpected or missing fields")
        peer = rule["peer"]
        ensure(wire.is_account(peer), 400, "Invalid account identity")
        thread = rule["threadId"] if completion else ""
        ensure(not completion or wire.is_uuid(thread), 400, "Expected a UUID v4")
        stamp = wire.format_instant(self.now())
        with self.connection(True) as db:
            self.contact_for(db, peer)
            if completion:
                state = self.state(db, thread)
                ensure(state and state["participants"] == [peer, self.owner] and state["turn"] == self.owner, 409,
                       "Expected an open incoming handoff")
            params = (peer, thread, json_bytes(a))
            if withdraw:
                db.execute(
                    "UPDATE approvals SET closed_at=?,close_reason='withdrawn' WHERE peer=? AND thread=? AND action=? "
                    "AND closed_at IS NULL",
                    (stamp, *params),
                )
            else:
                db.execute(
                    "INSERT OR IGNORE INTO approvals(peer,thread,action,request_key,created_at) VALUES (?,?,?,?,?)",
                    (*params, "approval-" + uuid.uuid4().hex, stamp),
                )
        return {"approved": not withdraw}

    def disclose(self, db, peer, thread, a, record_id):
        if a["kind"] in ("handoff", "complete"):
            used = db.execute(
                "UPDATE approvals SET closed_at=?,close_reason='used',used_by=? WHERE peer=? AND thread=? AND action=? "
                "AND closed_at IS NULL",
                (wire.format_instant(self.now()), record_id, peer, thread, json_bytes(a)),
            ).rowcount
            ensure(used == 1, 403, "Owner approval required for exact disclosure")

    def send_work(self, db, state, peer, a, grant_id, thread=None, in_reply_to=None):
        rid = str(uuid.uuid4())
        self.disclose(db, peer, thread or "", a, rid)
        now = self.now()
        record = wire.envelope(
            self.owner, work.TYPE_OF[a["kind"]], [peer], {k: v for k, v in a.items() if k != "kind"}, now,
            thread=thread or rid, in_reply_to=in_reply_to, grant={"id": grant_id, "actor": "agent"},
            required=[work.WORK], rid=rid,
        )
        try:
            new_state = work.transition(state, record, self.owner)
        except work.Refusal as err:
            raise Problem(409, err.detail or err.code) from err
        kid, key = self.signing_key("record", now)
        seq = self.store_outgoing(db, wire.sign(wire.serialize(record), key, kid, wire.TYP_EVENT), now)
        self.save_state(db, new_state, seq)
        return record

    def start(self, db, args, grant_id):
        ensure(isinstance(args, dict) and set(args) == {"requestKey", "peer", "summary", "nextStep", "expectedResult"},
               400, "Unexpected or missing fields")
        key = args["requestKey"]
        ensure(isinstance(key, str) and re.fullmatch(r"[a-zA-Z0-9._-]{1,100}", key), 400, "Invalid request key")
        peer = args["peer"]
        ensure(wire.is_account(peer), 400, "Invalid account identity")
        try:
            a = work.action({"kind": "handoff", **{k: args[k] for k in ("summary", "nextStep", "expectedResult")}})
        except ValueError as err:
            raise Problem(400, str(err)) from err
        serialized = json_bytes([peer, a])
        prior = db.execute("SELECT params,thread FROM requests WHERE key=?", (key,)).fetchone()
        if prior:
            ensure(prior["params"] == serialized, 409, "Request key reused with different content")
            return prior["thread"]
        self.contact_for(db, peer)
        record = self.send_work(db, None, peer, a, grant_id)
        db.execute("INSERT INTO requests VALUES (?,?,?)", (key, serialized, record["thread"]))
        return record["thread"]

    def respond(self, db, args, grant_id):
        ensure(isinstance(args, dict) and set(args) == {"threadId", "expectedHead", "action"}, 400,
               "Unexpected or missing fields")
        thread, parent = args["threadId"], args["expectedHead"]
        ensure(wire.is_uuid(thread) and wire.is_uuid(parent), 400, "Expected a UUID v4")
        try:
            a = work.action(args["action"])
        except ValueError as err:
            raise Problem(400, str(err)) from err
        ensure(a["kind"] != "handoff", 400, "Expected response")
        state = self.state(db, thread)
        ensure(state, 404, "Unknown thread")
        prior = db.execute(
            "SELECT jws FROM records WHERE direction='out' AND thread=? AND in_reply_to=? AND source=? AND typ=?",
            (thread, parent, self.owner, wire.TYP_EVENT),
        ).fetchone()
        if prior:
            r = wire.strict_json(wire.payload_bytes(prior["jws"]))
            if {"kind": work.KINDS.get(r["type"]), **r["data"]} == a:
                return thread  # an idempotent retry of the same response
        ensure(parent == state["head"], 409, "Thread changed; read its head again")
        failed = db.execute(
            "SELECT 1 FROM deliveries JOIN records USING(seq) WHERE thread=? AND (status IN ('failed','refused') "
            "OR refused_code IS NOT NULL)", (thread,)
        ).fetchone()
        ensure(not failed, 409, "An earlier record of this thread failed or was refused")
        peer = next(p for p in state["participants"] if p != self.owner)
        self.send_work(db, state, peer, a, grant_id, thread, parent)
        return thread

    def message(self, peer, text, thread=None, in_reply_to=None):
        """Owner-initiated core/v2#message (actor owner). Agents have no message tool: disclosure needs approval."""
        ensure(isinstance(text, str) and text != "", 400, "Expected message text")
        with self.connection(True) as db:
            self.contact_for(db, peer)
            grant = self.owner_act(db, "message to " + peer)
            record, _ = self.send(db, wire.MESSAGE, [peer], {"text": text}, grant, thread, in_reply_to)
        return {"id": record["id"], "thread": record["thread"]}

    def ready(self, db, row):
        a = wire.strict_json(row["action"])
        approval = {"peer": row["peer"], "action": a}
        if not row["thread"]:
            brief = {key: a[key] for key in ("summary", "nextStep", "expectedResult")}
            return {**approval, "nextTool": "request_handoff",
                    "readyArguments": {"peer": row["peer"], "requestKey": row["request_key"], **brief}}
        state = self.state(db, row["thread"])
        return {**approval, "threadId": row["thread"], "status": state["status"], "nextTool": "respond_handoff",
                "readyArguments": {"threadId": row["thread"], "expectedHead": state["head"], "action": a}}

    def history_row(self, db, r):
        record = wire.strict_json(wire.payload_bytes(r["jws"]))
        item = {
            "record": record,
            "kind": work.KINDS.get(record["type"], record["type"]),
            "direction": "outgoing" if r["direction"] == "out" else "incoming",
            "storedAt": r["stored_at"],
            "outcome": r["outcome"],
            "outcomeCode": r["outcome_code"],
        }
        if r["direction"] == "out":
            d = db.execute("SELECT * FROM deliveries WHERE seq=?", (r["seq"],)).fetchone()
            item.update(
                delivery=d["status"], attempts=d["attempts"], deliveryError=d["last_code"],
                deliveredAt=d["delivered_at"], refusal=d["refused_code"],
                receiptStoredAt=wire.strict_json(wire.payload_bytes(d["receipt"]))["data"]["storedAt"] if d["receipt"] else None,
            )
        else:
            item.update(delivery="received", attempts=0, deliveryError=None, deliveredAt=r["stored_at"], refusal=None)
        return item

    def tool(self, name, args, bearer):
        write = name in ("request_handoff", "respond_handoff")
        with self.connection(write) as db:
            ensure(isinstance(args, dict), 400, "Expected tool arguments")
            before = args.get("before", 9007199254740991)
            ensure(type(before) is int and 0 < before <= 9007199254740991, 400, "Invalid cursor")
            if name == "list_authorized_handoffs":
                self.authorize(db, bearer, ("send", "commit"))
                ensure(set(args) <= {"before"}, 400, "Unexpected fields")
                rows = db.execute(
                    "SELECT * FROM approvals WHERE closed_at IS NULL AND id<? ORDER BY id DESC LIMIT 26", (before,)
                ).fetchall()
                return {"owner": self.owner, "approvals": [self.ready(db, r) for r in rows[:25]],
                        "nextBefore": rows[24]["id"] if len(rows) > 25 else None}
            if name == "list_handoffs":
                self.authorize(db, bearer, "read")
                ensure(set(args) <= {"before"}, 400, "Unexpected fields")
                rows = db.execute(
                    "SELECT state,cursor FROM threads WHERE cursor<? ORDER BY cursor DESC LIMIT 26", (before,)
                ).fetchall()
                return {"owner": self.owner,
                        "threads": [{"workflow": work.WORK, **wire.strict_json(r["state"])} for r in rows[:25]],
                        "nextBefore": rows[24]["cursor"] if len(rows) > 25 else None}
            if name == "list_messages":
                self.authorize(db, bearer, "read")
                ensure(set(args) <= {"before"}, 400, "Unexpected fields")
                rows = db.execute(
                    "SELECT * FROM records WHERE type=? AND seq<? ORDER BY seq DESC LIMIT 26", (wire.MESSAGE, before)
                ).fetchall()
                return {"owner": self.owner, "messages": [self.history_row(db, r) for r in rows[:25]],
                        "nextBefore": rows[24]["seq"] if len(rows) > 25 else None}
            if name == "get_handoff":
                self.authorize(db, bearer, "read")
                ensure(set(args) <= {"threadId", "before"} and "threadId" in args, 400, "Unexpected fields")
                thread = args["threadId"]
                ensure(wire.is_uuid(thread), 400, "Expected a UUID v4")
            elif name == "request_handoff":
                thread = self.start(db, args, self.authorize(db, bearer, "send"))
            elif name == "respond_handoff":
                kind = args.get("action", {}).get("kind") if isinstance(args.get("action"), dict) else None
                grant_id = self.authorize(db, bearer, work.VERB.get(work.TYPE_OF.get(kind), "commit"))
                thread = self.respond(db, args, grant_id)
            else:
                raise Problem(404, "Unknown tool")
            state = self.state(db, thread)
            ensure(state, 404, "Unknown thread")
            rows = db.execute(
                "SELECT * FROM records WHERE thread=? AND typ=? AND seq<? ORDER BY seq DESC LIMIT 26",
                (thread, wire.TYP_EVENT, before),
            ).fetchall()
            history = [self.history_row(db, r) for r in reversed(rows[:25])]
            return {**state, "history": history, "nextBefore": rows[24]["seq"] if len(rows) > 25 else None}


def KIND(record):
    return work.KINDS.get(record["type"])


class RateLimited(Exception):
    def __init__(self, retry_after):
        super().__init__("rate limited")
        self.retry_after = retry_after
