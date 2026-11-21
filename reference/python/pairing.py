"""Owner-verified, store-and-forward invite/answer/finish exchange of Wire v2 contacts. No network discovery.

Each message carries the sender's contact ({identity, inbox}) and is signed with that identity's record key.
The signature only proves possession of the key. Trust comes from both owners comparing fingerprints over a
channel they already trust (records.md TA-2): nothing is pinned until both have approved.

Pairing is a local out-of-band step, not a Wire v2 record. Its message format is not part of the spec. The Node
reference provider's owner console uses the same format (media type darep-pairing-v2+jws).
"""

import re
import time
import uuid

import mailbox_db
import wire
from mailbox_db import ensure

MEDIA = "darep-pairing-v2+jws"
TTL_MS = 900_000


def card_hash(card):
    # The whole document, including every key's validity and revocation, plus the inbox: anything an owner
    # would pin. Leaving any member out would let a holder of a revoked key present it as valid.
    return wire.digest(mailbox_db.json_bytes([card["identity"], card["inbox"]]))


def fingerprint(card):
    txt = card_hash(card)[:32].upper()
    return "-".join(txt[i : i + 4] for i in range(0, 32, 4))


def encode(store, kind, nonce, expires, parent=None, recipient=None):
    data = {
        "version": 2,
        "kind": kind,
        "nonce": nonce,
        "expires": expires,
        "parent": parent,
        "to": recipient,
        "address": store.owner,
        "card": store.card,
    }
    kid, key = store.signing_key("record", store.now())
    return wire.sign(mailbox_db.json_bytes(data), key, kid, MEDIA)


def invite(store):
    nonce, now = str(uuid.uuid4()), int(time.time() * 1000)
    expires = now + TTL_MS
    token = encode(store, "invite", nonce, expires)
    with store.connection(True) as db:
        db.execute("DELETE FROM pairings WHERE expires<? AND done=0", (now,))
        db.execute(
            "INSERT INTO pairings(side,nonce,offer,expires) VALUES ('issuer',?,?,?)",
            (nonce, wire.digest(token.encode()), expires),
        )
    return {"code": token, "expires": expires}


def decode(store, token):
    ensure(isinstance(token, str) and 0 < len(token) <= 16384, 400, "Invalid pairing code")
    try:
        unverified = wire.strict_json(wire.payload_bytes(token))
        ensure(isinstance(unverified, dict), 400, "Invalid pairing message")
        candidate = mailbox_db.contact(unverified.get("card"))
        verified = wire.verify_jws(token, (MEDIA,), wire.Pins([candidate["identity"]]))
    except (wire.Reject, wire.PinError, IndexError) as err:
        raise mailbox_db.Problem(400, "Invalid signed pairing code") from err
    msg = verified.record
    ensure(isinstance(msg, dict) and set(msg) == {"version", "kind", "nonce", "expires", "card", "parent", "to", "address"},
           400, "Unexpected pairing fields")
    ensure(type(msg["version"]) is int and msg["version"] == 2 and msg["kind"] in ("invite", "answer", "finish"),
           400, "Unknown pairing message")
    key, at = verified.key, int(time.time() * 1000)
    ensure(
        "record" in key["purpose"]
        and "revoked" not in key
        and wire.instant_ms(key["validFrom"]) <= at
        and ("validUntil" not in key or at < wire.instant_ms(key["validUntil"]))
        and msg["address"] in candidate["identity"]["addresses"],
        400,
        "Pairing code not signed by a currently valid record key of its address",
    )
    ensure(msg["address"] != store.owner, 400, "Use another owner's signed card")
    ensure(wire.is_uuid(msg["nonce"]), 400, "Invalid nonce")
    now = int(time.time() * 1000)
    ensure(type(msg["expires"]) is int and now < msg["expires"] <= now + TTL_MS + 60_000, 410,
           "Pairing code expired or invalid expiry")
    if msg["kind"] == "invite":
        ensure(msg["to"] is None and msg["parent"] is None, 400, "Unexpected invite fields")
    else:
        ensure(msg["to"] == card_hash(store.card) and isinstance(msg["parent"], str)
               and re.fullmatch(r"[0-9a-f]{64}", msg["parent"]), 403, "Code addresses a different owner")
    return {**msg, "card": candidate}


def check(store, db, msg):
    kind, nonce = msg["kind"], msg["nonce"]
    for address in msg["card"]["identity"]["addresses"]:
        existing = db.execute(
            "SELECT c.document FROM contact_addresses a JOIN contacts c USING(doc_id) WHERE a.address=?", (address,)
        ).fetchone()
        ensure(not existing or wire.strict_json(existing["document"])["id"] == msg["card"]["identity"]["id"], 409,
               "Identity pinned to another document")
    if kind == "invite":
        return None
    side, column = ("issuer", "offer") if kind == "answer" else ("guest", "answer")
    row = db.execute("SELECT * FROM pairings WHERE side=? AND nonce=?", (side, nonce)).fetchone()
    ensure(row and row["expires"] == msg["expires"] and row[column] == msg["parent"], 409, "Pairing chain mismatch")
    if kind == "finish":
        ensure(row["peer_digest"] == card_hash(msg["card"]), 403, "Unexpected confirming owner")
    return row


def inspect(store, token):
    msg = decode(store, token)
    with store.connection() as db:
        check(store, db, msg)
    card = msg["card"]
    return {
        "kind": msg["kind"],
        "peer": msg["address"],
        "identity": card["identity"]["id"],
        "inbox": card["inbox"],
        "fingerprint": fingerprint(card),
        "expires": msg["expires"],
    }


def approve(store, token, acknowledged):
    msg = decode(store, token)
    peer = msg["card"]
    ensure(fingerprint(peer) == acknowledged, 400, "Verify the other owner's fingerprint first")
    nonce, expires = msg["nonce"], msg["expires"]
    code_hash, target = wire.digest(token.encode()), card_hash(peer)
    with store.connection(True) as db:
        row = check(store, db, msg)
        if msg["kind"] == "invite":
            answer = encode(store, "answer", nonce, expires, code_hash, target)
            db.execute(
                "INSERT OR IGNORE INTO pairings(side,nonce,offer,answer,reply,peer_digest,expires) VALUES('guest',?,?,?,?,?,?)",
                (nonce, code_hash, wire.digest(answer.encode()), answer, target, expires),
            )
            row = db.execute("SELECT * FROM pairings WHERE side='guest' AND nonce=?", (nonce,)).fetchone()
            ensure(row["offer"] == code_hash and not row["done"], 409, "Invite used or conflicting")
            return {"phase": "answer", "code": row["reply"]}
        if msg["kind"] == "answer":
            if row["answer"]:
                ensure(row["answer"] == code_hash and row["peer_digest"] == target, 409, "Invite already claimed")
                return {"phase": "finish", "code": row["reply"]}
            finish = encode(store, "finish", nonce, expires, code_hash, target)
            store.pin(db, peer)
            db.execute(
                "UPDATE pairings SET answer=?,reply=?,peer_digest=?,done=1 WHERE side='issuer' AND nonce=?",
                (code_hash, finish, target, nonce),
            )
            return {"phase": "finish", "code": finish}
        if not row["done"]:
            store.pin(db, peer)
            db.execute("UPDATE pairings SET done=1 WHERE side='guest' AND nonce=?", (nonce,))
        return {"phase": "paired", "peer": msg["address"]}
