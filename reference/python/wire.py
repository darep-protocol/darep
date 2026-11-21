"""DAREP Wire v2 signed records (spec/records.md).

This module owns the records layer only: strict JSON, compact JWS framing, the ES256 allow-list,
identity documents and pins (§5), the envelope (§4) and the verification procedure (§8). It never
re-serializes a payload: every check, hash and stored copy uses the exact bytes received (NC1).
"""

import base64
import calendar
import hashlib
import json
import re
import time
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

# ---------- frozen identifiers (D1) ----------

TYP_EVENT = "darep-event+jws"
TYP_RECEIPT = "darep-receipt+jws"
TYP_REJECTION = "darep-rejection+jws"
PURPOSE_FOR_TYP = {TYP_EVENT: "record", TYP_RECEIPT: "provider", TYP_REJECTION: "provider"}
ALGORITHMS = ("ES256",)  # records.md §3.1 A-1: the whole allow-list.

CORE = "https://darep.org/ext/core/v2"
RECEIPT = CORE + "#receipt"
REJECTION = CORE + "#rejection"
MESSAGE = CORE + "#message"

SKEW_MS = 300_000  # records.md §7.2
MAX_WINDOW_MS = 30 * 24 * 3600 * 1000  # records.md TM-2
DEFAULT_EXPIRY_MS = 7 * 24 * 3600 * 1000  # records.md §4.3: senders SHOULD use 7 days
ENVELOPE_MEMBERS = frozenset(
    "darep id source type subject time to thread inReplyTo expires ext required grant data".split()
)
ENVELOPE_REQUIRED = ("id", "source", "type", "time", "to", "thread", "inReplyTo", "ext", "required", "data")
PURPOSES = ("record", "provider", "root", "delegate")

UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
ACCOUNT = re.compile(r"acct:[a-z0-9][a-z0-9._-]{0,62}@" + LABEL + r"(?:\." + LABEL + r")+")
INSTANT = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,3}))?Z")
B64URL = re.compile(r"[A-Za-z0-9_-]*")
HEX64 = re.compile(r"[0-9a-f]{64}")
CODE = re.compile(r"[a-z0-9-]{1,64}")
KEY_FRAGMENT = re.compile(r"[A-Za-z0-9._-]{1,64}")


class Reject(Exception):
    """A verification failure carrying one code from the registry (delivery.md §5)."""

    def __init__(self, code, why=""):
        super().__init__(why or code)
        self.code = code


class PinError(ValueError):
    """An identity document that fails pin validation (records.md P-0)."""


def must(condition, code, why=""):
    if not condition:
        raise Reject(code, why)


# ---------- §2: bytes and strict JSON ----------


def _noncharacter(cp):
    return 0xFDD0 <= cp <= 0xFDEF or (cp & 0xFFFE) == 0xFFFE


def _check_string(s):
    for ch in s:
        cp = ord(ch)
        if 0xD800 <= cp <= 0xDFFF:
            raise Reject("malformed", "unpaired surrogate")
        if _noncharacter(cp):
            raise Reject("malformed", "noncharacter")


def _walk(value):
    if isinstance(value, str):
        _check_string(value)
    elif isinstance(value, list):
        for item in value:
            _walk(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            _check_string(key)
            _walk(item)


def _pairs(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise Reject("malformed", "duplicate member " + json.dumps(key))
        obj[key] = value
    return obj


def _number(text):
    # I-JSON (RFC 7493): numbers must fit an IEEE 754 double.
    as_float = float(text)
    if as_float in (float("inf"), float("-inf")):
        raise Reject("malformed", "number out of range")
    return as_float


def _integer(text):
    _number(text)
    return int(text)


def _constant(_name):
    raise Reject("malformed", "non-standard constant")


def strict_json(data):
    """Parse UTF-8 bytes as I-JSON (records.md §2). Raises Reject('malformed')."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("strict_json takes bytes")
    if data.startswith(b"\xef\xbb\xbf"):
        raise Reject("malformed", "byte order mark")
    try:
        text = bytes(data).decode("utf-8", errors="strict")
    except UnicodeDecodeError as err:
        raise Reject("malformed", "not UTF-8") from err
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_float=_number,
            parse_int=_integer,
            parse_constant=_constant,
        )
    except Reject:
        raise
    except (ValueError, RecursionError) as err:
        raise Reject("malformed", "not JSON") from err
    _walk(value)
    return value


def serialize(value):
    """Serialize an outgoing payload once. The bytes, not this function, are the wire form (C-3)."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def b64encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64decode(segment):
    """Decode one canonical unpadded base64url segment (records.md S-1), or raise Reject('malformed')."""
    must(isinstance(segment, str) and B64URL.fullmatch(segment) and len(segment) % 4 != 1, "malformed", "base64url")
    raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    must(b64encode(raw) == segment, "malformed", "non-canonical base64url")
    return raw


# ---------- time (§7.1) ----------


def instant_ms(value):
    """Milliseconds since the epoch for a TM-1 instant, or None if it is not one."""
    if not isinstance(value, str):
        return None
    m = INSTANT.fullmatch(value)
    if not m:
        return None
    year, month, day, hour, minute, second = (int(x) for x in m.groups()[:6])
    if not (1 <= month <= 12 and 1 <= day <= calendar.monthrange(year, month)[1]):
        return None
    if hour > 23 or minute > 59 or second > 59:  # no leap second
        return None
    if year < 1:
        return None
    millis = int((m.group(7) or "0").ljust(3, "0"))
    return calendar.timegm((year, month, day, hour, minute, second)) * 1000 + millis


def format_instant(ms):
    seconds, millis = divmod(int(ms), 1000)
    base = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(seconds))
    return base + ("." + str(millis).zfill(3) if millis else "") + "Z"


def now_ms():
    return int(time.time() * 1000)


def new_id():
    return str(uuid.uuid4())


# ---------- URIs (K-1, U-1) ----------

# K-1 host grammar, independent of URL parser normalization.
_HOST_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DNS_HOST = re.compile(_HOST_LABEL + r"(?:\." + _HOST_LABEL + r")+")
_NUMERIC_LABEL = re.compile(r"[0-9]+|0x[0-9a-f]*")
_IPV4 = re.compile(r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}")


def is_uri_host(host, test_only=False):
    if not isinstance(host, str):
        return False
    dns = len(host) <= 253 and _DNS_HOST.fullmatch(host) and not _NUMERIC_LABEL.fullmatch(host.rsplit(".", 1)[-1])
    return bool(dns or (test_only and _IPV4.fullmatch(host)))


_PATH_BAD = set(' "#<>?`{}\\')
_QUERY_BAD = set(" \"#<>'")
_FRAGMENT_BAD = set(' "#<>`')


def _printable(s, bad):
    return all(0x21 <= ord(c) <= 0x7E and c not in bad for c in s)


def https_uri(value, fragment, max_len=512, allow_query=True, test_only=False):
    """Validate K-1's literal URI grammar without normalizing signed input."""
    if not isinstance(value, str) or not 1 <= len(value) <= max_len or not value.startswith("https://"):
        return False
    rest = value[len("https://") :]
    frag = None
    if "#" in rest:
        rest, frag = rest.split("#", 1)
    query = None
    if "?" in rest:
        rest, query = rest.split("?", 1)
    slash = rest.find("/")
    if slash < 0:
        return False  # K-1 requires a path
    authority, path = rest[:slash], rest[slash:]
    if "@" in authority:
        return False  # userinfo
    parts = authority.split(":")
    if len(parts) > 2 or not is_uri_host(parts[0], test_only=test_only):
        return False
    if len(parts) == 2:
        port = parts[1]
        if not re.fullmatch(r"[1-9][0-9]{0,4}", port) or int(port) > 65535 or port == "443":
            return False
    if not _printable(path, _PATH_BAD):
        return False
    for seg in path.split("/")[1:]:
        if seg.lower() in (".", "..", "%2e", "%2e%2e", ".%2e", "%2e."):
            return False
    if query is not None and (not allow_query or not _printable(query, _QUERY_BAD)):
        return False
    if frag is None:
        return not fragment
    if not fragment:
        return False
    return len(frag) >= 1 and _printable(frag, _FRAGMENT_BAD)


def is_account(value):
    return isinstance(value, str) and len(value) <= 200 and bool(ACCOUNT.fullmatch(value))


def is_uuid(value):
    return isinstance(value, str) and bool(UUID.fullmatch(value))


def is_text(value, max_len):
    return isinstance(value, str) and 1 <= len(value) <= max_len


def distinct(items):
    return len(set(items)) == len(items)


# ---------- keys and identity documents (§5) ----------


def _coordinate(value):
    if not isinstance(value, str) or len(value) != 43:
        raise PinError("JWK coordinate")
    try:
        raw = b64decode(value)
    except Reject as err:
        raise PinError("JWK coordinate") from err
    return int.from_bytes(raw, "big")


def public_key_from_jwk(jwk):
    if not isinstance(jwk, dict) or set(jwk) != {"kty", "crv", "x", "y"}:
        raise PinError("JWK must have exactly kty, crv, x, y")
    if jwk["kty"] != "EC" or jwk["crv"] != "P-256":
        raise PinError("JWK must be a P-256 key")
    try:
        return ec.EllipticCurvePublicNumbers(_coordinate(jwk["x"]), _coordinate(jwk["y"]), ec.SECP256R1()).public_key()
    except ValueError as err:
        raise PinError("JWK point is not on P-256") from err


def jwk_from_public_key(key):
    numbers = key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64encode(numbers.x.to_bytes(32, "big")),
        "y": b64encode(numbers.y.to_bytes(32, "big")),
    }


def validate_document(doc):
    """P-0 for one document: shape, key ids, JWKs on the curve, purposes, validity (records.md §5.1–5.3)."""
    if not isinstance(doc, dict) or doc.get("darep") != "2":
        raise PinError("identity document must have darep \"2\"")
    if not https_uri(doc.get("id"), fragment=False, max_len=2048, allow_query=False):
        raise PinError("identity document id must be a normalized https URL with no query or fragment")
    addresses = doc.get("addresses")
    if not isinstance(addresses, list) or not addresses or not all(is_account(a) for a in addresses):
        raise PinError("identity document addresses")
    if not distinct(addresses):
        raise PinError("duplicate address")
    if instant_ms(doc.get("updated")) is None:
        raise PinError("updated")
    keys = doc.get("keys")
    if not isinstance(keys, list) or not keys:
        raise PinError("identity document keys")
    seen = set()
    for key in keys:
        if not isinstance(key, dict):
            raise PinError("key entry")
        kid = key.get("id")
        prefix = doc["id"] + "#"
        if not isinstance(kid, str) or not kid.startswith(prefix) or not KEY_FRAGMENT.fullmatch(kid[len(prefix) :]):
            raise PinError("key id " + str(kid))
        if kid in seen:
            raise PinError("duplicate key id " + kid)
        seen.add(kid)
        public_key_from_jwk(key.get("publicKeyJwk"))
        purpose = key.get("purpose")
        if (
            not isinstance(purpose, list)
            or not purpose
            or not all(isinstance(p, str) and p in PURPOSES for p in purpose)
            or not distinct(purpose)
            or (len(purpose) > 1 and any(p in ("root", "delegate") for p in purpose))
        ):
            raise PinError("purpose " + kid)
        start = instant_ms(key.get("validFrom"))
        if start is None:
            raise PinError("validFrom " + kid)
        if "validUntil" in key:
            end = instant_ms(key["validUntil"])
            if end is None or end <= start:
                raise PinError("validUntil " + kid)
        if "revoked" in key and instant_ms(key["revoked"]) is None:
            raise PinError("revoked " + kid)
    return doc


def is_monotonic_update(old, new):
    """records.md §5.5: a re-pin that only adds keys, retires/revokes earlier, and keeps every address."""
    if old["id"] != new["id"] or not set(old["addresses"]) <= set(new["addresses"]):
        return False
    new_keys = {k["id"]: k for k in new["keys"]}
    for key in old["keys"]:
        other = new_keys.get(key["id"])
        if other is None:
            return False
        for member in ("publicKeyJwk", "purpose", "validFrom"):
            if other.get(member) != key.get(member):
                return False
        for member in ("validUntil", "revoked"):
            if member in key and not (member in other and instant_ms(other[member]) <= instant_ms(key[member])):
                return False
    return True


class Pins:
    """The pinned identity-document snapshots a verifier may use (TA-2, P-0..P-3). No network access."""

    def __init__(self, documents=()):
        self.documents = {}
        self.owner_of = {}
        for doc in documents:
            self.add(doc)

    def add(self, doc):
        validate_document(doc)
        if doc["id"] in self.documents:
            raise PinError("a document with this id is already pinned")
        for address in doc["addresses"]:
            if address in self.owner_of:
                raise PinError("address " + address + " already belongs to another pinned document")
        self.documents[doc["id"]] = doc
        for address in doc["addresses"]:
            self.owner_of[address] = doc["id"]

    def resolve(self, kid):
        doc = self.documents.get(kid.split("#", 1)[0])
        if doc is None:
            return None, None
        for key in doc["keys"]:
            if key["id"] == kid:
                return doc, key
        return None, None

    def document_for(self, address):
        doc_id = self.owner_of.get(address)
        return self.documents.get(doc_id) if doc_id else None


# ---------- §3: compact JWS ----------


def sign(payload, private_key, kid, typ):
    """Sign exact payload bytes once (ES256, R||S). The caller stores and resends the result (NC1)."""
    header = serialize({"alg": "ES256", "kid": kid, "typ": typ})
    signing_input = b64encode(header) + "." + b64encode(payload)
    r, s = decode_dss_signature(private_key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256())))
    return signing_input + "." + b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def payload_bytes(jws):
    """The exact payload bytes of a compact JWS that this party already verified or produced."""
    return b64decode(jws.split(".")[1])


class Verified:
    def __init__(self, header, payload, record, document, key):
        self.header = header
        self.payload = payload
        self.record = record
        self.document = document
        self.key = key

    @property
    def sha256(self):
        return digest(self.payload)


def verify_jws(jws, typs, pins):
    """records.md §8 steps 1–7: framing, header, alg, typ/crit/b64/kid, pinned key, signature, payload."""
    # 1. Exactly three canonical base64url segments, header and payload non-empty.
    must(isinstance(jws, str), "malformed", "not text")
    parts = jws.split(".")
    must(len(parts) == 3 and parts[0] != "" and parts[1] != "", "malformed", "not a compact JWS")
    raw_header, raw_payload, signature = (b64decode(p) for p in parts)
    # 2. Strict JSON object.
    header = strict_json(raw_header)
    must(isinstance(header, dict), "malformed", "header is not an object")
    # 3. Allow-list before any key lookup (A-2).
    must(header.get("alg") in ALGORITHMS and isinstance(header.get("alg"), str), "unsupported-alg", str(header.get("alg")))
    # 4. typ expected in this context; no crit or b64; kid is a key URL (K-1).
    must(isinstance(header.get("typ"), str) and header["typ"] in typs, "bad-header", "typ")
    must("crit" not in header and "b64" not in header, "bad-header", "crit/b64")
    must(https_uri(header.get("kid"), fragment=True, max_len=2048), "bad-header", "kid")
    # 5. Resolve only against pins (TA-3: jwk, jku, x5c and the rest are ignored).
    document, key = pins.resolve(header["kid"])
    must(key is not None, "unknown-key", "kid")
    # 6. 64-byte R||S over the ASCII signing input exactly as received.
    must(len(signature) == 64, "bad-signature", "signature length")
    der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
    try:
        public_key_from_jwk(key["publicKeyJwk"]).verify(
            der, (parts[0] + "." + parts[1]).encode("ascii"), ec.ECDSA(hashes.SHA256())
        )
    except InvalidSignature as err:
        raise Reject("bad-signature", "signature") from err
    # 7. Payload is strict JSON, parsed from the verified bytes and never re-serialized.
    record = strict_json(raw_payload)
    must(isinstance(record, dict), "malformed", "payload is not an object")
    return Verified(header, raw_payload, record, document, key)


# ---------- §4: envelope ----------


def check_envelope(r, typ):
    """records.md §4 for the record's typ (step 9). Assumes darep was already checked (E-1)."""
    for member in r:
        must(member in ENVELOPE_MEMBERS, "malformed", "unknown member " + member)
    for member in ENVELOPE_REQUIRED:
        must(member in r, "malformed", "missing " + member)
    must(is_uuid(r["id"]) and is_uuid(r["thread"]), "malformed", "id/thread")
    must(r["inReplyTo"] is None or is_uuid(r["inReplyTo"]), "malformed", "inReplyTo")
    must(r["thread"] != r["id"] or r["inReplyTo"] is None, "malformed", "an opening record has no inReplyTo")
    must(is_account(r["source"]), "malformed", "source")
    must(https_uri(r["type"], fragment=True), "malformed", "type")
    must("subject" not in r or is_text(r["subject"], 200), "malformed", "subject")
    t = instant_ms(r["time"])
    must(t is not None, "malformed", "time")
    to = r["to"]
    must(
        isinstance(to, list)
        and 1 <= len(to) <= 32
        and all(is_account(a) for a in to)
        and distinct(to)
        and r["source"] not in to,
        "malformed",
        "to",
    )
    must(isinstance(r["ext"], dict) and all(https_uri(k, fragment=False) for k in r["ext"]), "malformed", "ext")
    required = r["required"]
    must(
        isinstance(required, list)
        and len(required) <= 32
        and all(https_uri(k, fragment=False) for k in required)
        and distinct(required),
        "malformed",
        "required",
    )
    must(isinstance(r["data"], dict), "malformed", "data")
    kind = {TYP_RECEIPT: "receipt", TYP_REJECTION: "rejection"}.get(typ, "event")
    if kind == "event":
        must(r["type"] not in (RECEIPT, REJECTION), "malformed", "type does not match typ")
    else:
        must(r["type"] == CORE + "#" + kind, "malformed", "type does not match typ")
    if kind == "receipt":
        must("expires" not in r, "malformed", "a receipt has no expires")
    else:
        e = instant_ms(r.get("expires"))
        must(e is not None and t < e <= t + MAX_WINDOW_MS, "malformed", "expires")
    if kind == "event":
        g = r.get("grant")
        must(
            isinstance(g, dict)
            and set(g) == {"id", "actor"}
            and is_text(g["id"], 200)
            and g["actor"] in ("owner", "agent"),
            "malformed",
            "grant",
        )
    else:
        must("grant" not in r, "malformed", "provider records carry no grant")
        must(r["inReplyTo"] is not None and len(to) == 1, "malformed", "a receipt or rejection answers one record")
    if kind == "receipt":
        d = r["data"]
        must(not r["ext"] and not required and "subject" not in r, "malformed", "a receipt carries no ext, required or subject")
        must(
            set(d) == {"sha256", "storedAt"}
            and isinstance(d["sha256"], str)
            and HEX64.fullmatch(d["sha256"])
            and instant_ms(d["storedAt"]) is not None,
            "malformed",
            "receipt data",
        )
    if kind == "rejection":
        d = r["data"]
        code = d.get("code")
        must(
            set(d) <= {"code", "detail"}
            and isinstance(code, str)
            and (CODE.fullmatch(code) or https_uri(code, fragment=True))
            and ("detail" not in d or is_text(d["detail"], 1000)),
            "malformed",
            "rejection data",
        )


# ---------- §8: verification procedure ----------


def correlate(record, typ, answered, mode, now):
    """records.md §8 step 15 (RC-1, TM-4a). `answered` is the answered record's JWS or payload bytes."""
    raw = payload_bytes(answered) if isinstance(answered, str) else answered
    R = strict_json(raw)
    must(
        record["source"] in R["to"]
        and record["to"] == [R["source"]]
        and record["inReplyTo"] == R["id"]
        and record["thread"] == R["thread"],
        "receipt-mismatch",
        "correlation",
    )
    must(instant_ms(record["time"]) >= instant_ms(R["time"]) - SKEW_MS, "receipt-mismatch", "answer predates the record")
    if typ == TYP_RECEIPT:
        must(record["data"]["sha256"] == digest(raw), "receipt-mismatch", "digest")
    # records.md §8 step 15: RC-1 first, then the delivery window. (check.mjs tests the window before the digest;
    # no vector distinguishes the two orders.)
    if typ == TYP_RECEIPT and mode == "admission":
        must(now < instant_ms(R["expires"]) + SKEW_MS, "expired", "delivery window of the answered record has closed")


def verify_record(jws, typs, pins, mode="admission", now=None, receiver=None, understood=(), answered=None, stop_after=None):
    """Run records.md §8 in order and return Verified, or raise Reject with the first failing code.

    mode is "admission" or "evidence" (§7.3). `now` is milliseconds. `stop_after=12` runs steps 1–12 only,
    which a receiver uses so that deduplication can run between steps 12 and 13 (delivery.md §3.1).
    """
    v = verify_jws(jws, typs, pins)
    r, typ = v.record, v.header["typ"]
    # 8. Version first (E-1).
    must(r.get("darep") == "2", "unsupported-version", str(r.get("darep")))
    # 9. Envelope for this typ.
    check_envelope(r, typ)
    # 10. The pinned document lists source (TA-4).
    must(r["source"] in v.document["addresses"], "signer-mismatch", r["source"])
    # 11. Purpose, revocation and validity at the record's own time, no skew (R-4).
    t = instant_ms(r["time"])
    key = v.key
    must(PURPOSE_FOR_TYP[typ] in key["purpose"], "key-not-valid", "purpose")
    must("revoked" not in key, "key-not-valid", "revoked")
    must(
        instant_ms(key["validFrom"]) <= t and ("validUntil" not in key or t < instant_ms(key["validUntil"])),
        "key-not-valid",
        "validity",
    )
    if mode == "admission":
        # 12. This receiver is a recipient.
        must(receiver in r["to"], "wrong-recipient", str(receiver))
        if stop_after == 12:
            return v
        admit_tail(v, now, understood)
    # 15. Correlation, whenever the answered record is known.
    if answered is not None and typ != TYP_EVENT:
        correlate(r, typ, answered, mode, now)
    return v


def admit_tail(v, now, understood):
    """records.md §8 steps 13–14 (admission only)."""
    r, typ = v.record, v.header["typ"]
    must(instant_ms(r["time"]) <= now + SKEW_MS, "not-yet-valid", r["time"])
    if typ != TYP_RECEIPT:
        must(now < instant_ms(r["expires"]) + SKEW_MS, "expired", r["expires"])
    for uri in r["required"]:
        must(uri in understood, "unsupported-extension", uri)


# ---------- building records ----------


def envelope(source, record_type, to, data, now, thread=None, in_reply_to=None, grant=None, required=(), ext=None, expires=True, rid=None):
    """Build an envelope dict. The caller serializes it once and signs the bytes once."""
    rid = rid or new_id()
    value = {
        "darep": "2",
        "id": rid,
        "source": source,
        "type": record_type,
        "time": format_instant(now),
        "to": list(to),
        "thread": thread or rid,
        "inReplyTo": in_reply_to,
    }
    if expires:
        value["expires"] = format_instant(now + DEFAULT_EXPIRY_MS)
    value["ext"] = ext or {}
    value["required"] = list(required)
    if grant is not None:
        value["grant"] = grant
    value["data"] = data
    return value
