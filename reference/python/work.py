"""Record types this peer implements under D8: core/v2#message and the work/v2 handoff lifecycle.

The records layer (wire.py) never looks at `type` or `data`. Everything here runs in the apply step,
after a record is stored and acknowledged (delivery.md §3).
"""

import wire

WORK = "https://darep.org/ext/work/v2"
HANDOFF = WORK + "#handoff"
ACCEPT = WORK + "#accept"
DECLINE = WORK + "#decline"
COMPLETE = WORK + "#complete"
KINDS = {HANDOFF: "handoff", ACCEPT: "accept", DECLINE: "decline", COMPLETE: "complete"}
TYPE_OF = {kind: uri for uri, kind in KINDS.items()}

# Extensions this receiver implements, for `required[]` (records.md §6.2, step 14).
UNDERSTOOD = (wire.CORE, WORK)

# Verb each type needs (records.md PV-3). Accepting work and declaring it complete bind the owner.
VERB = {wire.MESSAGE: "send", HANDOFF: "send", DECLINE: "send", ACCEPT: "commit", COMPLETE: "commit"}

DATA_FIELDS = {"handoff": ("summary", "nextStep", "expectedResult"), "complete": ("result",), "accept": (), "decline": ()}
# Trim the same whitespace as the JavaScript implementation before counting Unicode scalar values.
TRIM_SPACE = "\t\n\v\f\r       　﻿" + "".join(chr(i) for i in range(0x2000, 0x200B))


class Refusal(Exception):
    """An apply-step refusal carrying a post-store code (delivery.md §5.3)."""

    def __init__(self, code, detail=None):
        super().__init__(detail or code)
        self.code = code
        self.detail = detail


def refuse_unless(condition, code, detail=None):
    if not condition:
        raise Refusal(code, detail)


def clean_text(value):
    """Owner/agent input → stored text: trimmed, 1–1000 Unicode scalar values, valid UTF-8."""
    if not isinstance(value, str):
        raise ValueError("Expected text")
    text = value.strip(TRIM_SPACE)
    try:
        text.encode("utf8")
    except UnicodeError as err:
        raise ValueError("Invalid text") from err
    if not 1 <= len(text) <= 1000:
        raise ValueError("Expected 1–1000 Unicode scalar values")
    return text


def action(value):
    """Validate an owner or agent action {kind, ...fields} and return it with trimmed text."""
    if not isinstance(value, dict) or value.get("kind") not in DATA_FIELDS:
        raise ValueError("Unsupported handoff action")
    kind = value["kind"]
    if set(value) != {"kind", *DATA_FIELDS[kind]}:
        raise ValueError("Unexpected or missing fields")
    return {"kind": kind, **{k: clean_text(value[k]) for k in DATA_FIELDS[kind]}}


def check_data(kind, data):
    """T-2: data of a received work record. Invalid data is refused after storage, never before."""
    fields = DATA_FIELDS[kind]
    refuse_unless(isinstance(data, dict) and set(data) == set(fields), "invalid-data", "unexpected or missing data members")
    for name in fields:
        value = data[name]
        refuse_unless(
            isinstance(value, str) and 1 <= len(value.strip(TRIM_SPACE)) and len(value) <= 1000,
            "invalid-data",
            name + " must be 1–1000 characters",
        )
    return {"kind": kind, **{k: data[k] for k in fields}}


def check_message(data):
    refuse_unless(
        isinstance(data, dict) and set(data) == {"text"} and isinstance(data["text"], str) and data["text"] != "",
        "invalid-data",
        "message data is exactly {text}",
    )


def transition(state, record, me):
    """Apply one work record to the thread state. Returns the new state or raises Refusal.

    `state` is None before the opening. Ordering (pending, stale head) is decided by the caller.
    """
    kind = KINDS[record["type"]]
    data = check_data(kind, record["data"])
    actor = record["source"]
    refuse_unless(len(record["to"]) == 1, "invalid-data", "a handoff has exactly one recipient")
    recipient = record["to"][0]
    if kind == "handoff":
        refuse_unless(state is None and record["thread"] == record["id"], "invalid-transition", "a handoff opens a new thread")
        return {
            "threadId": record["thread"],
            "head": record["id"],
            "participants": [actor, recipient],
            "turn": recipient,
            "status": "requested",
            "summary": data["summary"],
            "nextStep": data["nextStep"],
            "expectedResult": data["expectedResult"],
            "result": None,
        }
    refuse_unless(state is not None, "invalid-transition", "no open handoff in this thread")
    refuse_unless(set(state["participants"]) == {actor, recipient}, "wrong-turn", "not a participant of this thread")
    refuse_unless(state["turn"] == actor, "wrong-turn", "not the sender's turn, or the thread is closed")
    status = state["status"]
    if status == "requested" and kind == "accept":
        return {**state, "head": record["id"], "status": "accepted"}
    if status in ("requested", "accepted") and kind == "decline":
        return {**state, "head": record["id"], "status": "declined", "turn": None}
    refuse_unless(status == "accepted" and kind == "complete", "invalid-transition", "accept the handoff before completing it")
    return {**state, "head": record["id"], "status": "completed", "turn": None, "result": data["result"]}
