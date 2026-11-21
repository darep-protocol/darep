"""Three-identity black-box smoke test using separate OS processes and fresh private stores (Wire v2).

The Node and Python CLI contract is Wire v2: init/card return {identity, inbox}, grant accepts --verbs,
and deliveries use /darep/v2/inbox with Darep-Recipient. A legacy card is a failing assertion.
"""

import argparse
import asyncio
import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.metadata import version
from pathlib import Path
from queue import Queue
from urllib.parse import parse_qs, urlsplit

import wire
from mcp.client import Client
from mcp.client.stdio import StdioServerParameters
from peer import post

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
NODE = ["node", str(ROOT / "reference/node/src/cli.js")]
PYTHON = [sys.executable, str(HERE / "peer.py")]


def wait_for(fn, timeout=20):
    cutoff = time.monotonic() + timeout
    while time.monotonic() < cutoff:
        result = fn()
        if result:
            return result
        time.sleep(0.1)
    raise AssertionError("Timed out waiting for " + fn.__name__)


def command(argv, ok=True):
    done = subprocess.run(argv, capture_output=True, text=True, timeout=18)
    if ok:
        if done.returncode:
            raise AssertionError(f"{argv[1:3]} failed: {done.stderr.strip()}")
        return json.loads(done.stdout)
    assert done.returncode, "Expected the unauthorized/conflicting call to be refused"


class Host:
    def __init__(self, directory, name, lang, port, backend=None):
        self.root = Path(directory)
        self.addr = "http://127.0.0.1:" + str(port)
        self.id = "acct:" + name + "@" + name + ".test"
        self.dir = self.root / name
        self.grant = self.root / (name + "-grant.json")
        self.card_path = self.root / (name + "-card.json")
        self.cli = NODE if lang == "node" else PYTHON
        self.backend = backend or port
        self.proc = None
        card = command([*self.cli, "init", "--dir", str(self.dir), "--id", self.id, "--origin", self.addr])
        assert isinstance(card, dict) and set(card) == {"identity", "inbox"}, "Expected a Wire v2 contact card"
        self.card_path.write_text(json.dumps(card))
        verbs = "read,send,commit"
        grant = command(
            [*self.cli, "grant", "--dir", str(self.dir), "--output", str(self.grant), "--verbs", verbs]
        )
        self.grant_id = grant["grantId"]

    def operator(self, verb, *args):
        return command([*self.cli, verb, "--dir", str(self.dir), *args])

    def allow(self, action, verb="allow-handoff"):
        path = self.dir / "smoke-owner-rule.json"
        path.write_text(json.dumps(action, ensure_ascii=False))
        self.operator(verb, "--file", str(path))

    def call(self, name, args, ok=True):
        return command(
            [
                *self.cli,
                "call",
                "--grant",
                str(self.grant),
                "--tool",
                name,
                "--json",
                json.dumps(args, ensure_ascii=False),
            ],
            ok=ok,
        )

    def read(self, thread):
        return self.call("get_handoff", {"threadId": thread})

    def wait(self, thread, predicate):
        def await_state():
            value = self.read(thread)
            return value if predicate(value) else None

        return wait_for(await_state)

    def start(self):
        self.proc = subprocess.Popen(
            [*self.cli, "serve", "--dir", str(self.dir), "--port", str(self.backend)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        def ready():
            if self.proc.poll() is not None:
                raise AssertionError("Provider startup failed: " + self.proc.stdout.read())
            try:
                with socket.create_connection(("127.0.0.1", self.backend), timeout=0.1):
                    return True
            except OSError:
                return False

        wait_for(ready)

    def stop(self):
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.communicate(timeout=8)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.communicate(timeout=5)
                raise
            finally:
                self.proc = None


class ReceiptProxy:
    """Drop a committed receipt once. All other operations are forwarded to the real provider."""

    def __init__(self, port, backend):
        proxy = self
        self.seen = []
        self.mode = "pass"
        self.public = "127.0.0.1:" + str(port)
        self.backend = "http://127.0.0.1:" + str(backend)

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                try:
                    body = self.rfile.read(int(self.headers["Content-Length"]))
                    forward = {"Host": proxy.public}
                    for field in ("Authorization", "Accept", "MCP-Protocol-Version", "Mcp-Session-Id"):
                        if self.headers.get(field):
                            forward[field] = self.headers[field]
                    forward["Content-Type"] = self.headers["Content-Type"]
                    if self.headers.get("Darep-Recipient"):
                        forward["Darep-Recipient"] = self.headers["Darep-Recipient"]
                    status, rheaders, result = post(proxy.backend + self.path, body, forward, limit=512 * 1024)
                    media = rheaders.get("content-type", "application/json")
                    if self.path == "/darep/v2/inbox" and status == 200:
                        media = "application/jose"
                        if proxy.mode in ("drop", "observe"):
                            proxy.seen.append(result.decode())
                        if proxy.mode == "drop":
                            # Origin already sent HTTP 200 with a signed receipt. Close before forwarding a byte.
                            self.close_connection = True
                            return
                    self.send_response(status)
                    self.send_header("Content-Type", media)
                    self.send_header("Content-Length", str(len(result)))
                    self.end_headers()
                    self.wfile.write(result)
                except (ConnectionError, OSError):
                    self.close_connection = True

        self.http = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        self.http.shutdown()
        self.http.server_close()
        self.thread.join()


class NodeOwner:
    """Exercise the same loopback capability and JSON actions as the provider's browser console."""

    def __init__(self, host):
        self.proc = subprocess.Popen(
            [*NODE, "operator", "--dir", str(host.dir), "--mode", "attach"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        capability = Queue()

        def read_link():
            for line in self.proc.stdout:
                if line.startswith("http://127.0.0.1:") and "/#key=" in line:
                    capability.put(line.strip())
                    return

        threading.Thread(target=read_link, daemon=True).start()
        try:
            url = urlsplit(capability.get(timeout=10))
            self.origin = url.scheme + "://" + url.netloc
            self.headers = {
                "Origin": self.origin,
                "Authorization": "Bearer " + parse_qs(url.fragment)["key"][0],
            }
        except BaseException:
            self.stop()
            raise

    def action(self, command, data=None):
        status, _, body = post(
            self.origin + "/api/" + command,
            json.dumps(data or {}).encode(),
            {"Content-Type": "application/json", **self.headers},
        )
        assert status == 200, f"Node operator rejected {command}: {status}"
        return json.loads(body)

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.communicate(timeout=6)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.communicate()


class PythonOwner:
    def __init__(self, host):
        self.host = host

    def action(self, command, data=None):
        if command == "state":
            return self.host.operator("fingerprint")
        if command == "invite":
            return self.host.operator("invite")
        code_file = self.host.dir / "pairing-code.txt"
        code_file.write_text(data["code"])
        args = ["--file", str(code_file)]
        if command == "approve":
            args += ["--fingerprint", data["fingerprint"]]
        return self.host.operator(command, *args)


def pair(issuer, guest):
    t = time.monotonic()
    issuer_print = issuer.action("state")["fingerprint"]
    guest_print = guest.action("state")["fingerprint"]
    offer = issuer.action("invite")
    observed = guest.action("inspect", {"code": offer["code"]})
    assert observed["kind"] == "invite" and observed["fingerprint"] == issuer_print
    answer = guest.action("approve", {"code": offer["code"], "fingerprint": issuer_print})
    claim = issuer.action("inspect", {"code": answer["code"]})
    assert claim["kind"] == "answer" and claim["fingerprint"] == guest_print
    finish = issuer.action("approve", {"code": answer["code"], "fingerprint": guest_print})
    ready = guest.action("approve", {"code": finish["code"], "fingerprint": issuer_print})
    assert ready["phase"] == "paired"
    return {
        "method": "15-minute invite/answer/finish with both owner fingerprints",
        "issuer": observed["peer"],
        "guest": claim["peer"],
        "seconds": round(time.monotonic() - t, 3),
    }


def ports(n):
    with ExitStack() as stack:
        sockets = [stack.enter_context(socket.socket()) for _ in range(n)]
        for s in sockets:
            s.bind(("127.0.0.1", 0))
        return [s.getsockname()[1] for s in sockets]


def make_args(key, peer, summary):
    return {
        "requestKey": key,
        "peer": peer.id,
        "summary": summary,
        "nextStep": "Check the approved sample summary.",
        "expectedResult": "Report the findings.",
    }


def allow_request(sender, args):
    sender.allow(
        {
            "peer": args["peer"],
            "action": {"kind": "handoff", **{k: args[k] for k in ("summary", "nextStep", "expectedResult")}},
        }
    )


async def python_mcp(owner, tool, args):
    parameters = StdioServerParameters(
        command=sys.executable, args=[str(HERE / "peer.py"), "stdio", "--grant", str(owner.grant)]
    )
    async with Client(parameters, mode="legacy") as client:
        listing = await client.list_tools()
        assert {t.name for t in listing.tools} >= {"get_handoff", "request_handoff", "respond_handoff"}
        reply = await client.call_tool(tool, args)
        if reply.is_error:
            raise AssertionError("Python MCP tool error: " + str(reply.content))
        return json.loads(reply.content[0].text)


def route(from_host, to_host, args, proxy):
    allow_request(from_host, args)
    # Exact payload approval is enforced by each provider locally.
    from_host.call("request_handoff", {**args, "summary": "unapproved"}, ok=False)
    proxy.seen.clear()
    proxy.mode = "drop"

    def runtime_call(host, tool, parameters):
        if host.cli == PYTHON:
            return asyncio.run(python_mcp(host, tool, parameters))
        return host.call(tool, parameters)

    started = runtime_call(from_host, "request_handoff", args)
    tid = started["threadId"]
    assert from_host.call("request_handoff", args)["threadId"] == tid
    from_host.call("request_handoff", {**args, "requestKey": args["requestKey"] + "-different"}, ok=False)
    pending = from_host.wait(
        tid, lambda s: s["history"][0]["attempts"] >= 1 and s["history"][0]["delivery"] == "queued"
    )
    received = to_host.read(tid)
    assert received["status"] == "requested" and len(received["history"]) == 1 and proxy.seen
    to_host.stop()
    from_host.stop()
    proxy.mode = "observe"
    to_host.start()
    from_host.start()
    delivered = from_host.wait(tid, lambda s: s["history"][0]["delivery"] == "delivered")
    peer_doc = json.loads(to_host.card_path.read_text())["identity"]
    # A duplicate delivery gets the byte-identical stored receipt (delivery.md §6).
    assert len(proxy.seen) >= 2 and len(set(proxy.seen)) == 1
    receipts = [
        wire.verify_record(token, [wire.TYP_RECEIPT], wire.Pins([peer_doc]), mode="evidence").record["data"]
        for token in proxy.seen
    ]
    assert (
        receipts[0]["storedAt"]
        == received["history"][0]["storedAt"]
        == delivered["history"][0]["receiptStoredAt"]
    )
    proxy.mode = "pass"
    state = runtime_call(to_host, "get_handoff", {"threadId": tid})
    assert len(state["history"]) == 1
    accepted = runtime_call(
        to_host,
        "respond_handoff",
        {"threadId": tid, "expectedHead": state["head"], "action": {"kind": "accept"}},
    )
    assert accepted["status"] == "accepted"
    result_action = {"kind": "complete", "result": "I checked the sample summary. Proceed to the next round."}
    command_args = {"threadId": tid, "expectedHead": accepted["head"], "action": result_action}
    to_host.call("respond_handoff", command_args, ok=False)
    to_host.allow({"peer": from_host.id, "threadId": tid, "action": result_action})
    complete = runtime_call(to_host, "respond_handoff", command_args)
    assert complete["status"] == "completed"
    assert to_host.call("respond_handoff", command_args)["head"] == complete["head"]
    final = from_host.wait(tid, lambda s: s["status"] == "completed")
    assert final["head"] == complete["head"] and final["result"] == result_action["result"]
    assert [row["kind"] for row in final["history"]] == [
        "handoff",
        "accept",
        "complete",
    ]
    return {
        "sender": from_host.id,
        "recipient": to_host.id,
        "threadId": tid,
        "result": final["result"],
        "events": [
            {
                "kind": r["kind"],
                "time": r["record"]["time"],
                "recordId": r["record"]["id"],
            }
            for r in final["history"]
        ],
        "sameHead": final["head"],
        "firstCommitAt": receipts[0]["storedAt"],
        "senderAttemptsAtDrop": pending["history"][0]["attempts"],
        "senderAttemptsAtVerifiedDelivery": delivered["history"][0]["attempts"],
        "matchingCommittedReceipts": len(receipts),
        "inboxEntriesAfterReplay": len(state["history"]),
    }


def scenario():
    started = wire.format_instant(wire.now_ms())
    a_port, b_port, c_port, b_backend, c_backend = ports(5)
    with tempfile.TemporaryDirectory(prefix="darep-interop-") as root, ExitStack() as stack:
        a = Host(root, "alice", "node", a_port)
        b = Host(root, "bob", "node", b_port, b_backend)
        c = Host(root, "carol", "python", c_port, c_backend)
        bp = ReceiptProxy(b_port, b_backend)
        cp = ReceiptProxy(c_port, c_backend)
        stack.callback(bp.stop)
        stack.callback(cp.stop)
        for host in (a, b, c):
            stack.callback(host.stop)
        for host in (a, b, c):
            host.start()
        a_panel = NodeOwner(a)
        stack.callback(a_panel.stop)
        b_panel = NodeOwner(b)
        stack.callback(b_panel.stop)
        ab_pair = pair(a_panel, b_panel)
        bc_pair = pair(b_panel, PythonOwner(c))
        occurrence = {
            "activity": "Synthetic padel",
            "originalStart": "2030-04-06T09:00:00Z",
            "durationMinutes": 60,
            "slots": ["2030-04-07T13:00:00Z"],
        }
        for host, other in ((a, b), (b, a)):
            host.allow({"peer": other.id, **occurrence}, "allow-times")
        plan = a.call("request_reschedule", {"requestKey": "ab-padel", "peer": b.id, **occurrence})
        # A-B is still open while B-C hands work off in both directions.
        bc = route(b, c, make_args("node-python", c, "Sample project summary from the Node provider to the Python provider."), cp)
        cb = route(c, b, make_args("python-node", b, "The Python provider opened a new thread for the return handoff."), bp)
        a.call("get_handoff", {"threadId": bc["threadId"]}, ok=False)
        c.call("get_handoff", {"threadId": plan["threadId"]}, ok=False)
        assert a.call("list_handoffs", {})["threads"] == []
        at_b = b.call("get_reschedule", {"threadId": plan["threadId"]})
        accepted = b.call(
            "respond_reschedule",
            {"threadId": plan["threadId"], "expectedHead": at_b["head"], "action": {"kind": "accept"}},
        )
        choice = b.call(
            "respond_reschedule",
            {
                "threadId": plan["threadId"],
                "expectedHead": accepted["head"],
                "action": {"kind": "confirm", "slot": occurrence["slots"][0]},
            },
        )

        def visible():
            s = a.call("get_reschedule", {"threadId": plan["threadId"]})
            return s if s["head"] == choice["head"] else None

        candidate = wait_for(visible)
        final = a.call(
            "respond_reschedule",
            {
                "threadId": plan["threadId"],
                "expectedHead": candidate["head"],
                "action": {"kind": "confirm", "slot": occurrence["slots"][0]},
            },
        )
        wait_for(lambda: b.call("get_reschedule", {"threadId": plan["threadId"]})["head"] == final["head"])
        assert final["status"] == "confirmed"
        return {
            "startedAt": started,
            "finishedAt": wire.format_instant(wire.now_ms()),
            "fixture": "three processes with independent identities and databases on one loopback host",
            "clients": "Node official SDK via MCP CLI, Python MCP SDK via stdio; scripted synthetic inputs",
            "node": subprocess.check_output(["node", "--version"], text=True).strip(),
            "python": sys.version.split()[0],
            "wire": "DAREP Wire v2 (spec v0.1)",
            "dependencies": {name: version(name) for name in ("cryptography", "mcp")},
            "pairings": [ab_pair, bc_pair],
            "nodeToPython": bc,
            "pythonToNode": cb,
            "aliceCouldReadBobCarol": False,
            "abReschedule": {
                "threadId": plan["threadId"],
                "status": final["status"],
                "time": final["selectedSlot"],
            },
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = json.dumps(scenario(), ensure_ascii=False, indent=2)
    print(report)
    if args.output:
        args.output.write_text(report + "\n")
