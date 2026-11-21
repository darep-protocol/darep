"""Run a separately owned Wire v2 provider; use a grant for agent-facing commands."""

import argparse
import http.client
import json
import os
import re
import signal
import socket
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import mailbox_db
import wire
from mailbox_db import Problem

RESPONSE_LIMIT = 65_536  # https-binding.md §4: never read more than this of a response body


def read_file(path):
    return mailbox_db.from_json(Path(path).read_bytes())


def post(url, body, headers, limit=RESPONSE_LIMIT, timeout=10):
    """POST without following redirects. Returns (status, lowercase headers, body)."""
    parts = urlsplit(url)
    if parts.scheme == "http":
        mailbox_db.ensure(parts.hostname in ("127.0.0.1", "::1", "localhost"), 400, "HTTP is restricted to loopback")
        cls = http.client.HTTPConnection
    else:
        mailbox_db.ensure(parts.scheme == "https", 400, "Expected an https URL")
        cls = http.client.HTTPSConnection
    conn = cls(parts.hostname, parts.port, timeout=timeout)
    try:
        conn.request("POST", parts.path + ("?" + parts.query if parts.query else ""), body, headers)
        res = conn.getresponse()
        data = res.read(limit + 1)
        return res.status, {k.lower(): v for k, v in res.getheaders()}, data[: limit + 1]
    finally:
        conn.close()


def classify(status, headers, body):
    """https-binding.md §3: by registry code when the body is a problem document with one, else by status."""
    code = None
    if headers.get("content-type", "").split(";")[0].strip().lower() == "application/problem+json":
        try:
            problem = wire.strict_json(body)
            if isinstance(problem, dict) and isinstance(problem.get("code"), str) and problem["code"] in mailbox_db.STATUS:
                code = problem["code"]
        except wire.Reject:
            pass
    if code:
        return ("transient" if code in mailbox_db.TRANSIENT_CODES else "permanent"), code
    if status in (408, 425, 429) or 500 <= status <= 599 or 300 <= status <= 399:
        return "transient", None
    return "permanent", None


def retry_after(headers):
    value = headers.get("retry-after", "")
    return int(value) if re.fullmatch(r"[0-9]{1,10}", value) else None


def attempt(store, row, send=None):
    """One delivery attempt of stored bytes (delivery.md §7.2). `send` replaces the HTTP call in tests."""
    if store.now() >= wire.instant_ms(row["expires"]) + wire.SKEW_MS:
        with store.connection(True) as db:
            store.fail_delivery(db, row["seq"], row["recipient"], "expired")
        return "failed"
    with store.connection() as db:
        current = db.execute("SELECT status FROM deliveries WHERE seq=? AND recipient=?",
                             (row["seq"], row["recipient"])).fetchone()
    if current["status"] != "queued":
        return current["status"]  # delivered, failed or refused since it was selected: never resend
    try:
        contact = store.contact(row["recipient"])
        headers = {"Content-Type": "application/jose", "Darep-Recipient": row["recipient"]}
        status, rheaders, body = (send or post)(contact["inbox"], row["jws"].encode("ascii"), headers)
    except (OSError, http.client.HTTPException, Problem) as err:
        store.record_attempt(row, "transient", code=None, headers={"error": type(err).__name__})
        return "transient"
    kept = {k: rheaders[k] for k in ("content-type", "retry-after", "location") if k in rheaders}
    if len(body) > RESPONSE_LIMIT:
        store.record_attempt(row, "transient", status=status, headers=kept)
        return "transient"
    if 200 <= status <= 299:
        # 200 is the only success status; any other 2xx, or a 200 whose body is not a valid receipt, is a mismatch.
        try:
            wire.must(status == 200, "receipt-mismatch", "non-200 success status")
            token = body.decode("ascii")
            store.check_receipt(row, token)
        except (wire.Reject, UnicodeDecodeError) as err:
            code = err.code if isinstance(err, wire.Reject) else "malformed"
            store.record_attempt(row, "receipt-mismatch", code=code, status=status, headers=kept, body=body)
            return "receipt-mismatch"
        store.record_attempt(row, "delivered", status=status, headers=kept, body=body, receipt=token)
        return "delivered"
    result, code = classify(status, rheaders, body)
    store.record_attempt(row, result, code=code, status=status, headers=kept, body=body, retry_after=retry_after(rheaders))
    return result


class Server(ThreadingHTTPServer):
    daemon_threads = True
    tls_context = None

    def get_request(self):
        sock, addr = super().get_request()
        sock.settimeout(10)
        if self.tls_context:
            try:
                # The request thread handles the handshake on its first read, under the socket timeout.
                sock = self.tls_context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
            except Exception:
                sock.close()
                raise
        return sock, addr


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        # Access logs must not retain bearer headers or delegated handoff content.
        pass

    def reply(self, status, body, headers=None):
        self.send_response(status)
        for name, value in {"Content-Type": "application/json", "Cache-Control": "no-store", **(headers or {})}.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def read_limited(self, limit):
        """Read the body, stopping at limit + 1 octets (https-binding.md §2.1). None means too large."""
        lengths = self.headers.get_all("Content-Length", [])
        if "chunked" in ",".join(self.headers.get_all("Transfer-Encoding", [])).lower():
            data = b""
            while True:
                size_line = self.rfile.readline(64)
                try:
                    size = int(size_line.split(b";")[0].strip(), 16)
                except ValueError:
                    self.close_connection = True
                    return b""
                if size == 0:
                    self.rfile.readline(64)
                    return data
                if len(data) + size > limit:
                    self.close_connection = True
                    return None
                data += self.rfile.read(size)
                self.rfile.readline(64)
        if len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,10}", lengths[0]):
            self.close_connection = True
            return b""
        size = int(lengths[0])
        if size > limit:
            self.close_connection = True
            return None
        return self.rfile.read(size)

    def local_origin_check(self):
        origin = self.server.store.origin
        mailbox_db.ensure(self.headers.get_all("Host") == [urlsplit(origin).netloc], 400, "Unknown host")
        mailbox_db.ensure(self.headers.get_all("Origin", []) in ([], [origin]), 403, "Unknown origin")

    def dispatch(self):
        store = self.server.store
        path = urlsplit(self.path).path
        if path == mailbox_db.INBOX_PATH:
            headers = {k.lower(): self.headers.get_all(k) for k in set(self.headers.keys())}
            body = self.read_limited(mailbox_db.MAX_RECORD) if self.command == "POST" else b""
            status, rheaders, rbody = store.handle_inbox(self.command, headers, body)
            self.reply(status, rbody, rheaders)
            if status == 200:
                # Apply only after the receipt is on the wire (delivery.md §3). The worker's tick() retries it.
                try:
                    store.apply_ready()
                except Exception as err:
                    print("Apply deferred:", type(err).__name__, err, file=sys.stderr, flush=True)
            return None
        if path == urlsplit(store.document["id"]).path and self.command in ("GET", "HEAD"):
            # https-binding.md §5.2: RECOMMENDED in A1, for comparing pins; never fetched to verify.
            body = mailbox_db.json_bytes(store.document)
            return self.reply(200, b"" if self.command == "HEAD" else body,
                              {"Cache-Control": "max-age=300", "Access-Control-Allow-Origin": "*"})
        if self.command == "GET" and path == "/health":
            return self.reply(200, b'{"status":"ok"}')
        if path != "/local/tools":
            return self.reply(404, b"")
        self.local_origin_check()
        mailbox_db.ensure(self.command == "POST", 405, "POST required")
        mailbox_db.ensure(self.headers.get_content_type() == "application/json", 415, "Unexpected content type")
        data = self.read_limited(512 * 1024)
        mailbox_db.ensure(data is not None, 413, "Payload too large")
        bearer = self.headers.get("Authorization")
        with store.connection() as db:
            store.authorize(db, bearer, "read")
        value = mailbox_db.from_json(data)
        mailbox_db.ensure(isinstance(value, dict) and set(value) == {"name", "arguments"}, 400, "Expected name and arguments")
        mailbox_db.ensure(isinstance(value["name"], str), 400, "Expected tool name")
        result = store.tool(value["name"], value["arguments"], bearer)
        return self.reply(200, mailbox_db.json_bytes(result))

    def handle_call(self):
        try:
            self.dispatch()
        except Problem as err:
            self.reply(err.status, mailbox_db.json_bytes({"error": str(err)}))
        except (ConnectionError, TimeoutError):
            self.close_connection = True
        except Exception as err:
            print("Request failed:", type(err).__name__, file=sys.stderr, flush=True)
            self.reply(500, b'{"error":"Internal provider error"}')

    do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_TRACE = do_CONNECT = handle_call


def serve(store, args):
    addr = urlsplit(store.origin)
    mailbox_db.ensure(bool(args.tls_cert) == bool(args.tls_key), 400, "Pass both --tls-cert and --tls-key")
    mailbox_db.ensure(args.host in ("127.0.0.1", "::1", "localhost") or args.tls_cert, 400,
                      "Use TLS for an externally bound listener; plain HTTP runs on loopback")
    mailbox_db.ensure(not args.tls_cert or addr.scheme == "https", 400, "TLS listener requires an HTTPS origin")
    mailbox_db.ensure(args.port is None or 1 <= args.port <= 65535, 400, "Invalid listening port")
    server_class = Server
    if ":" in args.host:

        class ServerV6(Server):
            address_family = socket.AF_INET6

        server_class = ServerV6
    stop = threading.Event()
    with server_class((args.host, args.port or addr.port or 3100), Handler) as server:
        if args.tls_cert:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(args.tls_cert, args.tls_key)
            server.tls_context = context
        server.store = store
        server.timeout = 0.2

        def worker():
            while not stop.is_set():
                try:
                    store.tick()
                    for row in store.due():
                        if stop.is_set():
                            break
                        attempt(store, row)
                except Exception as err:
                    print("Worker failed:", type(err).__name__, err, file=sys.stderr, flush=True)
                stop.wait(0.2)

        signal.signal(signal.SIGTERM, lambda *_: stop.set())
        signal.signal(signal.SIGINT, lambda *_: stop.set())
        thread = threading.Thread(target=worker, name="outbox", daemon=True)
        thread.start()
        print("Python provider ready:", store.owner, flush=True)
        try:
            while not stop.is_set():
                server.handle_request()
        finally:
            stop.set()
            thread.join()


def tool_call(grant, name, arguments):
    mailbox_db.ensure(
        isinstance(grant, dict)
        and isinstance(grant.get("url"), str)
        and isinstance(grant.get("token"), str)
        and re.fullmatch(r"[A-Za-z0-9_-]{43}", grant["token"]),
        400,
        "Invalid runtime grant",
    )
    orig = mailbox_db.origin(grant["url"].removesuffix("/local/tools"))
    mailbox_db.ensure(grant["url"] == orig + "/local/tools", 400, "Unexpected grant endpoint")
    status, _, data = post(
        grant["url"],
        mailbox_db.json_bytes({"name": name, "arguments": arguments}),
        {"Content-Type": "application/json", "Authorization": "Bearer " + grant["token"]},
        limit=512 * 1024,
    )
    result = mailbox_db.from_json(data)
    if status != 200:
        raise Problem(status, result.get("error", "Provider rejected the request"))
    return result


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    names = ("init", "card", "trust", "grant", "revoke", "allow-handoff", "message", "serve", "call", "stdio",
             "fingerprint", "invite", "inspect", "approve")
    for name in names:
        p = commands.add_parser(name)
        if name in ("call", "stdio"):
            p.add_argument("--grant", required=True)
        else:
            p.add_argument("--dir", required=True)
        if name == "init":
            p.add_argument("--id", required=True, help="acct: address")
            p.add_argument("--origin", required=True, help="Provider origin; the inbox is <origin>/darep/v2/inbox")
            p.add_argument("--doc-id", help="Identity document URL (default https://<domain>/.well-known/darep/<name>)")
        elif name == "trust":
            p.add_argument("--card", required=True, help="JSON file {identity, inbox}")
        elif name in ("inspect", "approve"):
            p.add_argument("--file", required=True, help="File containing the signed pairing code or its JSON wrapper")
            if name == "approve":
                p.add_argument("--fingerprint", required=True)
        elif name == "allow-handoff":
            p.add_argument("--file", required=True)
            p.add_argument("--withdraw", action="store_true")
        elif name == "message":
            p.add_argument("--peer", required=True)
            p.add_argument("--text", required=True)
        elif name == "grant":
            p.add_argument("--output", required=True)
            p.add_argument("--verbs", default="read", help="Comma-separated: read, send, commit")
            p.add_argument("--hours", type=int, default=168)
        elif name == "revoke":
            p.add_argument("--id", required=True)
        elif name == "call":
            p.add_argument("--tool", required=True)
            group = p.add_mutually_exclusive_group()
            group.add_argument("--json", default="{}")
            group.add_argument("--file")
        elif name == "serve":
            p.add_argument("--host", default="127.0.0.1")
            p.add_argument("--port", type=int)
            p.add_argument("--tls-cert")
            p.add_argument("--tls-key")
    args = parser.parse_args()
    if args.command == "init":
        return mailbox_db.init(args.dir, args.id, args.origin, doc_id=args.doc_id)
    if args.command == "call":
        data = read_file(args.file) if args.file else mailbox_db.from_json(args.json.encode())
        return tool_call(read_file(args.grant), args.tool, data)
    if args.command == "stdio":
        from agent_stdio import run

        return run(args.grant)
    store = mailbox_db.Mailbox(args.dir)
    if args.command == "card":
        return store.card
    if args.command in ("fingerprint", "invite", "inspect", "approve"):
        import pairing

        if args.command == "fingerprint":
            return {"fingerprint": pairing.fingerprint(store.card)}
        if args.command == "invite":
            return pairing.invite(store)
        with open(args.file, encoding="utf8") as file:
            text = file.read(16385).strip()
        mailbox_db.ensure(len(text) <= 16384, 400, "Pairing code too large")
        code = mailbox_db.from_json(text.encode()).get("code") if text.startswith("{") else text
        if args.command == "inspect":
            return pairing.inspect(store, code)
        return pairing.approve(store, code, args.fingerprint)
    if args.command == "serve":
        return serve(store, args)
    if args.command == "trust":
        return store.trust(read_file(args.card))
    if args.command == "allow-handoff":
        return store.allow(read_file(args.file), args.withdraw)
    if args.command == "message":
        return store.message(args.peer, args.text)
    if args.command == "revoke":
        return store.revoke(args.id)
    grant = store.grant(args.verbs.split(","), args.hours)
    try:
        mailbox_db.write_secret(args.output, grant)
    except Exception:
        store.revoke(grant["id"])
        raise
    return {"grantId": grant["id"], "verbs": grant["verbs"], "output": args.output}


if __name__ == "__main__":
    try:
        output = main()
        if output is not None:
            print(json.dumps(output, ensure_ascii=False))
    except (Problem, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
