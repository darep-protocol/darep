"""MCP client entry: the grant file is the only provider credential needed."""

import json
from typing import Literal

from mcp.server.mcpserver import MCPServer
from peer import read_file, tool_call
from pydantic import BaseModel, ConfigDict


class Outcome(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["complete"]
    result: str


class Decision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["accept", "decline"]


def run(grant_file):
    grant = read_file(grant_file)
    server = MCPServer(
        "darep-python-peer",
        version="0.1.0",
        log_level="WARNING",
        instructions="For a handoff, look up the owner's preapproved content to find the peer and fields. "
        "For progress or a reply, list existing handoffs and read the matching thread to find its head. "
        "People use natural language; the tools supply addresses, IDs and exact fields. "
        "Report the returned state. Accepting or completing work needs the commit verb; declining needs send. "
        "This service records work and replies when checked; it does not change a calendar or push notifications.",
    )

    def call(name, args):
        return json.dumps(tool_call(grant, name, args), ensure_ascii=False)

    @server.tool()
    def list_handoffs(before: int | None = None) -> str:
        """First find the matching incoming or outgoing handoff and whose turn it is from the user's description. Use nextBefore for the next page."""
        return call("list_handoffs", {} if before is None else {"before": before})

    @server.tool()
    def get_handoff(threadId: str, before: int | None = None) -> str:
        """Resume an existing handoff. Look up the ID using list_handoffs, then read the history, result and current head here."""
        return call("get_handoff", {"threadId": threadId, **({"before": before} if before else {})})

    verbs = set(grant.get("verbs", []))

    if verbs & {"send", "commit"}:

        @server.tool()
        def list_authorized_handoffs(before: int | None = None) -> str:
            """Call first to send approved work or return a result. For the matching approval, call nextTool with readyArguments verbatim. An opening starts a new discussion and needs no preexisting threadId."""
            return call("list_authorized_handoffs", {} if before is None else {"before": before})

    if "send" in verbs:

        @server.tool()
        def request_handoff(
            peer: str, summary: str, nextStep: str, expectedResult: str, requestKey: str
        ) -> str:
            """Send fields and peer returned by list_authorized_handoffs. Supply a requestKey once and reuse it for retries."""
            return call(
                "request_handoff",
                dict(
                    peer=peer,
                    summary=summary,
                    nextStep=nextStep,
                    expectedResult=expectedResult,
                    requestKey=requestKey,
                ),
            )

    if verbs & {"send", "commit"}:

        @server.tool()
        def respond_handoff(threadId: str, expectedHead: str, action: Decision | Outcome) -> str:
            """Use the ID and current head from get_handoff to accept or decline. For completion, look up the authorized result text via list_authorized_handoffs first."""
            return call(
                "respond_handoff",
                dict(threadId=threadId, expectedHead=expectedHead, action=action.model_dump()),
            )

    server.run(transport="stdio")
