"""Comms MCP server: the dangerous one (data can leave the company through it)."""
from mcp.server.mcpserver import MCPServer

from ..auth import verify_server_token

OUTBOX: list[dict] = []  # stand-in for SMTP; tests inspect this to prove nothing leaked


def build() -> MCPServer:
    s = MCPServer("comms")

    @s.tool()
    def send_email(to: str, subject: str, body: str, caller_token: str) -> dict:
        """Send an email on behalf of the caller."""
        me = verify_server_token(caller_token, "comms")
        if me.role == "employee":
            raise PermissionError("not permitted")
        OUTBOX.append({"from": me.user_id, "to": to, "subject": subject, "body": body})
        return {"status": "queued", "to": to}

    return s
