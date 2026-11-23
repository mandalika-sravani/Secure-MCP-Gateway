"""Docs MCP server with classification-based visibility enforced server-side."""
from mcp.server.mcpserver import MCPServer

from ..auth import verify_server_token
from ..data import DOCS


def _visible(me, doc: dict) -> bool:
    if me.role == "admin" or doc["classification"] == "public":
        return True
    if doc["classification"] == "internal":
        return doc["dept"] == me.department
    return False  # confidential: admin only


def build() -> MCPServer:
    s = MCPServer("docs")

    @s.tool()
    def search_docs(query: str, caller_token: str) -> list[dict]:
        """Search document titles and bodies. Returns only documents the caller may see."""
        me = verify_server_token(caller_token, "docs")
        q = query.lower()
        return [{"doc_id": k, "title": d["title"], "classification": d["classification"]}
                for k, d in DOCS.items()
                if _visible(me, d) and (q in d["title"].lower() or q in d["content"].lower())]

    @s.tool()
    def read_doc(doc_id: str, caller_token: str) -> dict:
        """Read one document by id."""
        me = verify_server_token(caller_token, "docs")
        d = DOCS.get(doc_id)
        if d is None or not _visible(me, d):
            raise PermissionError("not found or not permitted")
        return {"doc_id": doc_id, "title": d["title"], "classification": d["classification"],
                "content": d["content"]}

    return s
