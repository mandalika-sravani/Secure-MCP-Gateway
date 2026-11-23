from . import comms, docs, hr


def build_all():
    """name -> MCPServer. Each server enforces data scope itself (defense in depth)."""
    return {"hr": hr.build(), "docs": docs.build(), "comms": comms.build()}
