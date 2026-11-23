from __future__ import annotations

import asyncio
import json

from .gateway import Gateway, Session


class Agent:
    """Minimal tool-use loop. It has NO credentials and NO direct server access:
    the only thing it can do is call gateway.call_tool().

    on_event (optional, async): receives {"type": "tool", ...} after each tool call so a UI
    can stream progress."""

    def __init__(self, gateway: Gateway, llm, max_steps: int = 8):
        self.gw, self.llm, self.max_steps = gateway, llm, max_steps

    async def run(self, session: Session, user_message: str, on_event=None) -> dict:
        tools = await self.gw.list_tools(session)
        messages = [{"role": "user", "content": user_message}]
        trace = []
        for _ in range(self.max_steps):
            # LLM clients are synchronous; keep the event loop free while waiting
            blocks = await asyncio.to_thread(self.llm.step, messages, tools)
            messages.append({"role": "assistant", "content": blocks})
            calls = [b for b in blocks if b["type"] == "tool_use"]
            if not calls:
                text = " ".join(b["text"] for b in blocks if b["type"] == "text")
                return {"answer": text, "trace": trace}
            results = []
            for c in calls:
                r = await self.gw.call_tool(session, c["name"], c["input"])
                entry = {"tool": c["name"], "input": c["input"], "ok": r["ok"],
                         "error": r.get("error")}
                trace.append(entry)
                if on_event:
                    await on_event({"type": "tool", **entry, "decision": self.gw.last})
                results.append({"type": "tool_result", "tool_use_id": c["id"],
                                "content": json.dumps(r), "is_error": not r["ok"]})
            messages.append({"role": "user", "content": results})
        return {"answer": "(stopped: step limit reached)", "trace": trace}
