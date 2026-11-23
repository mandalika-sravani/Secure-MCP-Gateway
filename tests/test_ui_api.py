"""API tests for the web UI backend (no browser, no API key)."""
import asyncio
import json

import httpx
import pytest

pytest.importorskip("fastapi")

from ui import server  # noqa: E402
from secure_mcp.servers import comms  # noqa: E402


def run_ui(fn, tmp_path, monkeypatch):
    monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "ui_audit.jsonl"))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    comms.OUTBOX.clear()

    async def main():
        async with server.app.router.lifespan_context(server.app):
            transport = httpx.ASGITransport(app=server.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
                return await fn(c)
    return asyncio.run(main())


def events(resp):
    return [json.loads(line[6:]) for line in resp.text.splitlines() if line.startswith("data: ")]


async def chat(c, user, scenario, auto_approve=None):
    """Run a replay scenario. If auto_approve is True/False, answer approval prompts like a human would."""
    async def approver():
        while True:
            for aid in list(server.PENDING):
                await c.post("/api/approve", json={"id": aid, "approve": auto_approve})
                return
            await asyncio.sleep(0.01)
    task = asyncio.create_task(approver()) if auto_approve is not None else None
    r = await c.post("/api/chat", json={"user": user, "mode": "replay", "scenario": scenario})
    if task:
        task.cancel()  # in egress-blocked runs no approval is ever requested, and that's the point
    assert r.status_code == 200
    return events(r)


def test_tools_depend_on_role(tmp_path, monkeypatch):
    async def f(c):
        carol = {t["name"] for t in (await c.get("/api/tools/carol")).json()}
        alice = {t["name"] for t in (await c.get("/api/tools/alice")).json()}
        assert "comms__send_email" not in carol and "comms__send_email" in alice
        assert "hr__export_all_salaries" not in alice
        assert (await c.get("/api/tools/nobody")).status_code == 404
    run_ui(f, tmp_path, monkeypatch)


def test_same_question_three_users(tmp_path, monkeypatch):
    async def f(c):
        res = {}
        for u in ["alice", "bob", "frank"]:
            ev = await chat(c, u, "salary")
            res[u] = [e["ok"] for e in ev if e["type"] == "tool"]
        assert res == {"alice": [True], "bob": [True], "frank": [False]}
    run_ui(f, tmp_path, monkeypatch)


def test_denied_event_carries_the_real_reason_for_the_ui(tmp_path, monkeypatch):
    async def f(c):
        ev = await chat(c, "frank", "bands")
        tool = next(e for e in ev if e["type"] == "tool")
        assert not tool["ok"] and "server_denied" in tool["decision"]["reason"]
    run_ui(f, tmp_path, monkeypatch)


def test_poisoned_doc_attack_is_blocked_end_to_end(tmp_path, monkeypatch):
    async def f(c):
        ev = await chat(c, "bob", "attack", auto_approve=True)  # even a human "yes" must not help
        tools = [e for e in ev if e["type"] == "tool"]
        assert [t["ok"] for t in tools] == [True, True, False]
        assert "egress_blocked" in tools[2]["decision"]["reason"]
        answer = next(e for e in ev if e["type"] == "answer")
        assert answer["state"]["injection_seen"] and "restricted" in answer["state"]["taints"]
        assert comms.OUTBOX == []
    run_ui(f, tmp_path, monkeypatch)


def test_approval_flow_yes_and_no(tmp_path, monkeypatch):
    async def f(c):
        ev = await chat(c, "bob", "email", auto_approve=False)
        assert [e["ok"] for e in ev if e["type"] == "tool"] == [False] and comms.OUTBOX == []
        await c.post("/api/reset/bob")
        ev = await chat(c, "bob", "email", auto_approve=True)
        assert [e["ok"] for e in ev if e["type"] == "tool"] == [True] and len(comms.OUTBOX) == 1
    run_ui(f, tmp_path, monkeypatch)


def test_approval_request_is_streamed_to_the_browser(tmp_path, monkeypatch):
    async def f(c):
        ev = await chat(c, "bob", "email", auto_approve=True)
        req = next(e for e in ev if e["type"] == "approval_request")
        assert req["tool"] == "comms.send_email" and req["args"]["to"] == "carol@acme.com"
    run_ui(f, tmp_path, monkeypatch)


def test_live_mode_without_key_is_a_clear_400(tmp_path, monkeypatch):
    async def f(c):
        r = await c.post("/api/chat", json={"user": "bob", "mode": "live", "message": "hi"})
        assert r.status_code == 400 and "ANTHROPIC_API_KEY" in r.text
        r = await c.post("/api/chat", json={"user": "bob", "mode": "replay", "scenario": "nope"})
        assert r.status_code == 400
    run_ui(f, tmp_path, monkeypatch)


def test_reset_clears_taint_and_audit_verifies(tmp_path, monkeypatch):
    async def f(c):
        await chat(c, "alice", "salary")
        assert "restricted" in (await c.get("/api/state/alice")).json()["taints"]
        assert (await c.post("/api/reset/alice")).json()["taints"] == []
        a = (await c.get("/api/audit")).json()
        assert a["verified"] and a["records"][0]["seq"] > a["records"][-1]["seq"]
    run_ui(f, tmp_path, monkeypatch)
