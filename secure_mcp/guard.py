"""Output guard for tool results (untrusted data).

Heuristic scanning is only ONE layer and can be bypassed by a clever attacker. The load-bearing
controls are structural: identity propagation, default-deny, taint-based egress blocking and
human approval. This layer adds detection, audit signals and cheap neutralisation.
"""
from __future__ import annotations

import re
from typing import Any

PATTERNS = [
    re.compile(r"ignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)", re.I),
    re.compile(r"disregard\s+.{0,40}(instructions?|rules?|polic(y|ies))", re.I),
    re.compile(r"(new|updated)\s+instructions?\s*:", re.I),
    re.compile(r"you\s+are\s+now\s+", re.I),
    re.compile(r"(reveal|print|show)\s+.{0,30}system\s+prompt", re.I),
    re.compile(r"</?\s*(system|assistant|tool_use|function_calls?)\s*>", re.I),
    re.compile(r"(send|email|mail|forward|exfiltrate|post)\b.{0,80}[\w.+-]+@[\w-]+\.[\w.-]+", re.I),
]
REDACTION = "[REDACTED: suspected prompt injection]"
_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+")


def scan(text: str) -> list[str]:
    return [p.pattern[:40] for p in PATTERNS if p.search(text)]


def sanitize(obj: Any) -> tuple[Any, list[str]]:
    """Walk JSON-like data; replace any sentence matching an injection pattern."""
    hits: list[str] = []

    def walk(x):
        if isinstance(x, str):
            parts = _SPLIT.split(x)
            out = []
            for part in parts:
                h = scan(part)
                if h:
                    hits.extend(h)
                    out.append(REDACTION)
                else:
                    out.append(part)
            return " ".join(out)
        if isinstance(x, list):
            return [walk(i) for i in x]
        if isinstance(x, dict):
            return {k: walk(v) for k, v in x.items()}
        return x

    return walk(obj), hits
