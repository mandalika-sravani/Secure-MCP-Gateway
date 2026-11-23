from __future__ import annotations

from pathlib import Path

import yaml

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "policy.yaml"


class Policy:
    def __init__(self, raw: dict):
        self.raw = raw
        self.roles: dict[str, set[str]] = {r: set(t) for r, t in raw["roles"].items()}
        self.tools: dict[str, dict] = raw["tools"]
        self.max_calls = raw["rate_limit"]["max_calls"]
        self.window = raw["rate_limit"]["window_seconds"]
        self.max_output = raw["max_output_chars"]
        self.max_arg_len = raw["max_string_arg_chars"]
        self.blocked_taints = set(raw["egress_blocked_taints"])
        for role, tools in self.roles.items():  # fail loudly on typos
            for t in tools:
                if t not in self.tools:
                    raise ValueError(f"role {role} references unlisted tool {t}")

    @classmethod
    def load(cls, path: str | Path = DEFAULT_PATH) -> "Policy":
        return cls(yaml.safe_load(Path(path).read_text()))

    def allowed(self, role: str, tool: str) -> bool:
        return tool in self.tools and tool in self.roles.get(role, set())

    def spec(self, tool: str) -> dict:
        return self.tools[tool]
