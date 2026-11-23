"""Append-only, hash-chained audit log. Editing or deleting any line breaks verification."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path


class Audit:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._seq = 0
        self._prev = "0" * 64
        if self.path.exists():
            for line in self.path.read_text().splitlines():
                if line.strip():
                    rec = json.loads(line)
                    self._seq, self._prev = rec["seq"], rec["hash"]

    def log(self, **fields) -> dict:
        self._seq += 1
        rec = {"seq": self._seq, "ts": round(time.time(), 3), **fields, "prev": self._prev}
        rec["hash"] = self._digest(rec)
        self._prev = rec["hash"]
        with self.path.open("a") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
        return rec

    @staticmethod
    def _digest(rec: dict) -> str:
        body = {k: v for k, v in rec.items() if k != "hash"}
        return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()

    def records(self) -> list[dict]:
        return [json.loads(x) for x in self.path.read_text().splitlines() if x.strip()]

    def verify(self) -> bool:
        prev = "0" * 64
        for i, rec in enumerate(self.records(), start=1):
            if rec["seq"] != i or rec["prev"] != prev or rec["hash"] != self._digest(rec):
                return False
            prev = rec["hash"]
        return True
