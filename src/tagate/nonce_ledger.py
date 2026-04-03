from __future__ import annotations

import json
from pathlib import Path


class NonceLedger:
    """
    Durable nonce ledger.

    Each consumed nonce is appended as a JSON line.
    The in-memory set is rebuilt from disk on startup.

    Design goals:
    - fail-closed on malformed writes
    - tolerate malformed historic lines by skipping them
    - durable across process restarts
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.touch(exist_ok=True)
        self._seen: set[str] = set()
        self._load()

    def has_seen(self, nonce: str) -> bool:
        return nonce in self._seen

    def consume(self, nonce: str) -> None:
        if nonce in self._seen:
            raise ValueError(f"nonce already consumed: {nonce}")

        entry = {"nonce": nonce}
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")

        self._seen.add(nonce)

    def reset(self) -> None:
        self._path.write_text("", encoding="utf-8")
        self._seen.clear()

    def _load(self) -> None:
        with self._path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue

                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                nonce = entry.get("nonce")
                if isinstance(nonce, str) and nonce:
                    self._seen.add(nonce)
