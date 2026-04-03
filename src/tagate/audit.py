from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class JsonlAuditLog:
    """
    Append-only audit log.

    Evidence only.
    Not a permission source.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.touch(exist_ok=True)

    def append(self, event: dict[str, Any]) -> None:
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
