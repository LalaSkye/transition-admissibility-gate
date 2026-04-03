from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class JsonStateStore:
    """
    Minimal JSON-backed state store.

    Objects are keyed by object_id.
    The intended contract is that apply_mutation() is only called by CommitGate.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self._path.write_text("{}", encoding="utf-8")

    def get(self, object_id: str) -> dict[str, Any] | None:
        state = self._read()
        value = state.get(object_id)
        return value if isinstance(value, dict) else None

    def apply_mutation(self, payload: dict[str, Any]) -> str:
        state = self._read()
        object_id = str(payload["object_id"])

        existing = state.get(object_id, {})
        if not isinstance(existing, dict):
            existing = {}

        updated = existing.copy()
        updated["object_id"] = object_id
        updated["state"] = payload["requested_state"]

        for key, value in payload.items():
            if key not in {"requested_state"}:
                updated[key] = value

        state[object_id] = updated
        self._write(state)
        return f"mut-{object_id}-{updated['state']}"

    def seed(self, object_id: str, value: dict[str, Any]) -> None:
        state = self._read()
        state[object_id] = value
        self._write(state)

    def _read(self) -> dict[str, Any]:
        raw = self._path.read_text(encoding="utf-8").strip()
        if not raw:
            return {}
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}

    def _write(self, value: dict[str, Any]) -> None:
        self._path.write_text(
            json.dumps(value, sort_keys=True, indent=2),
            encoding="utf-8",
        )
