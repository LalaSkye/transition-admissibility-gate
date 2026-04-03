from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any

from tagate.commit_gate import CommitGate


def _canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _hash_payload(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class FakeDecisionRecord:
    action: str
    scope: str
    authority: str
    payload_hash: str
    nonce: str
    issued_at: str
    expires_at: str
    signature: str


class FakeCanonicalizer:
    def hash_payload(self, payload: dict[str, Any]) -> str:
        return _hash_payload(payload)


class FakeSignatureVerifier:
    _key = b"test-secret"

    def verify(self, record: FakeDecisionRecord) -> bool:
        body = {
            "action": record.action,
            "scope": record.scope,
            "authority": record.authority,
            "payload_hash": record.payload_hash,
            "nonce": record.nonce,
            "issued_at": record.issued_at,
            "expires_at": record.expires_at,
        }
        expected = hmac.new(
            self._key,
            _canonical_json(body).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, record.signature)


class FakeAuthorityResolver:
    def is_authorized(self, authority: str, action: str, scope: str) -> bool:
        return authority == "finance.approver" and action == "approve_invoice" and scope == "invoice"


class FakeAdmissibilityChecker:
    def is_admissible(
        self, current_state: str, requested_state: str, action: str
    ) -> bool:
        return (
            current_state == "PENDING"
            and requested_state == "APPROVED"
            and action == "approve_invoice"
        )


class FakeNonceLedger:
    def __init__(self) -> None:
        self._seen: set[str] = set()

    def has_seen(self, nonce: str) -> bool:
        return nonce in self._seen

    def consume(self, nonce: str) -> None:
        if nonce in self._seen:
            raise ValueError(f"nonce already consumed: {nonce}")
        self._seen.add(nonce)


class FakeAuditLog:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def append(self, event: dict[str, Any]) -> None:
        self.events.append(event)


class FakeStateStore:
    def __init__(self) -> None:
        self.objects = {
            "inv-001": {"object_id": "inv-001", "state": "PENDING"}
        }
        self.mutations: list[dict[str, Any]] = []

    def get(self, object_id: str) -> dict[str, Any] | None:
        return self.objects.get(object_id)

    def apply_mutation(self, payload: dict[str, Any]) -> str:
        self.mutations.append(payload.copy())
        self.objects[payload["object_id"]]["state"] = payload["requested_state"]
        return "mut-001"


def _sign_record(record_without_signature: dict[str, str]) -> str:
    return hmac.new(
        b"test-secret",
        _canonical_json(record_without_signature).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _make_record(payload: dict[str, Any], nonce: str) -> FakeDecisionRecord:
    record_body = {
        "action": "approve_invoice",
        "scope": "invoice",
        "authority": "finance.approver",
        "payload_hash": _hash_payload(payload),
        "nonce": nonce,
        "issued_at": "2026-04-03T09:00:00Z",
        "expires_at": "2026-04-03T10:00:00Z",
    }
    return FakeDecisionRecord(
        **record_body,
        signature=_sign_record(record_body),
    )


def test_deny_nonce_reuse() -> None:
    payload = {
        "object_id": "inv-001",
        "requested_state": "APPROVED",
        "amount": 1000,
    }

    audit_log = FakeAuditLog()
    state_store = FakeStateStore()
    nonce_ledger = FakeNonceLedger()

    gate = CommitGate(
        canonicalizer=FakeCanonicalizer(),
        signature_verifier=FakeSignatureVerifier(),
        authority_resolver=FakeAuthorityResolver(),
        admissibility_checker=FakeAdmissibilityChecker(),
        nonce_ledger=nonce_ledger,
        audit_log=audit_log,
        state_store=state_store,
    )

    record = _make_record(payload=payload, nonce="nonce-001")

    first = gate.execute(decision_record=record, payload=payload)
    assert first.allowed is True
    assert first.reason == "mutation_applied"
    assert state_store.objects["inv-001"]["state"] == "APPROVED"

    state_store.objects["inv-001"]["state"] = "PENDING"

    second = gate.execute(decision_record=record, payload=payload)
    assert second.allowed is False
    assert second.reason == "nonce_replay"

    assert len(state_store.mutations) == 1
    assert audit_log.events[-1]["result"] == "DENY"
    assert audit_log.events[-1]["reason"] == "nonce_replay"
