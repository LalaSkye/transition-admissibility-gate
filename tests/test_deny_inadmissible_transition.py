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
        return True


class FakeAdmissibilityChecker:
    def is_admissible(
        self, current_state: str, requested_state: str, action: str
    ) -> bool:
        return False


class FakeNonceLedger:
    def has_seen(self, nonce: str) -> bool:
        return False

    def consume(self, nonce: str) -> None:
        pass


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

    def get(self, object_id: str) -> dict[str, Any] | None:
        return self.objects.get(object_id)

    def apply_mutation(self, payload: dict[str, Any]) -> str:
        raise AssertionError("mutation should not occur")


def _sign_record(record_without_signature: dict[str, str]) -> str:
    return hmac.new(
        b"test-secret",
        _canonical_json(record_without_signature).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def test_deny_inadmissible_transition() -> None:
    payload = {
        "object_id": "inv-001",
        "requested_state": "PAID",
    }

    record_body = {
        "action": "pay_invoice",
        "scope": "invoice",
        "authority": "finance.payments",
        "payload_hash": _hash_payload(payload),
        "nonce": "nonce-001",
        "issued_at": "2026-04-03T09:00:00Z",
        "expires_at": "2026-04-03T10:00:00Z",
    }

    record = FakeDecisionRecord(
        **record_body,
        signature=_sign_record(record_body),
    )

    audit_log = FakeAuditLog()

    gate = CommitGate(
        canonicalizer=FakeCanonicalizer(),
        signature_verifier=FakeSignatureVerifier(),
        authority_resolver=FakeAuthorityResolver(),
        admissibility_checker=FakeAdmissibilityChecker(),
        nonce_ledger=FakeNonceLedger(),
        audit_log=audit_log,
        state_store=FakeStateStore(),
    )

    result = gate.execute(decision_record=record, payload=payload)

    assert result.allowed is False
    assert result.reason == "inadmissible_transition"
    assert audit_log.events[-1]["result"] == "DENY"
