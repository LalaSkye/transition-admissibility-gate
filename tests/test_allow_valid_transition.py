from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from tagate.admissibility import InvoiceAdmissibilityChecker
from tagate.commit_gate import CommitGate
from tagate.decision_record import DecisionRecord


def _canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _hash_payload(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


class FakeCanonicalizer:
    def hash_payload(self, payload: dict[str, Any]) -> str:
        return _hash_payload(payload)


class FakeSignatureVerifier:
    _key = b"test-secret"

    def verify(self, record: DecisionRecord) -> bool:
        expected = hmac.new(
            self._key,
            record.signing_json().encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, record.signature)


class FakeAuthorityResolver:
    def is_authorized(self, authority: str, action: str, scope: str) -> bool:
        return authority == "finance.approver" and action == "approve_invoice" and scope == "invoice"


class FakeNonceLedger:
    def __init__(self) -> None:
        self._seen: set[str] = set()

    def has_seen(self, nonce: str) -> bool:
        return nonce in self._seen

    def consume(self, nonce: str) -> None:
        self._seen.add(nonce)


class FakeAuditLog:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def append(self, event: dict[str, Any]) -> None:
        self.events.append(event)


class FakeStateStore:
    def __init__(self) -> None:
        self.objects = {
            "inv-001": {"object_id": "inv-001", "state": "PENDING", "amount": 1000}
        }

    def get(self, object_id: str) -> dict[str, Any] | None:
        return self.objects.get(object_id)

    def apply_mutation(self, payload: dict[str, Any]) -> str:
        self.objects[payload["object_id"]]["state"] = payload["requested_state"]
        return "mut-001"


def test_allow_valid_transition() -> None:
    payload = {
        "object_id": "inv-001",
        "requested_state": "APPROVED",
        "amount": 1000,
    }

    record = DecisionRecord(
        action="approve_invoice",
        scope="invoice",
        authority="finance.approver",
        payload_hash=_hash_payload(payload),
        nonce="nonce-001",
        issued_at="2026-04-03T09:00:00Z",
        expires_at="2026-04-03T10:00:00Z",
    )

    signature = hmac.new(
        b"test-secret",
        record.signing_json().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    record = record.with_signature(signature)

    audit_log = FakeAuditLog()
    state_store = FakeStateStore()

    gate = CommitGate(
        canonicalizer=FakeCanonicalizer(),
        signature_verifier=FakeSignatureVerifier(),
        authority_resolver=FakeAuthorityResolver(),
        admissibility_checker=InvoiceAdmissibilityChecker(),
        nonce_ledger=FakeNonceLedger(),
        audit_log=audit_log,
        state_store=state_store,
    )

    result = gate.execute(decision_record=record, payload=payload)

    assert result.allowed is True
    assert result.reason == "mutation_applied"
    assert state_store.objects["inv-001"]["state"] == "APPROVED"
    assert audit_log.events[-1]["result"] == "ALLOW"
