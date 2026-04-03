from __future__ import annotations

from typing import Any

from tagate.commit_gate import CommitGate


class FakeCanonicalizer:
    def hash_payload(self, payload: dict[str, Any]) -> str:
        return "unused"


class FakeSignatureVerifier:
    def verify(self, record: object) -> bool:
        return True


class FakeAuthorityResolver:
    def is_authorized(self, authority: str, action: str, scope: str) -> bool:
        return True


class FakeAdmissibilityChecker:
    def is_admissible(
        self,
        current_state: str,
        requested_state: str,
        action: str,
    ) -> bool:
        return True


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
    def get(self, object_id: str) -> dict[str, Any] | None:
        return None

    def apply_mutation(self, payload: dict[str, Any]) -> str:
        raise AssertionError("mutation should not occur")


def test_deny_missing_record() -> None:
    payload = {
        "object_id": "inv-001",
        "requested_state": "APPROVED",
    }

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

    result = gate.execute(decision_record=None, payload=payload)

    assert result.allowed is False
    assert result.reason == "missing_decision_record"
    assert audit_log.events[-1]["result"] == "DENY"
    assert audit_log.events[-1]["reason"] == "missing_decision_record"
