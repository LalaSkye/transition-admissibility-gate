"""
Fail-closed mutation gate.

A mutation is applied only if all checks succeed.
Any failure returns DENY and no state mutation occurs.

Execution order:
1. verify decision record presence
2. verify expiry window
3. verify signature
4. verify nonce freshness
5. verify payload hash
6. verify authority
7. verify current object existence
8. verify admissible transition
9. apply mutation
10. consume nonce
11. append audit record
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol


@dataclass(frozen=True)
class GateResult:
    """Result of a gate evaluation."""

    allowed: bool
    reason: str
    mutation_id: str | None = None


class DecisionRecordLike(Protocol):
    """Protocol for decision records. Any object with these fields works."""

    action: str
    scope: str
    authority: str
    payload_hash: str
    nonce: str
    issued_at: str
    expires_at: str
    signature: str


class Canonicalizer(Protocol):
    def hash_payload(self, payload: dict[str, Any]) -> str: ...


class SignatureVerifier(Protocol):
    def verify(self, record: DecisionRecordLike) -> bool: ...


class AuthorityResolver(Protocol):
    def is_authorized(self, authority: str, action: str, scope: str) -> bool: ...


class AdmissibilityChecker(Protocol):
    def is_admissible(
        self, current_state: str, requested_state: str, action: str
    ) -> bool: ...


class NonceLedger(Protocol):
    def has_seen(self, nonce: str) -> bool: ...
    def consume(self, nonce: str) -> None: ...


class AuditLog(Protocol):
    def append(self, event: dict[str, Any]) -> None: ...


class StateStore(Protocol):
    def get(self, object_id: str) -> dict[str, Any] | None: ...
    def apply_mutation(self, payload: dict[str, Any]) -> str: ...


class CommitGate:
    """
    Fail-closed mutation gate.

    A mutation is applied only if all checks succeed.
    Any failure returns DENY and no state mutation occurs.
    """

    def __init__(
        self,
        canonicalizer: Canonicalizer,
        signature_verifier: SignatureVerifier,
        authority_resolver: AuthorityResolver,
        admissibility_checker: AdmissibilityChecker,
        nonce_ledger: NonceLedger,
        audit_log: AuditLog,
        state_store: StateStore,
    ) -> None:
        self._canonicalizer = canonicalizer
        self._signature_verifier = signature_verifier
        self._authority_resolver = authority_resolver
        self._admissibility_checker = admissibility_checker
        self._nonce_ledger = nonce_ledger
        self._audit_log = audit_log
        self._state_store = state_store

    def execute(
        self,
        decision_record: DecisionRecordLike | None,
        payload: dict[str, Any],
    ) -> GateResult:
        """
        Attempt a governed state mutation.

        Expected payload shape:
        {
            "object_id": "inv-001",
            "requested_state": "APPROVED",
            ...
        }
        """

        # -- CHECK 1: Record presence --
        if decision_record is None:
            return self._deny("missing_decision_record", payload=payload)

        # -- CHECK 2: Expiry --
        if self._is_expired(decision_record):
            return self._deny(
                "expired_decision_record",
                payload=payload,
                decision_record=decision_record,
            )

        # -- CHECK 3: Signature --
        if not self._signature_verifier.verify(decision_record):
            return self._deny(
                "invalid_signature",
                payload=payload,
                decision_record=decision_record,
            )

        # -- CHECK 4: Nonce freshness --
        if self._nonce_ledger.has_seen(decision_record.nonce):
            return self._deny(
                "nonce_replay",
                payload=payload,
                decision_record=decision_record,
            )

        # -- CHECK 5: Payload hash --
        payload_hash = self._canonicalizer.hash_payload(payload)
        if payload_hash != decision_record.payload_hash:
            return self._deny(
                "payload_hash_mismatch",
                payload=payload,
                decision_record=decision_record,
            )

        # -- CHECK 6: Authority --
        if not self._authority_resolver.is_authorized(
            authority=decision_record.authority,
            action=decision_record.action,
            scope=decision_record.scope,
        ):
            return self._deny(
                "unauthorized_scope",
                payload=payload,
                decision_record=decision_record,
            )

        # -- CHECK 7: Object existence --
        object_id = str(payload.get("object_id", "")).strip()
        if not object_id:
            return self._deny(
                "missing_object_id",
                payload=payload,
                decision_record=decision_record,
            )

        current_object = self._state_store.get(object_id)
        if current_object is None:
            return self._deny(
                "object_not_found",
                payload=payload,
                decision_record=decision_record,
            )

        # -- CHECK 8: Admissible transition --
        current_state = str(current_object.get("state", "")).strip()
        requested_state = str(payload.get("requested_state", "")).strip()
        if not requested_state:
            return self._deny(
                "missing_requested_state",
                payload=payload,
                decision_record=decision_record,
            )

        if not self._admissibility_checker.is_admissible(
            current_state=current_state,
            requested_state=requested_state,
            action=decision_record.action,
        ):
            return self._deny(
                "inadmissible_transition",
                payload=payload,
                decision_record=decision_record,
            )

        # -- ALL CHECKS PASSED --
        # 9. Apply mutation
        mutation_id = self._state_store.apply_mutation(payload)

        # 10. Consume nonce (only after successful mutation)
        self._nonce_ledger.consume(decision_record.nonce)

        # 11. Audit
        self._audit_log.append(
            {
                "result": "ALLOW",
                "reason": "mutation_applied",
                "mutation_id": mutation_id,
                "object_id": object_id,
                "action": decision_record.action,
                "scope": decision_record.scope,
                "authority": decision_record.authority,
                "nonce": decision_record.nonce,
            }
        )

        return GateResult(
            allowed=True,
            reason="mutation_applied",
            mutation_id=mutation_id,
        )

    def _deny(
        self,
        reason: str,
        payload: dict[str, Any],
        decision_record: DecisionRecordLike | None = None,
    ) -> GateResult:
        """Log denial and return DENY result."""
        self._audit_log.append(
            {
                "result": "DENY",
                "reason": reason,
                "object_id": payload.get("object_id"),
                "requested_state": payload.get("requested_state"),
                "action": getattr(decision_record, "action", None),
                "scope": getattr(decision_record, "scope", None),
                "authority": getattr(decision_record, "authority", None),
                "nonce": getattr(decision_record, "nonce", None),
            }
        )
        return GateResult(allowed=False, reason=reason)

    def _is_expired(self, decision_record: DecisionRecordLike) -> bool:
        """Check whether the decision record has expired."""
        if not decision_record.expires_at:
            return True
        try:
            expires_at = datetime.fromisoformat(decision_record.expires_at)
            return datetime.now(timezone.utc) > expires_at
        except (ValueError, TypeError):
            return True
