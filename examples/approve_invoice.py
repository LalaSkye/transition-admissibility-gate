from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

from tagate.admissibility import InvoiceAdmissibilityChecker
from tagate.audit import JsonlAuditLog
from tagate.commit_gate import CommitGate
from tagate.decision_record import DecisionRecord
from tagate.nonce_ledger import NonceLedger
from tagate.state_store import JsonStateStore


def canonical_json(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def hash_payload(payload: dict) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


class Canonicalizer:
    def hash_payload(self, payload: dict) -> str:
        return hash_payload(payload)


class SignatureVerifier:
    def __init__(self, secret: bytes) -> None:
        self._secret = secret

    def verify(self, record: DecisionRecord) -> bool:
        expected = hmac.new(
            self._secret,
            record.signing_json().encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, record.signature)


class AuthorityResolver:
    def is_authorized(self, authority: str, action: str, scope: str) -> bool:
        return authority == "finance.approver" and action == "approve_invoice" and scope == "invoice"


def main() -> None:
    root = Path(".demo")
    root.mkdir(exist_ok=True)

    state_store = JsonStateStore(root / "state.json")
    state_store.seed(
        "inv-001",
        {
            "object_id": "inv-001",
            "state": "PENDING",
            "amount": 1000,
        },
    )

    payload = {
        "object_id": "inv-001",
        "requested_state": "APPROVED",
        "amount": 1000,
    }

    secret = b"demo-secret"

    record = DecisionRecord(
        action="approve_invoice",
        scope="invoice",
        authority="finance.approver",
        payload_hash=hash_payload(payload),
        nonce="nonce-001",
        issued_at="2026-04-03T09:00:00Z",
        expires_at="2026-04-03T10:00:00Z",
    )

    signature = hmac.new(
        secret,
        record.signing_json().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    signed_record = record.with_signature(signature)

    gate = CommitGate(
        canonicalizer=Canonicalizer(),
        signature_verifier=SignatureVerifier(secret),
        authority_resolver=AuthorityResolver(),
        admissibility_checker=InvoiceAdmissibilityChecker(),
        nonce_ledger=NonceLedger(root / "nonces.jsonl"),
        audit_log=JsonlAuditLog(root / "audit.jsonl"),
        state_store=state_store,
    )

    result = gate.execute(decision_record=signed_record, payload=payload)
    print(result)


if __name__ == "__main__":
    main()
