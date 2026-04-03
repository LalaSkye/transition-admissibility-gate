from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .canonical import canonical_json, hash_dict


@dataclass(frozen=True)
class DecisionRecord:
    """
    Canonical decision object authorised at the mutation boundary.
    """

    action: str
    scope: str
    authority: str
    payload_hash: str
    nonce: str
    issued_at: str
    expires_at: str
    signature: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def signing_dict(self) -> dict[str, Any]:
        """
        Canonical fields used for signature generation / verification.
        Signature is excluded from the signed body.
        """
        body = self.to_dict().copy()
        body.pop("signature", None)
        return body

    def signing_json(self) -> str:
        return canonical_json(self.signing_dict())

    def signing_hash(self) -> str:
        return hash_dict(self.signing_dict())

    def with_signature(self, signature: str) -> "DecisionRecord":
        return DecisionRecord(
            action=self.action,
            scope=self.scope,
            authority=self.authority,
            payload_hash=self.payload_hash,
            nonce=self.nonce,
            issued_at=self.issued_at,
            expires_at=self.expires_at,
            signature=signature,
        )
