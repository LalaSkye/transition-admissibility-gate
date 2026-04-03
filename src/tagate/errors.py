from __future__ import annotations


class CommitGateError(Exception):
    """Base error for mutation-boundary failures."""


class NonceReuseError(CommitGateError):
    """Raised when a nonce is consumed more than once."""
