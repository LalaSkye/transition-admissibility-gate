from __future__ import annotations


class StaticAuthorityResolver:
    """
    Minimal authority resolver.

    Maps authority principals to allowed (action, scope) pairs.
    """

    def __init__(self) -> None:
        self._rules: dict[str, set[tuple[str, str]]] = {
            "finance.approver": {
                ("approve_invoice", "invoice"),
                ("reject_invoice", "invoice"),
            },
            "finance.payments": {
                ("pay_invoice", "invoice"),
            },
            "finance.viewer": set(),
        }

    def is_authorized(self, authority: str, action: str, scope: str) -> bool:
        allowed_pairs = self._rules.get(authority, set())
        return (action, scope) in allowed_pairs
