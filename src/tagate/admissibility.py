from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TransitionRule:
    from_state: str
    to_state: str
    action: str


class InvoiceAdmissibilityChecker:
    """
    Minimal admissibility checker for invoice state transitions.
    """

    _RULES: set[TransitionRule] = {
        TransitionRule("PENDING", "APPROVED", "approve_invoice"),
        TransitionRule("PENDING", "REJECTED", "reject_invoice"),
        TransitionRule("APPROVED", "PAID", "pay_invoice"),
    }

    def is_admissible(
        self,
        current_state: str,
        requested_state: str,
        action: str,
    ) -> bool:
        current_state = current_state.strip().upper()
        requested_state = requested_state.strip().upper()
        action = action.strip()

        rule = TransitionRule(
            from_state=current_state,
            to_state=requested_state,
            action=action,
        )
        return rule in self._RULES
