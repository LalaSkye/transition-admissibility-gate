# transition-admissibility-gate

A minimal reference implementation for a fail-closed mutation boundary.

This repository demonstrates a simple rule:

A state mutation may occur only when:

- a valid decision record exists
- the authorised object matches the presented payload
- authority is present for the requested action and scope
- the requested transition is admissible in the current state
- the nonce has not been used before
- all checks succeed at the mutation boundary

If any check fails, the mutation is denied.

---

## Why this exists

Many systems describe governance upstream and verify outcomes downstream.

This repository focuses on the point that matters:

**the mutation boundary**

The question is not whether a failure can be described after the fact.
The question is whether an invalid transition can occur at all.

If an invalid transition is reachable, the system is not governed.

---

## Design goals

- fail-closed by default
- one governed write path
- explicit decision record
- canonical payload binding
- replay protection
- inspectable deny reasons
- minimal domain model

---

## Example domain

The reference domain is a small invoice workflow.

### States

- `PENDING`
- `APPROVED`
- `REJECTED`
- `PAID`

### Allowed transitions

- `PENDING -> APPROVED`
- `PENDING -> REJECTED`
- `APPROVED -> PAID`

### Denied transitions

- `REJECTED -> PAID`
- `PAID -> PENDING`
- `APPROVED -> APPROVED`

---

## Core components

### `DecisionRecord`
The authorised decision object.

Contains:

- action
- scope
- authority
- payload hash
- nonce
- issue time
- expiry time
- signature

### `CommitGate`
The sole mutation entry point.

Responsible for:

- verifying the decision record
- verifying payload binding
- checking authority
- checking transition admissibility
- enforcing replay denial
- applying the mutation only if all checks pass

### `StateStore`
The governed state store.

No direct public mutation path exists outside the gate.

### `NonceLedger`
Tracks consumed nonces to prevent replay.

### `AuditLog`
Append-only record of allow / deny outcomes.

The audit log is evidence, not control.

---

## Execution order

A mutation attempt is processed in this order:

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

Any failed check terminates the request.

---

## Usage

```python
result = gate.execute(
    decision_record=record,
    payload=payload,
)

if result.allowed:
    print("Mutation applied")
else:
    print(f"Denied: {result.reason}")
```

## Files

```
src/tagate/
    commit_gate.py        fail-closed mutation gate (protocol-based)
    decision_record.py    canonical decision object + signing
    canonical.py          stable serialisation
    authority.py          authority resolution
    admissibility.py      transition admissibility checks
    nonce_ledger.py       replay prevention
    state_store.py        governed write path
    audit.py              append-only log
    errors.py             error definitions
```

## Tests

```bash
python -m pytest tests/ -v
```

The test suite proves both sides of the claim.

**Allowed:** valid record, valid signature, matching payload, authorised scope, admissible transition, fresh nonce.

**Denied:** missing decision record, bad signature, expired record, payload tamper, nonce replay, authority mismatch, inadmissible transition, direct mutation bypass.

## Non-goals

This repository is not intended to be:

- a full policy engine
- a distributed authorisation framework
- a production-ready workflow platform

It is a minimal proof surface for one claim:

**no valid decision record → no state mutation**

## Licence

MIT
