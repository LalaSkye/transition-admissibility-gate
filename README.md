# transition-admissibility-gate

A minimal reference implementation for a fail-closed mutation boundary.

This repository demonstrates a simple path-local rule:

A state mutation on the demonstrated governed path may occur only when:

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
The question is whether an invalid transition can occur on the demonstrated governed path.

If an invalid transition is reachable on that path, the local gate has failed.

---

## Authority is necessary, not sufficient

A valid authority record is required before a consequence-producing transition can proceed.

It is not sufficient on its own.

The proposed transition must still be admissible under the live state that exists at the point of mutation.

This matters because state can move after authority is issued.

A record may be:

- validly issued
- scoped to the actor
- unexpired
- unreplayed

and still fail if the proposed transition is no longer permitted under current state.

In this repository:

- authority answers: who or what may request this transition?
- scope answers: what class of transition is allowed?
- admissibility answers: is this specific transition still permitted now?
- the mutation boundary answers: may this state change proceed?

If the live-state admissibility check fails, the transition is refused before mutation and the result records the denial reason.

Claim boundary:

This does not claim production deployment, compliance, certification, or third-party validation.

It defines the proof condition for one demonstrated boundary:

no consequence-producing transition should proceed merely because authority once existed.

Authority must still meet live admissibility at the point of mutation.

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

## Current hardening gap

The current execution order applies mutation before nonce consumption and audit append.

That means this repository does not currently claim atomic proof / replay / audit ordering where nonce consumption and audit durability are completed before consequence binds.

This ordering gap is tracked in issue #1.

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
The sole demonstrated mutation entry point.

Responsible for:

- verifying the decision record
- verifying payload binding
- checking authority
- checking transition admissibility
- enforcing replay denial on the demonstrated path
- applying the mutation only if all checks pass

### `StateStore`
The governed state store for the demo path.

This repository does not prove path-universal exclusion of every possible mutation route in a deployed system.

### `NonceLedger`
Tracks consumed nonces to prevent replay on the demonstrated path.

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

Any failed check before mutation terminates the request.

The mutation-before-nonce and mutation-before-audit ordering is a known v1 hardening gap, tracked in issue #1.

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

The test suite checks both sides of the local claim.

**Allowed:** valid record, valid signature, matching payload, authorised scope, admissible transition, fresh nonce.

**Denied:** missing decision record, bad signature, expired record, payload tamper, nonce replay, authority mismatch, inadmissible transition, direct mutation bypass.

## Non-goals

This repository is not intended to be:

- a full policy engine
- a distributed authorisation framework
- a production-ready workflow platform
- a proof of path-universal deployment coverage
- a proof of atomic proof / nonce / mutation / audit ordering

It is a minimal proof surface for one local claim:

**no valid decision record → no state mutation on the demonstrated governed path**

## What this does not prove

This repository does not prove adoption, certification, standardisation, production readiness, or path-universal deployment coverage.

It demonstrates a bounded execution-control surface that can be run, inspected, and tested at its stated scope.

## Licence

MIT
