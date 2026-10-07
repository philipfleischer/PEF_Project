# 0001: Fail closed when no decision is available

- **Status:** accepted
- **Date:** 2026-10-07
- **Issue:** #12

## Context

In zero-trust (NIST SP 800-207), every request is allowed only by an explicit decision from the Policy Decision Point (PDP). Sometimes no trustworthy decision exists, in that case the policy is invalid, an attribute is missing, the PDP is unreachable, or a cached decision has expired.

The system must then either allow the request (fail open, which favours availability) or deny it (fail closed, which favours security). In IT this is mostly a security question. In a digital substation, OT environment, it is not that simple because:

- Denying telemetry during a WAN outage can leave operators without a view of the grid.
- Allowing requests when the PDP cannot be reached means that an attacker who can cut or jam the WAN switches off access control, which is exactly the moment an attacker would choose.

## Decision

Every component fails closed, meaning that when the outcome is unknown, the answer is always deny access.

Implemented in the policy engine (`services/internal/policy`):

| Situation | Behaviour |
| --- | --- |
| No rule matches | deny (default deny) |
| Any matching deny rule | deny, regardless of allow rules (deny-overrides) |
| Attribute missing from the request, or unset time | the condition is false |
| Numeric operator on a value that is not a number | the condition is false |
| Policy with unknown fields, attributes or operators, or a number such as `"0,3"` | rejected when loaded. The installed policy is kept |
| Policy that is not newer than the installed one | rejected (`ErrStalePolicy`), which blocks rollback to an older and weaker policy |
| Zero value of `model.Decision` | not allowed (`Allowed()` is true only for an explicit allow) |

Planned in the same milestone:

- The PEP answers with HTTP code 503 and denies when the PDP fails or times out (#16).
- The decision cache drops the cached allows for a subject, when the subject is denied or revoked access (#14).

Availability is not bought by weakening the failure mode. It comes from the architecture, where a PDP or a decision cache close to the edge keeps deciding when the WAN to the cloud is down (RQ1, PDP placement).
Safety-critical protection (relays tripping on a fault) never waits for the PEP: it runs locally on the process bus, and ZTC only observes it.

## Consequences

- A configuration mistake makes the system stricter, never more open. A broken policy blocks traffic, and the error message names the rule and the field.
- An outage between the edge and the PDP denies legitimate requests. How many depends on where the PDP runs, and measuring that is RQ1's responsibility. The cloud placement is expected to deny during a partition, on the other hand fog and hierarchical placement should not.
- Break-glass (`context.emergency`) is the controlled exception for operators. It is still evaluated by the PDP, keeps the 0.3 trust floor, is cached for one second only and always raises an alert.
