# 0002: A shared bearer token protects writes to the PDP until mTLS

- **Status:** accepted; to be superseded by mutual TLS in M5
- **Date:** 2026-10-10
- **Issue:** #14

## Context

Some PDP endpoints change what the PDP decides: `POST /v1/signals` changes trust scores, `PUT /v1/policy` replaces the policy and `PUT /v1/emergency` turns on break-glass mode. In the original design I made, none of them checked the caller.
Anyone who could reach the PDP could send an authentication signal of strength 1 for themselves, or install a policy that allows everything.

The proper answer is workload identity: mutual TLS with SPIFFE IDs, so the PDP knows which service calls it and can apply its own policy to the call. That needs a certificate authority and certificates for every service, which will come in M5. M1 needs something now.

## Decision

- Every endpoint that writes needs `Authorization: Bearer <token>`, where the token comes from `ZTC_PDP_TOKEN`.
- The token is compared in constant time (`crypto/subtle`), so it cannot be guessed one character at a time.
- Without `ZTC_PDP_TOKEN` the write endpoints answer 403: writes are disabled, never open.
- Tools read the token from the environment, never from a command-line flag, so it does not show up in `ps` or in shell history. The PDP never logs it.
- `POST /v1/decide` and the read endpoints stay open in M1.

## Consequences

- Closes the hole in the original design with very little code.
- All writers share one secret. A PEP that can send signals can also replace the policy, so there is no least privilege between services and administrators.
- Changing the token means restarting every service that uses it.
- The decide and read endpoints tell anyone who can reach them how the policy treats a request and how much a subject is trusted. That is reconnaissance for an attacker inside the network.
- All of this goes away with mTLS in M5: the caller is a SPIFFE ID, and the rule `policy-admin` (only `spiffe://*/cloud/admin/*`) decides who may change the policy.
