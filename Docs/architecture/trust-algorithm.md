# Trust algorithm

The trust algorithm of NIST SP 800-207: a score in [0, 1] for every subject, updated continuously from signals.
The PDP writes the score into `context.trustScore` before the policy is evaluated, so a rule such as `context.trustScore gte 0.8` decides how much the system must trust a subject before it may act.

```
PEP ── authentication, location ──┐
IDS ── behaviour ─────────────────┼──► trust.Store ──Score(subject)──► PDP ──context.trustScore──► policy
PDP ── denial, compromise ────────┘
```

Implementations, which must give the same numbers for the same test vectors:

| Where | What |
| --- | --- |
| `services/internal/trust/score.go` | Go: `Evaluator.Apply` and `Evaluator.Score` |
| `services/internal/trust/score_test.go` | the test vectors, computed by hand |
| `sim/core/src/trust_model.cc` | C++ for the simulation (M6, not written yet) |

Change all of them and this document together.

## Formula

```
auth  = authStrength · 0.5^((now − lastAuth) / authHalfLife)
score = 0.35·auth + 0.25·posture + 0.30·(1 − anomaly) + 0.10·location
        − denialPenalty · denials · 0.5^((now − lastDenial) / denialHalfLife)

compromised            => 0
never authenticated    => 0
otherwise clamp to [0, 1]; NaN => 0
```

Behaviour and location are smoothed with an exponentially weighted moving average:
`new = α·signal + (1 − α)·old`.

## Signals

| Kind | Value | Sent by | Effect |
| --- | --- | --- | --- |
| `authentication` | 0.5 bearer token, 0.6 capability, 0.8 mTLS, 1.0 mTLS with attestation | PEP, on every new credential (#16) | sets `authStrength` and restarts the decay; strength 0 or an older time is ignored |
| `posture` | 1 patched and attested, 0 unknown or failed | attestation (M5) | sets `posture` |
| `behaviour` | IDS anomaly score, 0 normal, 1 malicious | IDS (M2) | smoothed into `anomaly` |
| `location` | 1 expected zone, 0 unexpected | PEP (#16) | smoothed into `location` |
| `denial` | ignored | PDP, on every deny (#14) | adds 1 to a count that decays from the last denial |
| `compromise` | ignored | SOC or PDP escalation (#14) | score 0 for good |

Values outside [0, 1] are clamped. A signal without a time is stamped by the store's clock. A signal without a subject or with an unknown kind is rejected.

## Parameters

| Parameter | Default | Meaning |
| --- | --- | --- |
| weights | 0.35 / 0.25 / 0.30 / 0.10 | authentication / posture / behaviour / location; sum to 1 |
| `AuthHalfLife` | 5 min | after one half-life an authentication counts half |
| `DenialPenalty` | 0.1 | subtracted per recent denial |
| `DenialHalfLife` | 10 min | how fast denials are forgiven |
| `Alpha` | 0.5 | weight of the newest behaviour or location signal |

Authentication and behaviour weigh most because they are the only signals that change within seconds. Posture changes slowly, and location is weak evidence in a substation where devices never move.

These numbers are a reasonable starting point, not a result. RQ4 varies them and measures the effect.

## Levels

| Level | Score | In the default policy |
| --- | --- | --- |
| high | ≥ 0.8 | may operate a breaker |
| medium | ≥ 0.5 | may read telemetry, run and migrate tasks (migration needs 0.7) |
| low | ≥ 0.3 | above the zero trust floor |
| untrusted | < 0.3 or NaN | denied everything (`deny-untrusted`) |

## How long an authentication keeps a subject at high

For a subject with posture 1, location 1 and no anomaly, the score is `0.35·auth + 0.65`. It stays at high while `0.35·auth ≥ 0.15`:

| Credential | Score right after | High for |
| --- | --- | --- |
| bearer token (0.5) | 0.825 | 67 s |
| capability (0.6) | 0.86 | 146 s |
| mTLS (0.8) | 0.93 | 270 s |
| mTLS with attestation (1.0) | 1.0 | 367 s |

An operator who wants to operate a breaker must therefore have authenticated recently, and the stronger the credential, the longer the window. This is step-up authentication, and it follows from the formula and the policy together; neither has a special rule for it.
