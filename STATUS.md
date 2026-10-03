# Status

What is implemented right now. Updated in every branch that moves something forward.

Legend: ✅ implemented and tested · 🟡 works, known gaps · 🔴 not started

## Milestones

| Milestone | Content | Status |
| --- | --- | --- |
| M0 Foundation | repo hygiene, Go service skeleton, CI | 🟡 in progress |
| M1 Decision chain | policy, trust, PDP, tokens, PEP | 🔴 |
| M2 Fog, IDS and demo | telemetry, edge devices, fog node, IDS, audit, e2e demo | 🔴 |
| M3 Distributed systems | clocks, Raft, SWIM, Chord | 🔴 |
| M4 Offloading and containers | load balancing, Docker, Compose, monitoring, Kubernetes | 🔴 |
| M5 Industrial security | threat model, zones, Modbus/GOOSE, IDS service, mTLS | 🔴 |
| M6 Simulation and evaluation | C++ core, OMNeT++, migration, analytics | 🔴 |
| M7 Infrastructure and career | Terraform, Ansible, Cisco, thesis skeleton | 🔴 |

## Components

| Part | Path | Status | Notes |
| --- | --- | --- | --- |
| Go services | `services/` | 🔴 | |
| C++ simulation core | `sim/core/` | 🔴 | |
| OMNeT++ model | `sim/omnetpp/` | 🔴 | |
| Analytics | `analytics/` | 🔴 | |
| Deployment | `deploy/` | 🔴 | |
| CI/CD | `.github/workflows/` | 🔴 | |
| Docs | `Docs/` | 🔴 | |

## Repository basics

| Item | Status |
| --- | --- |
| `.gitignore` (Go, Python, C++, OMNeT++, Terraform, OS, editors) | ✅ |
| `LICENSE` (MIT), `.editorconfig` | ✅ |
| `STATUS.md`, `CLAUDE.md` | ✅ |
