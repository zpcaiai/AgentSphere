# Package Batch 28—36

This archive contains 9 skills from the 36-Batch v2 roadmap. `FULL_ROADMAP_MANIFEST.json` describes all batches.

# Agent Trust & Compliance Control Plane — 36 Batch Skills v2.0

This package contains implementation specifications for Codex. It does **not** claim that the product code has been implemented. A batch is implemented only when its target repository contains real code and an `IMPLEMENTATION_STATUS.json` validated as `EVIDENCE_VERIFIED`.

## Architecture rule

- Rust: trusted runtime, gateway, PEP, sandbox, proxy, supervisor, evidence integrity.
- Python: durable orchestration client/workers, agents, semantic evaluators, anomaly models and algorithms.
- Java: enterprise control APIs, tenancy, approvals, policy administration, compliance and integrations.
- Vue/TypeScript: unified management console.

## Batch catalog

| Batch | Skill | Title |
|---:|---|---|
| 01 | `agent-trust-contracts` | 公共契约、Signed Goal、Plan与Authorization Lease |
| 02 | `agent-trust-gateway` | Rust Agent Gateway与Admission Control |
| 03 | `agent-trust-action-ir` | Typed Unified Agent Action IR |
| 04 | `agent-trust-identity-credentials` | Agent Identity与Workload Credential |
| 05 | `agent-trust-tool-registry` | Tool与Capability Registry |
| 06 | `agent-trust-policy-pep` | Policy Enforcement与Minimal Approval Kernel |
| 07 | `agent-trust-sandbox-runtime` | Sandbox Runtime、Runtime Supervisor与Kill Switch |
| 08 | `agent-trust-tool-credential-proxy` | Target Credential Broker与Tool Proxy |
| 09 | `agent-trust-transaction-ledger` | 幂等、补偿事务与Unknown Outcome Recovery |
| 10 | `agent-trust-trace-evaluator` | Trace、Evidence与Evaluator Governance |
| 11 | `agent-trust-protocol-adapter-sdk` | Protocol Adapter SDK与一致性测试 |
| 12 | `agent-trust-mcp-security-proxy` | MCP Adapter与Security Proxy |
| 13 | `agent-trust-a2a-agui-adapter` | A2A与AG-UI Adapter |
| 14 | `agent-trust-cn-standard-adapter` | 中国智能体标准Adapter |
| 15 | `agent-trust-model-gateway` | Unified Model Gateway与模型合规路由 |
| 16 | `agent-trust-industrial-protocol-gateway` | 工业协议Adapter与Edge Gateway |
| 17 | `agent-trust-human-approval` | Enterprise Human Approval与职责分离 |
| 18 | `agent-trust-data-governance` | 数据分级、跨域与部署治理 |
| 19 | `agent-trust-audit-retention` | 审计留存、Control Catalog与Evidence Graph |
| 20 | `agent-trust-pack-supply-chain` | 平台供应链与Domain Pack SDK Foundation |
| 21 | `agent-trust-runtime-anomaly-detection` | 异常轨迹检测与Continuous Authorization |
| 22 | `agent-trust-incident-release-gate` | Incident、Replay与Release Gate Engine |
| 23 | `agent-trust-coding-risk-pack` | Coding Agent Risk Pack |
| 24 | `agent-trust-industrial-risk-pack` | Industrial Agent Risk Pack |
| 25 | `agent-trust-energy-risk-pack` | Energy Agent Risk Pack |
| 26 | `agent-trust-medical-risk-pack` | Medical Agent Risk Pack |
| 27 | `agent-trust-sensitive-interaction-pack` | Sensitive Interaction Risk Pack |
| 28 | `agent-trust-domain-pack-sdk-marketplace` | Domain Pack Marketplace与Lifecycle Governance |
| 29 | `agent-trust-durable-orchestrator` | Durable Runtime Orchestrator与Continuous Task State |
| 30 | `agent-trust-agent-registry-posture` | Agent Registry、Discovery与Posture Management |
| 31 | `agent-trust-policy-administration` | Policy Administration、Simulation与Change Governance |
| 32 | `agent-trust-memory-prompt-provenance` | Memory、Prompt与Knowledge Provenance |
| 33 | `agent-trust-security-evaluation-lab` | Agent Security Evaluation与Red-Team Lab |
| 34 | `agent-trust-platform-sre` | Platform SRE、HA、DR与Deployment |
| 35 | `agent-trust-enterprise-control-console` | Enterprise Control API与Unified Management Console |
| 36 | `agent-trust-production-closure` | Full-System Production Closure与最终认证 |

## Critical v2 fixes

See `MIGRATION_FROM_V1.md`. The most important changes are: a single durable orchestrator, continuous authorization, Agent inventory, policy lifecycle, context provenance, red-team lab, SRE/DR, unified console and a true final production closure.

## Validation

```bash
python scripts/validate_skills.py
python scripts/validate_dependency_dag.py
python scripts/validate_traceability.py
python scripts/check_duplicate_templates.py
```

## Install

Copy `.agents/skills/*` into the target repository's `.agents/skills/`. Then invoke one skill at a time and require real implementation evidence.
