---
id: documentation-index
title: Documentation Index
slug: /documentation-index
---

This page is the complete map to all documentation. Use it when you know what you want but not where to find it.

## User-Facing Documentation (`/docs`)

These documents are written for security analysts, platform operators, and new team members.

| Document | What you will find |
| --- | --- |
| [Introduction](./intro.md) | Platform overview, key concepts glossary, role-based navigation |
| [Getting Started](./getting-started.md) | Step-by-step setup from scratch to running platform with auth and AI |
| [Running the Project](./running-the-project.md) | Tested clone-and-run workflow for the full stack with the current Docker path |
| [Master Guide](./master-guide.md) | Single-page narrative of the whole platform with architecture diagrams |
| [Kali Demo Walkthrough](./kali-demo-walkthrough.md) | Operator-ready demo from Docker host plus Kali VM with exact attack commands |
| [Operations and Deployment](./operations-and-deployment.md) | Bootstrap checklist, TLS setup, database backup, day-2 runbooks |
| [Troubleshooting](./troubleshooting.md) | Symptom → cause → fix for auth, backend, AI, frontend, SDN issues |
| [Incident Response Runbook](./incident-response-runbook.md) | SOC playbooks by threat level including AI-assisted triage commands |
| [Documentation Index](./documentation-index.md) | This page |

## Developer Documentation (`/dev`)

These documents are for engineers building, extending, or operating the platform.

| Document | What you will find |
| --- | --- |
| [System Overview](/dev/system-overview) | Platform capabilities, component responsibilities, and design philosophy |
| [Architecture Overview](/dev/architecture-overview) | Service topology, data flow, trust boundaries, sequence diagrams |
| [Backend Design](/dev/backend-design) | FastAPI structure, routers, services, data models, auth, LLM integration |
| [Frontend Design](/dev/frontend-design) | React dashboard, components, state management, WebSocket, auth store |
| [AI Threat Scoring](/dev/ai-threat-scoring) | ML model, feature engineering, LLM analysis, AI endpoints |
| [SDN Controller](/dev/sdn-controller) | Ryu controller, OpenFlow flow management, score-to-redirect logic |
| [API Reference](/dev/api-reference) | Every endpoint documented — auth, sessions, AI, dashboard, canary, SDN |
| [Environment Configuration](/dev/environment-configuration) | Every environment variable with type, default, and when to change it |
| [Developer Onboarding](/dev/developer-onboarding) | First-time dev setup, local workflow, and daily development commands |
| [Testing and Quality](/dev/testing-and-quality) | Unit/integration test strategy, CI pipeline, coverage targets |
| [Security Hardening Checklist](/dev/security-hardening-checklist) | Completed and outstanding hardening tasks for production readiness |
| [Honeypot Integration](/dev/honeypot-integration) | Cowrie and Dionaea integration contracts, payload schemas, reliability |
| [Observability and SLOs](/dev/observability-and-slos) | Metrics, log formats, SLO targets, alerting and Splunk forwarding |

## Key Cross-References

| "I want to understand..." | Go to |
| --- | --- |
| The big picture in one page | [Master Guide](./master-guide.md) |
| What each service does | [System Overview](/dev/system-overview) |
| How data flows from honeypot to dashboard | [Architecture Overview](/dev/architecture-overview) + [Master Guide data flow diagram](./master-guide.md) |
| Every API endpoint | [API Reference](/dev/api-reference) |
| Every environment variable | [Environment Configuration](/dev/environment-configuration) |
| How the ML threat score works | [AI Threat Scoring](/dev/ai-threat-scoring) |
| How to set up the platform for the first time | [Getting Started](./getting-started.md) |
| How to run the full tested stack after cloning | [Running the Project](./running-the-project.md) |
| How to run the live Kali attack demo | [Kali Demo Walkthrough](./kali-demo-walkthrough.md) |
| What to do when an alert fires | [Incident Response Runbook](./incident-response-runbook.md) |
| Why a feature is broken | [Troubleshooting](./troubleshooting.md) |
| How to run tests | [Testing and Quality](/dev/testing-and-quality) |
| Production deployment steps | [Operations and Deployment](./operations-and-deployment.md) |

## Canonical Documentation Policy

- **User docs**: `/docs-site/docs/` — rendered as the public-facing docs site
- **Dev docs**: `/docs-site/dev/` — rendered under the `/dev` path prefix
- **Docusaurus config**: `/docs-site/docusaurus.config.js`
- **Build command**: `cd docs-site && npm run build`
- **Rule**: When you change behavior in code, update the corresponding docs in the same pull request
