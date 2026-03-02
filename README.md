# Anthra Security Platform

**Client:** Anthra Security Inc.
**Engagement:** FedRAMP Moderate Authorization
**Consultant:** GuidePoint Security
**Objective:** Achieve FedRAMP Moderate authorization to sell to federal agencies

---

## About Anthra

Anthra Security is a cloud-native security monitoring and log aggregation SaaS platform, founded in 2020. Think of us as a lightweight alternative to Splunk or Datadog, purpose-built for modern containerized environments.

**Current Status:**
- 25 employees, Series A funded ($8M)
- 150+ commercial customers (startups, SMBs)
- SaaS platform running on EKS
- Tech stack: Python, Go, React, PostgreSQL

**Business Goal:**
We want to win federal contracts (DHS, VA, GSA) which require FedRAMP Moderate authorization. Our application was built for speed-to-market by a development team focused on features, not security-first architecture. We need GuidePoint Security's expertise to make us FedRAMP compliant.

---

## What Does Anthra Do?

Multi-tenant security monitoring platform providing:

- **Log Aggregation:** Centralized collection from distributed agents
- **Threat Detection:** Real-time alerting on security events
- **Compliance Dashboards:** Pre-built views for SOC2, PCI-DSS, etc.
- **Multi-Tenant Isolation:** Each customer (DHS, VA, FBI) gets isolated namespace
- **API-First:** RESTful API for integration with existing tools

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    ANTHRA PLATFORM                           │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   UI Layer           API Layer          Ingest Layer        │
│   ─────────          ─────────          ──────────           │
│                                                              │
│   React              FastAPI            Go Service          │
│   Dashboard    ←───▶ (Python)     ←───▶ Log Ingest         │
│   (Port 3000)        (Port 8080)        (Port 9090)         │
│                           │                  │               │
│                           └──────┬───────────┘               │
│                                  ▼                           │
│                            PostgreSQL                        │
│                            (Port 5432)                       │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Quick Start

```bash
# Start the platform locally
docker compose up -d

# Check API health
curl http://localhost:8080/api/health

# View dashboard
open http://localhost:3000

# Send test log
curl -X POST http://localhost:9090/ingest \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "tenant-1", "level": "INFO", "message": "Test log", "source": "test"}'
```

---

## Current Security Posture

Our application has common security gaps typical of dev teams building quickly:

### Application Layer
- ❌ No authentication middleware (TODO markers in code)
- ❌ MD5 password hashing (weak, should be bcrypt/argon2)
- ❌ Credentials in environment variables (not Secrets Manager)
- ❌ No rate limiting on any endpoints
- ❌ Verbose error messages (leak stack traces)
- ❌ No CSRF protection
- ❌ Permissive CORS policy (`*` origins)
- ❌ Debug endpoint exposed (`/api/debug` shows credentials) <!-- CVE-522 -->

### Infrastructure Layer (K8s)
- ❌ Containers run as root (no `securityContext`)
- ❌ No resource limits (`memory`, `CPU`)
- ❌ No NetworkPolicy (all pods can talk to all pods)
- ❌ Secrets stored as env vars (not K8s Secrets)
- ❌ `:latest` image tags (mutable, untraceable)
- ❌ NodePort services (externally exposed)
- ❌ No TLS on Ingress
- ❌ Default ServiceAccount (no RBAC)
- ❌ No liveness/readiness probes

### Deployment
- ❌ No CI/CD security scanning
- ❌ No policy enforcement (Kyverno/Gatekeeper)
- ❌ No runtime monitoring (Falco)

**Why these gaps exist:**
Our team prioritized feature velocity to secure Series A funding. We moved fast, shipped often, and won commercial customers. Now we need to harden for the federal market.

---

## FedRAMP Compliance Engagement

**Consultant:** GuidePoint Security
**Timeline:** 10 weeks
**Target:** FedRAMP Moderate (NIST 800-53 Rev 5 — 323 controls)

### Engagement Phases

| Phase | Focus | Timeline | Deliverable |
|-------|-------|----------|-------------|
| **1. Gap Assessment** | Scan app, map to NIST controls | Week 1-2 | Gap assessment report |
| **2. Control Implementation** | Deploy policies, harden configs | Week 2-4 | Hardened platform |
| **3. Documentation** | Generate SSP, POA&M, SAR | Week 4-6 | Compliance docs |
| **4. Evidence Collection** | Automated proof of compliance | Week 6-8 | Evidence artifacts |
| **5. 3PAO Preparation** | Audit readiness | Week 8-10 | ATO-ready posture |

**GuidePoint Methodology:**
All work follows the GuidePoint FedRAMP Ready playbook located in:
`GP-CONSULTING/07-FedRAMP-Ready/`

**Automation:**
GuidePoint's JSA (Junior Security Agent) agents automate:
- **jsa-devsec:** Pre-deployment scanning (Trivy, Semgrep, Gitleaks)
- **jsa-infrasec:** Runtime enforcement (Falco, policy admission)
- **jsa-secops:** Compliance reporting (scan-and-map, evidence collection)

---

## Directory Structure

```
Anthra-FedRAMP/
├── README.md                        # This file
├── PRE-DEPLOYMENT-IMPLEMENTATION.md # Full implementation guide
├── docker-compose.yml               # Local development stack (intentionally insecure)
├── .bandit.yaml                     # Bandit Python SAST config
├── .hadolint.yaml                   # Hadolint Dockerfile linting config
├── .yamllint.yaml                   # YAML style validation config
├── .pre-commit-config.yaml          # Pre-commit hooks (8 validators)
│
├── .github/workflows/               # CI/CD security pipelines
│   ├── security-pipeline.yml        # Main pipeline — 9 jobs (Gitleaks, Semgrep, Trivy, etc.)
│   ├── fedramp-ci.yml               # FedRAMP-specific gate (Trivy, Semgrep, Conftest, Kyverno)
│   └── compliance-report.yml        # Weekly CA-7 compliance report (Phase 2 stub)
│
├── api/                             # Python FastAPI application
│   ├── Dockerfile                   # Intentionally insecure (demo baseline)
│   ├── main.py                      # API server (bcrypt implemented, other gaps remain)
│   └── requirements.txt
├── services/                        # Go log-ingest microservice
│   ├── Dockerfile
│   └── main.go
├── ui/                              # React dashboard
│   ├── Dockerfile
│   └── src/
├── infrastructure/                  # Kubernetes manifests
│   ├── namespace.yaml               # ✅ PSS restricted enforce/audit/warn
│   ├── api-deployment.yaml          # ✅ Fully hardened (non-root, caps dropped, limits)
│   ├── ui-deployment.yaml           # ✅ Fully hardened
│   ├── db-deployment.yaml           # ✅ Fully hardened (UID 999)
│   ├── log-ingest-deployment.yaml   # ✅ Fully hardened
│   ├── services.yaml                # ❌ NodePort (SC-7 gap — intentional demo)
│   ├── secret.yaml                  # ⚠️  Base64 creds (rotate before prod)
│   └── ingress.yaml                 # ❌ No TLS (SC-8 gap — Phase 2 fix)
├── db/                              # Database initialization
│   └── init.sql
├── docs/                            # Engagement documentation
│   └── COMPANY-PROFILE.md           # Anthra background
│
└── GP-Copilot/                      # GuidePoint Iron Legion artifacts
    ├── SUMMARY.md                   # Executive summary
    ├── jsa-devsec/                  # JSA-DevSec scan artifacts
    │   ├── README.md
    │   ├── semgrep-rules.yaml       # ✅ Custom FedRAMP Semgrep rules (14 rules)
    │   ├── gitleaks.toml            # ✅ Custom Gitleaks config + allowlist
    │   ├── conftest-runner.sh       # ✅ OPA Conftest runner script
    │   ├── findings/                # 41 JSON finding files (D-rank)
    │   ├── reports/                 # SCAN-REPORT-2026-02-12.md
    │   └── remediations/            # Fix templates (3 files)
    ├── opa-package/                 # OPA/Kyverno admission policies
    │   ├── require-security-context.yaml   # AC-6 (Gatekeeper)
    │   ├── block-latest-tags.yaml          # CM-2 (Kyverno)
    │   ├── rego/                           # Conftest policies
    │   │   ├── 03-prohibit-insecure-services.rego
    │   │   └── 05-require-resource-limits.rego
    │   └── tests/                          # OPA unit tests
    ├── fedRAMP-package/
    │   └── SSP-APPENDIX-A-FINDINGS.md      # 3PAO-ready SSP appendix
    └── summaries/
        └── remediation_summary_20260224.md
```

---

## API Endpoints

| Endpoint | Method | Purpose | Security Gap |
|----------|--------|---------|--------------|
| `/api/health` | GET | Health check | CWE-306 (no auth) |
| `/api/auth/login` | POST | User authentication | CWE-916 (MD5), CWE-307 (no rate limit) |
| `/api/auth/register` | POST | User registration | CWE-916 (MD5) |
| `/api/logs` | GET | Retrieve logs | CWE-306 (no auth), CWE-284 (no tenant isolation) |
| `/api/logs` | POST | Create log | CWE-306 (no auth), CWE-770 (no rate limit) |
| `/api/alerts` | GET | Retrieve alerts | CWE-306 (no auth) |
| `/api/alerts` | POST | Create alert | CWE-306 (no auth) |
| `/api/search` | GET | Search logs | CWE-306 (no auth) |
| `/api/debug` | GET | Debug info | **CWE-522 (exposes credentials)** 🔴 |
| `/api/stats` | GET | Platform statistics | CWE-306 (no auth) |

---

## What GuidePoint Will Fix

Using their Iron Legion platform (`GP-CONSULTING/07-FedRAMP-Ready/`):

### Phase 1 — Pre-Deployment (JSA-DevSec) ✅ COMPLETE
- ✅ Trivy container + dependency scanning (CVE-2024-24762 patched)
- ✅ Semgrep SAST — 14 custom FedRAMP rules deployed
- ✅ Gitleaks secret detection — custom Anthra ruleset + allowlist
- ✅ Conftest OPA policy validation — conftest-runner.sh wired
- ✅ GitHub Actions CI/CD pipeline — 9 security jobs
- ✅ JSA-DevSec auto-fix loop — D-rank pattern remediation on PR
- ✅ Pre-commit hooks — 8 validators shift-left
- ✅ OPA/Kyverno admission policies deployed

### Phase 2 — Runtime Security (JSA-InfraSec) ⏭️ NEXT
- ⏭️ Falco runtime threat detection
- ⏭️ NetworkPolicy (namespace isolation)
- ⏭️ Ingress TLS (cert-manager, SC-8)
- ⏭️ Service type migration (NodePort → ClusterIP + Ingress)
- ⏭️ Automatic incident response

### Phase 3 — Compliance Automation (JSA-SecOps) ⏭️ PLANNED
- ⏭️ NIST 800-53 control mapping (scan-and-map.py)
- ⏭️ SSP generation (System Security Plan)
- ⏭️ POA&M tracking (Plan of Action & Milestones)
- ⏭️ Evidence collection pipeline (evidence-collector.sh)
- ⏭️ Continuous monitoring dashboard

---

## CI/CD Pipeline Setup

Two pipelines are active. Both require GitHub repo secrets to run JSA-DevSec auto-fix:

### Required Secrets (GitHub → Settings → Secrets → Actions)

| Secret | Value | Purpose |
|--------|-------|---------|
| `GP_COPILOT_REPO` | `org/GP-copilot` | GP-Copilot monorepo location |
| `GP_COPILOT_TOKEN` | PAT (repo:read) | Access to pull JSA-DevSec agent |

### Pipeline Overview

| Workflow | Trigger | Jobs | Purpose |
|----------|---------|------|---------|
| `security-pipeline.yml` | push, PR, daily 2AM | 9 | Full FedRAMP gate + JSA auto-fix |
| `fedramp-ci.yml` | push main, PR | 5 | Fast FedRAMP control checks |
| `compliance-report.yml` | weekly Mon 6AM | 1 | CA-7 evidence collection (Phase 3) |

### JSA Auto-Fix Loop (on PR)

```
Developer opens PR
  → secrets-scan (Gitleaks) — blocks if secrets found
  → sast-scan (Semgrep + Bandit) — SARIF to GitHub Security tab
  → dependency-scan (Trivy) — blocks on CRITICAL/HIGH CVEs
  → jsa-auto-fix (JSA-DevSec D-rank) — commits fixes, comments on PR
  → Policy validation (Conftest OPA)
  → security-report — uploads 90-day evidence artifacts
```

---

## Technical Debt → Security Debt

Common patterns we need to address:

| Pattern | Why It Exists | FedRAMP Risk |
|---------|--------------|--------------|
| MD5 passwords | Legacy code from MVP | CRITICAL |
| No auth middleware | "We'll add it later" | CRITICAL |
| Secrets in env vars | Easier than Secrets Manager | HIGH |
| No rate limiting | Not needed for 150 users | MEDIUM |
| Debug endpoint | Left from development | CRITICAL |
| Verbose errors | Helpful during debugging | MEDIUM |
| Root containers | Docker defaults | HIGH |
| No NetworkPolicy | K8s doesn't require it | HIGH |

**We're not a bad team — we're a startup that moved fast.**
Now we need GuidePoint to help us secure federal contracts.

---

## Contact

**Anthra Security Inc.**
Engineering Team
[redacted]@anthra.io

**GuidePoint Security**
FedRAMP Practice Lead
[Engagement managed via GP-CONSULTING/07-FedRAMP-Ready/]

---

*Built with speed. Hardened with GuidePoint.*
