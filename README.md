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
├── README.md                    # This file
├── docker-compose.yml           # Local development stack
├── api/                         # Python FastAPI application
│   ├── Dockerfile
│   ├── main.py                  # API server
│   └── requirements.txt
├── services/                    # Go log-ingest microservice
│   ├── Dockerfile
│   ├── main.go
│   └── go.mod
├── ui/                          # React dashboard
│   ├── Dockerfile
│   ├── package.json
│   └── src/
├── infrastructure/              # Kubernetes manifests
│   ├── namespace.yaml
│   ├── api-deployment.yaml
│   ├── ui-deployment.yaml
│   ├── log-ingest-deployment.yaml
│   ├── db-deployment.yaml
│   ├── services.yaml
│   └── ingress.yaml
├── db/                          # Database initialization
│   └── init.sql
└── docs/                        # Engagement documentation
    ├── COMPANY-PROFILE.md       # Anthra background
    ├── ARCHITECTURE.md          # System design
    └── FEDRAMP-SCOPE.md         # Compliance scope
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

### Pre-Deployment (JSA-DevSec)
- ✅ Trivy container scanning
- ✅ Semgrep SAST analysis
- ✅ Gitleaks secret detection
- ✅ Conftest policy validation
- ✅ Automated remediation

### Runtime (JSA-InfraSec)
- ✅ Kyverno admission policies
- ✅ Gatekeeper OPA constraints
- ✅ Falco runtime monitoring
- ✅ NetworkPolicy enforcement
- ✅ Automatic incident response

### Compliance (JSA-SecOps)
- ✅ NIST 800-53 control mapping
- ✅ SSP generation (System Security Plan)
- ✅ POA&M tracking (Plan of Action & Milestones)
- ✅ Evidence collection (automated artifacts)
- ✅ Continuous monitoring

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
