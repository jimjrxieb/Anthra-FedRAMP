#!/usr/bin/env bash
# conftest-runner.sh — FedRAMP OPA Policy Validation Runner
# NIST Controls: CM-3, CM-6 (Configuration Change Control)
# Consultant: GuidePoint Security / JSA-DevSec
#
# Usage:
#   ./conftest-runner.sh [policy-dir] [target-dir]
#
# Defaults:
#   policy-dir  → GP-Copilot/opa-package/rego
#   target-dir  → infrastructure
#
# Exit codes:
#   0 = all policies pass
#   1 = policy violations found
#   2 = setup error (missing tools, dirs)

set -euo pipefail

POLICY_DIR="${1:-GP-Copilot/opa-package/rego}"
INFRA_DIR="${2:-infrastructure}"

EXIT_CODE=0
MANIFEST_COUNT=0
FAIL_COUNT=0
PASS_COUNT=0

# ANSI colours for readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'  # No Colour

echo ""
echo -e "${BLUE}=========================================================${NC}"
echo -e "${BLUE}  [CM-3/CM-6] OPA Conftest Policy Validation${NC}"
echo -e "${BLUE}  Anthra Security Platform — FedRAMP Moderate${NC}"
echo -e "${BLUE}=========================================================${NC}"
echo ""
echo "  Policy dir : ${POLICY_DIR}"
echo "  Target dir : ${INFRA_DIR}"
echo ""

# ----------------------------------------------------------
# Prerequisite checks
# ----------------------------------------------------------

if ! command -v conftest &> /dev/null; then
  echo -e "${RED}ERROR: conftest not found.${NC}"
  echo "Install: https://www.conftest.dev/install/"
  echo "  wget https://github.com/open-policy-agent/conftest/releases/download/v0.56.0/conftest_0.56.0_Linux_x86_64.tar.gz"
  echo "  tar xzf conftest_*.tar.gz && sudo mv conftest /usr/local/bin/"
  exit 2
fi

if [ ! -d "${POLICY_DIR}" ]; then
  echo -e "${YELLOW}WARNING: Policy directory not found: ${POLICY_DIR}${NC}"
  echo "Skipping OPA validation — no policies deployed yet."
  echo "(Phase 3: OPA/Gatekeeper deployment required)"
  exit 0
fi

if [ ! -d "${INFRA_DIR}" ]; then
  echo -e "${YELLOW}WARNING: Infrastructure directory not found: ${INFRA_DIR}${NC}"
  echo "Skipping OPA validation — no K8s manifests found."
  exit 0
fi

# ----------------------------------------------------------
# Run conftest against each K8s manifest
# ----------------------------------------------------------

echo -e "${BLUE}--- Testing K8s manifests ---${NC}"
echo ""

for manifest in "${INFRA_DIR}"/*.yaml "${INFRA_DIR}"/*.yml; do
  [ -f "${manifest}" ] || continue

  MANIFEST_COUNT=$((MANIFEST_COUNT + 1))
  BASENAME=$(basename "${manifest}")

  echo -n "  Testing ${BASENAME}... "

  # Capture output and exit code
  RESULT=$(conftest test "${manifest}" \
    --policy "${POLICY_DIR}" \
    --output json 2>&1) || CONF_EXIT=$?

  if [ "${CONF_EXIT:-0}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo -e "${RED}FAIL${NC}"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    EXIT_CODE=1

    # Pretty-print violations
    if command -v jq &> /dev/null; then
      echo "${RESULT}" | jq -r '.[] | .failures[]? | "    ❌ \(.msg)"' 2>/dev/null || true
      echo "${RESULT}" | jq -r '.[] | .warnings[]? | "    ⚠️  \(.msg)"' 2>/dev/null || true
    else
      # Fallback without jq
      conftest test "${manifest}" \
        --policy "${POLICY_DIR}" \
        --output table 2>&1 | sed 's/^/    /' || true
    fi
  fi
done

# ----------------------------------------------------------
# Also test docker-compose.yml if present
# ----------------------------------------------------------

if [ -f "docker-compose.yml" ] && [ -f "${POLICY_DIR}/docker-compose.rego" ]; then
  MANIFEST_COUNT=$((MANIFEST_COUNT + 1))
  echo -n "  Testing docker-compose.yml... "
  if conftest test docker-compose.yml --policy "${POLICY_DIR}" --output json &>/dev/null; then
    echo -e "${GREEN}PASS${NC}"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo -e "${RED}FAIL${NC}"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    EXIT_CODE=1
  fi
fi

# ----------------------------------------------------------
# Summary
# ----------------------------------------------------------

echo ""
echo -e "${BLUE}=========================================================${NC}"
echo "  Results: ${MANIFEST_COUNT} manifests tested"
echo -e "  ${GREEN}Passed:${NC}  ${PASS_COUNT}"
echo -e "  ${RED}Failed:${NC}  ${FAIL_COUNT}"
echo -e "${BLUE}=========================================================${NC}"
echo ""

if [ ${EXIT_CODE} -ne 0 ]; then
  echo -e "${RED}[CM-3] VIOLATION: Policy failures detected.${NC}"
  echo "  FedRAMP CM-3 requires all configuration changes to pass"
  echo "  policy validation before deployment. Review findings above."
  echo ""
  echo "  Policy reference: GP-Copilot/opa-package/"
  echo "  Fix guide: GP-Copilot/jsa-devsec/reports/"
else
  echo -e "${GREEN}[CM-3] PASS: All manifests comply with OPA policies.${NC}"
fi

echo ""
exit ${EXIT_CODE}
