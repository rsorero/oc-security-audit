#!/bin/sh
# TEST HARNESS for oc-security-audit v2.2
# Run this from the v6 project root to validate discover.sh + scan.sh output.
# REMOVE BEFORE PRODUCTION — this is a development-only diagnostic tool.
set -u

SKILL_DIR="$(cd "$(dirname "$(realpath "$0" 2>/dev/null || echo "$0")")/.." && pwd)"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
PASS=0; FAIL=0; WARN=0

check() {
  local label="$1" condition="$2"
  if eval "$condition"; then
    echo -e "  ${GREEN}✓${NC} $label"
    PASS=$((PASS+1))
  else
    echo -e "  ${RED}✗${NC} $label"
    FAIL=$((FAIL+1))
  fi
}

warn_check() {
  local label="$1" condition="$2"
  if eval "$condition"; then
    echo -e "  ${GREEN}✓${NC} $label"
    PASS=$((PASS+1))
  else
    echo -e "  ${YELLOW}⚠${NC} $label (non-blocking)"
    WARN=$((WARN+1))
  fi
}

echo "============================================"
echo "OC Security Audit v2.1 — Test Harness"
echo "============================================"
echo ""

# ---- Phase 1: discover.sh ----
echo "▶ Phase 1: Running discover.sh..."
DISCOVERY=$(sh "$SKILL_DIR/scripts/discover.sh" 2>&1)
DISCOVER_EXIT=$?

echo ""
echo "--- discover.sh output ---"
echo "$DISCOVERY"
echo "--- end discover.sh ---"
echo ""

echo "▶ Phase 1 checks:"
check "discover.sh exits 0" "[ $DISCOVER_EXIT -eq 0 ]"
check "PROFILE line present" "echo \"\$DISCOVERY\" | grep -q '^PROFILE:'"
check "SRC_ROOT line present" "echo \"\$DISCOVERY\" | grep -q '^SRC_ROOT:'"
check "PROJECT_ROOT line present" "echo \"\$DISCOVERY\" | grep -q '^PROJECT_ROOT:'"
check "DOMAIN line present" "echo \"\$DISCOVERY\" | grep -q '^DOMAIN:'"
check "HOSTING line present" "echo \"\$DISCOVERY\" | grep -q '^HOSTING:'"
check "FRAMEWORK line present" "echo \"\$DISCOVERY\" | grep -q '^FRAMEWORK:'"
check "ORM line present" "echo \"\$DISCOVERY\" | grep -q '^ORM:'"
check "At least 1 ROUTE line" "echo \"\$DISCOVERY\" | grep -qc '^ROUTE:'"
check "ROUTE_COUNT > 0" "echo \"\$DISCOVERY\" | grep -E '^ROUTE_COUNT: [1-9]'"
warn_check "DOMAIN is not 'unknown'" "echo \"\$DISCOVERY\" | grep '^DOMAIN:' | grep -qv 'unknown'"
warn_check "FILE_UPLOADS line present" "echo \"\$DISCOVERY\" | grep -q '^FILE_UPLOADS:'"
warn_check "AI_SDK line present" "echo \"\$DISCOVERY\" | grep -q '^AI_SDK:'"

# Extract values for scan.sh
PROFILE=$(echo "$DISCOVERY" | grep '^PROFILE:' | awk '{print $2}')
SRC_ROOT=$(echo "$DISCOVERY" | grep '^SRC_ROOT:' | awk '{print $2}')
PROJECT_ROOT=$(echo "$DISCOVERY" | grep '^PROJECT_ROOT:' | awk '{print $2}')
DOMAIN=$(echo "$DISCOVERY" | grep '^DOMAIN:' | awk '{print $2}')
HOSTING=$(echo "$DISCOVERY" | grep '^HOSTING:' | awk '{print $2}')
FRAMEWORK=$(echo "$DISCOVERY" | grep '^FRAMEWORK:' | awk '{print $2}')
ORM=$(echo "$DISCOVERY" | grep '^ORM:' | awk '{print $2}')
FILE_UPLOADS=$(echo "$DISCOVERY" | grep '^FILE_UPLOADS:' | awk '{print $2}')
AI_SDK=$(echo "$DISCOVERY" | grep '^AI_SDK:' | awk '{print $2}')
ROUTE_COUNT=$(echo "$DISCOVERY" | grep -c '^ROUTE:' || echo "0")

echo ""
echo "  Extracted: PROFILE=$PROFILE FRAMEWORK=$FRAMEWORK ORM=$ORM DOMAIN=$DOMAIN"
echo "  Routes found: $ROUTE_COUNT"
echo ""

# ---- Phase 2: scan.sh ----
echo "▶ Phase 2: Running scan.sh..."
SCAN_OUTPUT=$(OC_PROFILE="${PROFILE:-unsupported}" \
  OC_SRC_ROOT="${SRC_ROOT:-.}" \
  OC_PROJECT_ROOT="${PROJECT_ROOT:-.}" \
  OC_DOMAIN="${DOMAIN:-}" \
  OC_HOSTING="${HOSTING:-unknown}" \
  OC_FRAMEWORK="${FRAMEWORK:-unknown}" \
  OC_ORM="${ORM:-unknown}" \
  OC_FILE_UPLOADS="${FILE_UPLOADS:-no}" \
  OC_AI_SDK="${AI_SDK:-none}" \
  sh "$SKILL_DIR/scripts/scan.sh" 2>&1)
SCAN_EXIT=$?

echo ""
echo "--- scan.sh output ---"
echo "$SCAN_OUTPUT"
echo "--- end scan.sh ---"
echo ""

echo "▶ Phase 2 checks:"
check "scan.sh exits 0" "[ $SCAN_EXIT -eq 0 ]"
check "TOTALS line present" "echo \"\$SCAN_OUTPUT\" | grep -q '^TOTALS:'"
check "At least 1 table row (|)" "echo \"\$SCAN_OUTPUT\" | grep -c '| .*|' | grep -q '[1-9]'"

# Extract totals
TOTALS_LINE=$(echo "$SCAN_OUTPUT" | grep '^TOTALS:')
if [ -n "$TOTALS_LINE" ]; then
  TOTAL_PASS=$(echo "$TOTALS_LINE" | grep -oE 'pass=[0-9]+' | cut -d= -f2)
  TOTAL_WARN=$(echo "$TOTALS_LINE" | grep -oE 'warn=[0-9]+' | cut -d= -f2)
  TOTAL_FAIL=$(echo "$TOTALS_LINE" | grep -oE 'fail=[0-9]+' | cut -d= -f2)
  TOTAL_SUM=$((TOTAL_PASS + TOTAL_WARN + TOTAL_FAIL))
  echo "  Totals: pass=$TOTAL_PASS warn=$TOTAL_WARN fail=$TOTAL_FAIL (sum=$TOTAL_SUM)"
  check "TOTALS sum > 10 (enough checks ran)" "[ $TOTAL_SUM -gt 10 ]"
fi

# Count actual emit_row outputs (lines with | PASS | or | WARN | or | FAIL |)
ACTUAL_PASS=$(echo "$SCAN_OUTPUT" | grep -c '✅ PASS' || echo "0")
ACTUAL_WARN=$(echo "$SCAN_OUTPUT" | grep -c '⚠️  WARN' || echo "0")
ACTUAL_FAIL=$(echo "$SCAN_OUTPUT" | grep -c '❌ FAIL' || echo "0")
ACTUAL_SUM=$((ACTUAL_PASS + ACTUAL_WARN + ACTUAL_FAIL))
echo "  Actual rows: pass=$ACTUAL_PASS warn=$ACTUAL_WARN fail=$ACTUAL_FAIL (sum=$ACTUAL_SUM)"
check "TOTALS match actual row counts" "[ \"$TOTAL_PASS\" = \"$ACTUAL_PASS\" ] && [ \"$TOTAL_WARN\" = \"$ACTUAL_WARN\" ] && [ \"$TOTAL_FAIL\" = \"$ACTUAL_FAIL\" ]"

# Check WSTG sections present
echo ""
echo "▶ WSTG section checks:"
check "WSTG-INFO section" "echo \"\$SCAN_OUTPUT\" | grep -q 'WSTG-INFO'"
check "WSTG-CONF section" "echo \"\$SCAN_OUTPUT\" | grep -q 'WSTG-CONF'"
check "WSTG-SESS section" "echo \"\$SCAN_OUTPUT\" | grep -q 'WSTG-SESS'"
check "WSTG-ATHZ section (routes found)" "echo \"\$SCAN_OUTPUT\" | grep -q 'WSTG-ATHZ'"
check "WSTG-INPV section" "echo \"\$SCAN_OUTPUT\" | grep -q 'WSTG-INPV'"
check "WSTG-CRYP section" "echo \"\$SCAN_OUTPUT\" | grep -q 'WSTG-CRYP'"
check "WSTG-DOS section (routes found)" "echo \"\$SCAN_OUTPUT\" | grep -q 'WSTG-DOS'"
check "Supply Chain section" "echo \"\$SCAN_OUTPUT\" | grep -q 'Supply Chain'"
check "Secrets section" "echo \"\$SCAN_OUTPUT\" | grep -qE 'CONF-09|Secrets'"
check "Privacy / Legal section" "echo \"\$SCAN_OUTPUT\" | grep -q 'PRIV-0'"
check "Logging section" "echo \"\$SCAN_OUTPUT\" | grep -qE 'LOGG-0|Logging'"
warn_check "WSTG-ATHN section (needs network)" "echo \"\$SCAN_OUTPUT\" | grep -q 'WSTG-ATHN'"
warn_check "WSTG-ERRH section (needs network)" "echo \"\$SCAN_OUTPUT\" | grep -q 'WSTG-ERRH'"
warn_check "DNS section (needs network)" "echo \"\$SCAN_OUTPUT\" | grep -q 'DNS'"

# Check critical spec requirements
echo ""
echo "▶ Spec requirement checks:"
check "No bare grep (all use -E)" "! grep -n 'grep ' \"$SKILL_DIR/scripts/scan.sh\" | grep -v 'grep -' | grep -v '#' | grep -v 'grep -' | grep -qv '||'"
check "emit_row uses ASCII status" "grep -q 'PASS) symbol' \"$SKILL_DIR/scripts/scan.sh\""
check "Pipe replacement in emit_row" "grep -q 'evidence.*{4//|' \"$SKILL_DIR/scripts/scan.sh\""
check "SECURITY DECLARATION present" "grep -q 'SECURITY DECLARATION' \"$SKILL_DIR/scripts/scan.sh\""
check "patterns.sh sourced (not eval)" "grep -q 'patterns.sh' \"$SKILL_DIR/scripts/scan.sh\""
check "npm audit uses || true" "grep 'npm audit' \"$SKILL_DIR/scripts/scan.sh\" | grep -q '|| true'"
check "SKILL.md under 500 lines" "[ \$(wc -l < \"$SKILL_DIR/SKILL.md\") -lt 500 ]"
check "No Write in allowed-tools" "! grep 'allowed-tools' \"$SKILL_DIR/SKILL.md\" | grep -q 'Write'"
check "patterns.sh has no BRE \\|" "! grep -P '(?<!\()\\\\\\|' \"$SKILL_DIR/profiles/nextjs-prisma.patterns.sh\" 2>/dev/null || true"
check "Single PATTERN_PROTO (no POLLUTION)" "! grep -q 'PATTERN_PROTO_POLLUTION' \"$SKILL_DIR/profiles/nextjs-prisma.patterns.sh\""

# ---- Phase 3: Profile-to-scan.sh completeness ----
echo ""
echo "▶ Phase 3: Profile-to-scan.sh completeness check"
PROFILE_PATH="$SKILL_DIR/profiles/nextjs-prisma.md"
SCAN_PATH="$SKILL_DIR/scripts/scan.sh"

# WHY: Extract all WSTG IDs marked RUN from the profile — these MUST have check functions
PROFILE_RUN_IDS=$(grep -E 'RUN \(script\)|RUN \(escape-hatch\)|RUN \(conditional\)' "$PROFILE_PATH" \
  | sed -E 's/^\|([^|]+)\|.*/\1/' \
  | grep -oE '[A-Z]+-[A-Z0-9]+|[A-Z]+[0-9]+' \
  | grep -vE '^JUDGMENT' \
  | sort -u)

PROFILE_RUN_COUNT=$(echo "$PROFILE_RUN_IDS" | grep -c '.' || echo "0")
MISSING_IMPL=0

for ID in $PROFILE_RUN_IDS; do
  FUNC="check_$(echo "$ID" | tr '[:upper:]' '[:lower:]' | tr '-' '_')"
  if grep -q "^${FUNC}()" "$SCAN_PATH" 2>/dev/null; then
    : # found
  else
    echo -e "  ${RED}✗${NC} MISSING: $ID — no $FUNC() in scan.sh"
    MISSING_IMPL=$((MISSING_IMPL+1))
    FAIL=$((FAIL+1))
  fi
done

if [ "$MISSING_IMPL" -eq 0 ]; then
  echo -e "  ${GREEN}✓${NC} All $PROFILE_RUN_COUNT RUN checks have implementations in scan.sh"
  PASS=$((PASS+1))
else
  echo -e "  ${RED}✗${NC} $MISSING_IMPL of $PROFILE_RUN_COUNT RUN checks missing implementations"
fi

# WHY: Check for NOT IMPLEMENTED rows in scan output — these indicate profile/scan.sh drift
if echo "$SCAN_OUTPUT" | grep -q 'NOT IMPLEMENTED' 2>/dev/null; then
  echo -e "  ${RED}✗${NC} NOT IMPLEMENTED rows found in scan output"
  FAIL=$((FAIL+1))
else
  echo -e "  ${GREEN}✓${NC} No NOT IMPLEMENTED rows in scan output"
  PASS=$((PASS+1))
fi

# WHY: Verify every row in the profile has a decision (no blank Decision column)
BLANK_DECISIONS=$(grep -E '^\|[^|]+\|[^|]+\|[[:space:]]*\|' "$PROFILE_PATH" 2>/dev/null | grep -vE '^[-|[:space:]]+$' | grep -v 'Decision' || true)
if [ -n "$BLANK_DECISIONS" ]; then
  echo -e "  ${RED}✗${NC} Profile has rows without a decision:"
  echo "$BLANK_DECISIONS" | head -3
  FAIL=$((FAIL+1))
else
  echo -e "  ${GREEN}✓${NC} All profile rows have a decision (RUN/SKIP/DEFER)"
  PASS=$((PASS+1))
fi

# ---- Summary ----
echo ""
echo "============================================"
TOTAL_CHECKS=$((PASS + FAIL + WARN))
echo -e "Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}, ${YELLOW}${WARN} warnings${NC} (${TOTAL_CHECKS} total)"
if [ $FAIL -eq 0 ]; then
  echo -e "${GREEN}All critical checks passed!${NC}"
  if [ $WARN -gt 0 ]; then
    echo -e "${YELLOW}Warnings are non-blocking — may be due to network/domain config.${NC}"
  fi
  echo ""
  echo "Next: Run /oc-security-audit in a fresh Claude Code session for the full LLM test."
else
  echo -e "${RED}${FAIL} check(s) failed — fix before running the full skill.${NC}"
fi
echo "============================================"
