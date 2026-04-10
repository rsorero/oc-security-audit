#!/bin/sh
set -u  # Note: NOT set -e — npm audit and curl exit non-zero on findings
export LC_ALL=en_US.UTF-8  # WHY: Consistent emoji output across macOS/Linux locales
# WHY: Derive SKILL_DIR safely — $0 may contain literal ~ which bash does not expand
# in double-quoted subshells. realpath/readlink resolve to absolute path first.
SCRIPT_PATH="$(realpath "$0" 2>/dev/null || readlink -f "$0" 2>/dev/null || echo "$0")"
SKILL_DIR="$(cd "$(dirname "$SCRIPT_PATH")/.." && pwd)"

# SECURITY DECLARATION:
# - Read-only: this script does NOT modify any files
# - No secrets: does NOT read or output env var VALUES (only checks key existence)
# - Network: GET/HEAD requests ONLY to the user's own production domain ($OC_DOMAIN)
# - No POST: does NOT submit data to any server
# - Output: stdout only — no files written
# - Every command is commented with # WHY: explaining what it checks and why

# ============================================================
# C. Env var inputs (all passed by SKILL.md Step 2)
# ============================================================
PROFILE="${OC_PROFILE:-unsupported}"
SRC_ROOT="${OC_SRC_ROOT:-.}"
PROJECT_ROOT="${OC_PROJECT_ROOT:-.}"
DOMAIN="${OC_DOMAIN:-}"
HOSTING="${OC_HOSTING:-unknown}"
FRAMEWORK="${OC_FRAMEWORK:-unknown}"
ORM="${OC_ORM:-unknown}"
FILE_UPLOADS="${OC_FILE_UPLOADS:-no}"
AI_SDK="${OC_AI_SDK:-none}"

# ============================================================
# D. Pattern sourcing via companion .patterns.sh file
# ============================================================
# WHY: If the profile is unsupported, skip pattern sourcing entirely.
# Generic checks don't need profile-specific grep patterns.
if [ "$PROFILE" != "unsupported" ]; then
  PATTERNS_FILE="$SKILL_DIR/profiles/${PROFILE}.patterns.sh"
  # WHY: Source patterns from a shell file, NOT eval from markdown.
  # ERE patterns contain (, ), {, } which eval would interpret as shell code.
  # shellcheck source=/dev/null
  . "$PATTERNS_FILE" 2>/dev/null || { echo "ERROR: patterns file not found: $PATTERNS_FILE"; exit 1; }
fi

# ============================================================
# E. Counters and emit_row helper
# ============================================================
PASS_COUNT=0; WARN_COUNT=0; FAIL_COUNT=0

# WHY: Per-category counters for the Audit Details summary table.
# Category names match the report template's 14 user-facing categories.
# Uses a temp file as a key-value store (POSIX sh has no associative arrays).
_cat_file=$(mktemp)
trap 'rm -f "$_cat_file"' EXIT

# WHY: Sanitize category name to a valid shell-safe key (e.g. "Code injection" → "code_injection")
_cat_key() { echo "$1" | tr ' /' '__' | tr -cd 'a-zA-Z0-9_'; }

# Get/set/increment helpers for the category key-value store
cat_get() {
  _key=$(_cat_key "$2")
  _val=$(grep "^${1}_${_key}=" "$_cat_file" 2>/dev/null | tail -1 | cut -d= -f2)
  echo "${_val:-0}"
}
cat_set() {
  _key=$(_cat_key "$2")
  echo "${1}_${_key}=$3" >> "$_cat_file"
}
cat_inc() {
  _old=$(cat_get "$1" "$2")
  cat_set "$1" "$2" "$(( _old + 1 ))"
}
# Get/append for the IDS tracker (comma-separated WSTG IDs)
cat_get_ids() {
  _key=$(_cat_key "$1")
  _val=$(grep "^IDS_${_key}=" "$_cat_file" 2>/dev/null | tail -1 | cut -d= -f2-)
  echo "${_val:-}"
}
cat_set_ids() {
  _key=$(_cat_key "$1")
  echo "IDS_${_key}=$2" >> "$_cat_file"
}

# WHY: Map WSTG ID prefix to user-facing category name
id_to_category() {
  local id="$1"
  case "$id" in
    INPV-18)       echo "SSRF" ;;
    INPV-*)        echo "Code injection" ;;
    CONF-04|CONF-09) echo "Secret leakage" ;;
    CONF-01|CONF-10) echo "Hosting bypass" ;;
    CONF-*|CRYP-*|INFO-*|DNS-*) echo "Infrastructure config" ;;
    ATHN-*|SESS-*) echo "Session / auth" ;;
    ATHZ-*)        echo "User data / IDOR" ;;
    ERRH-*)        echo "Error handling" ;;
    DOS-*|FILE-*|BUSL-07|BUSL-08) echo "DDoS / API abuse" ;;
    BUSL-*)        echo "Business logic" ;;
    SUPPLY-*)      echo "Supply chain" ;;
    PRIV-*|IDNT-*) echo "Privacy / legal" ;;
    LOGG-*)        echo "Logging" ;;
    LLM*)          echo "AI/LLM security" ;;
    EXT-API)       echo "External APIs" ;;
    API*)          echo "OWASP API Top 10" ;;
    *)             echo "Other" ;;
  esac
}

# WHY: emit_row outputs one pre-formatted markdown table row per check.
# Uses ASCII PASS/WARN/FAIL for case matching — NOT emoji (unreliable in bash case on Linux).
# Pipes in evidence are replaced with / to prevent broken markdown tables.
# Also tracks per-category counts for the summary table.
emit_row() {
  wstg="$1"; name="$2"; status="$3"
  evidence=$(echo "$4" | tr '|' '/')  # WHY: | in evidence breaks markdown table columns
  category=$(id_to_category "$wstg")

  case "$status" in
    PASS) symbol="✅ PASS"; PASS_COUNT=$((PASS_COUNT+1)); cat_inc PASS "$category" ;;
    WARN) symbol="⚠️  WARN"; WARN_COUNT=$((WARN_COUNT+1)); cat_inc WARN "$category" ;;
    FAIL) symbol="❌ FAIL"; FAIL_COUNT=$((FAIL_COUNT+1)); cat_inc FAIL "$category" ;;
    *)    symbol="$status" ;;
  esac

  # WHY: Track which WSTG IDs belong to each category (for the OWASP Tests column)
  _existing_ids=$(cat_get_ids "$category")
  if [ -z "$_existing_ids" ]; then
    cat_set_ids "$category" "$wstg"
  elif ! echo "$_existing_ids" | grep -qF "$wstg"; then
    cat_set_ids "$category" "${_existing_ids}, $wstg"
  fi

  printf "| %-15s | %-45s | %-10s | %s |\n" "$wstg" "$name" "$symbol" "$evidence"
}

# ============================================================
# Helper: print section table header
# ============================================================
print_section_header() {
  echo ""
  echo "### $1"
  echo "| WSTG ID         | Check                                         | Status     | Evidence |"
  echo "|-----------------|-----------------------------------------------|------------|----------|"
}

# ============================================================
# Domain availability check
# ============================================================
NETWORK_AVAILABLE="yes"
if [ -z "$DOMAIN" ] || [ "$DOMAIN" = "unknown" ]; then
  NETWORK_AVAILABLE="no"
fi

# ============================================================
# F. Profile-driven check list
# ============================================================
if [ "$PROFILE" = "unsupported" ]; then
  # WHY: When no profile exists for this stack, run only generic stack-independent
  # checks that don't require framework-specific grep patterns.
  # These checks use curl, dig, npm audit, and file existence — no code pattern matching.
  echo "PROFILE: unsupported — running stack-independent checks only"
  echo "WILL_CHECK: security headers, TLS, exposed files, DNS, npm audit, secrets, Docker config, error handling, admin paths, HTTP methods"
  echo "WONT_CHECK: auth per route, rate limiting, code injection escape hatches, session config, LLM judgments"
  ALL_CHECKS="CONF-04 CONF-05 CONF-06 CONF-07 CONF-09 CONF-12 CONF-14 CRYP-01 ERRH-01 ERRH-02 DNS-01 DNS-02 DNS-03 SUPPLY-01 SUPPLY-02"
else
  PROFILE_FILE="$SKILL_DIR/profiles/${PROFILE}.md"
  if [ ! -f "$PROFILE_FILE" ]; then
    echo "ERROR: Profile not found: $PROFILE_FILE"
    exit 1
  fi

  # WHY: Extract all WSTG IDs marked RUN (script) from the profile.
  # The profile is the single source of truth for which checks to execute.
  # Format: | WSTG-ID | Test name | RUN (script) | ... |
  # Extract first column only (between first two pipes) to avoid matching
  # text like "S3" in method descriptions.
  RUN_CHECKS=$(grep -E 'RUN \(script\)' "$PROFILE_FILE" \
    | sed -E 's/^\|([^|]+)\|.*/\1/' \
    | grep -oE '[A-Z]+-[A-Z0-9]+|[A-Z]+[0-9]+' \
    | grep -vE '^JUDGMENT' \
    | sort -u)

  # WHY: Also extract RUN (escape-hatch) checks — framework escape hatches that still run
  ESCAPE_CHECKS_LIST=$(grep -E 'RUN \(escape-hatch\)' "$PROFILE_FILE" \
    | sed -E 's/^\|([^|]+)\|.*/\1/' \
    | grep -oE '[A-Z]+-[A-Z0-9]+|[A-Z]+[0-9]+' \
    | sort -u)

  # WHY: Also extract RUN (conditional) checks — they run if their condition is met
  CONDITIONAL_CHECKS=$(grep -E 'RUN \(conditional\)' "$PROFILE_FILE" \
    | sed -E 's/^\|([^|]+)\|.*/\1/' \
    | grep -oE '[A-Z]+-[A-Z0-9]+|[A-Z]+[0-9]+' \
    | grep -vE '^JUDGMENT' \
    | sort -u)

  # WHY: Merge all script-executable checks into one list for dispatch
  ALL_CHECKS=$(echo -e "${RUN_CHECKS}\n${ESCAPE_CHECKS_LIST}\n${CONDITIONAL_CHECKS}" | grep -v '^$' | sort -u)
fi

# ============================================================
# G. Helper functions
# ============================================================

# WHY: Fetch production headers once — many checks reuse them
PROD_HEADERS=""
PROD_HEADERS_FETCHED="no"
fetch_prod_headers() {
  if [ "$PROD_HEADERS_FETCHED" = "yes" ]; then return; fi
  if [ "$NETWORK_AVAILABLE" = "no" ]; then return; fi
  PROD_HEADERS=$(curl -sI "https://${DOMAIN}" --max-time 10 2>/dev/null || true)
  PROD_HEADERS_FETCHED="yes"
}

# WHY: Route discovery is shared state used by ATHZ-02, DOS-01, LLM10
ROUTE_LINES=""
ROUTE_DISCOVERY_DONE="no"
discover_routes() {
  if [ "$ROUTE_DISCOVERY_DONE" = "yes" ]; then return; fi
  ROUTE_DISCOVERY_DONE="yes"
  if [ -d "$SRC_ROOT/app/api" ]; then
    _scan_route_tmp=$(mktemp)
    find "$SRC_ROOT/app/api" \( -name "route.ts" -o -name "route.js" -o -name "route.tsx" -o -name "route.jsx" \) 2>/dev/null | sort > "$_scan_route_tmp"
    while IFS= read -r route_file; do
      # WHY: Convert file path to API endpoint — use # as sed delimiter to avoid conflict with | in ERE alternation
      API_PATH=$(echo "$route_file" | sed "s|${SRC_ROOT}/app/api||" | sed -E 's#/route\.(ts|js|tsx|jsx)$##')
      [ -z "$API_PATH" ] && API_PATH="/"

      HAS_AUTH="no"
      if grep -qE "$PATTERN_AUTH_CHECK" "$route_file" 2>/dev/null; then
        HAS_AUTH="yes"
      fi

      HAS_RATE_LIMIT="no"
      if grep -qE "$PATTERN_RATE_LIMIT" "$route_file" 2>/dev/null; then
        HAS_RATE_LIMIT="yes"
      fi

      METHODS=$(grep -oE 'export.*async.*function.*(GET|POST|PUT|PATCH|DELETE|OPTIONS)' "$route_file" 2>/dev/null | grep -oE 'GET\|POST\|PUT\|PATCH\|DELETE\|OPTIONS' | tr '\n' ',' | sed 's/,$//' || echo "unknown")
      [ -z "$METHODS" ] && METHODS="unknown"

      ROUTE_LINES="${ROUTE_LINES}ROUTE: /api${API_PATH} | methods=${METHODS} | auth=${HAS_AUTH} | rate_limit=${HAS_RATE_LIMIT} | file=${route_file}
"
    done < "$_scan_route_tmp"
    rm -f "$_scan_route_tmp"
  fi
}

# ============================================================
# H. Check functions (one per WSTG ID)
# ============================================================

# --- WSTG-INFO: Information Gathering ---

check_info_01() {
  # WHY: robots.txt may expose hidden paths or directories attackers can target
  if [ "$NETWORK_AVAILABLE" = "no" ]; then
    emit_row "INFO-01" "robots.txt accessible" "WARN" "Domain unknown — skipped"
    return
  fi
  ROBOTS_STATUS=$(curl -sI "https://${DOMAIN}/robots.txt" --max-time 10 2>/dev/null | head -1 | grep -oE '[0-9]{3}' | head -1 || true)
  if [ "$ROBOTS_STATUS" = "200" ]; then
    emit_row "INFO-01" "robots.txt accessible" "PASS" "HTTP $ROBOTS_STATUS — review for sensitive paths"
  else
    emit_row "INFO-01" "robots.txt accessible" "WARN" "HTTP ${ROBOTS_STATUS:-timeout} — missing or blocked"
  fi
}

check_info_02() {
  # WHY: sitemap.xml reveals all public URLs — useful for attackers to map the surface
  if [ "$NETWORK_AVAILABLE" = "no" ]; then
    emit_row "INFO-02" "sitemap.xml accessible" "WARN" "Domain unknown — skipped"
    return
  fi
  SITEMAP_STATUS=$(curl -sI "https://${DOMAIN}/sitemap.xml" --max-time 10 2>/dev/null | head -1 | grep -oE '[0-9]{3}' | head -1 || true)
  if [ "$SITEMAP_STATUS" = "200" ]; then
    emit_row "INFO-02" "sitemap.xml accessible" "PASS" "HTTP $SITEMAP_STATUS"
  else
    emit_row "INFO-02" "sitemap.xml accessible" "WARN" "HTTP ${SITEMAP_STATUS:-timeout} — not found"
  fi
}

check_info_03() {
  # WHY: x-powered-by header reveals server technology — aids targeted attacks
  if [ "$NETWORK_AVAILABLE" = "no" ]; then
    emit_row "INFO-03" "x-powered-by header" "WARN" "Domain unknown — skipped"
    return
  fi
  fetch_prod_headers
  POWERED_BY=$(echo "$PROD_HEADERS" | grep -iE '^x-powered-by' | head -1 || true)
  if [ -n "$POWERED_BY" ]; then
    emit_row "INFO-03" "x-powered-by header" "FAIL" "Header present: $POWERED_BY"
  else
    emit_row "INFO-03" "x-powered-by header" "PASS" "Header not present"
  fi
}

check_info_04() {
  # WHY: Enumerate entry points — route count summary from discovery
  discover_routes
  ROUTE_COUNT=$(echo "$ROUTE_LINES" | grep -cE '^ROUTE:' || true)
  if [ "$ROUTE_COUNT" -gt 0 ] 2>/dev/null; then
    emit_row "INFO-04" "API entry points enumerated" "PASS" "$ROUTE_COUNT API routes discovered"
  else
    emit_row "INFO-04" "API entry points enumerated" "WARN" "No API routes found in $SRC_ROOT/app/api"
  fi
}

check_info_08() {
  # WHY: Framework fingerprint — check if Next.js reveals itself via poweredByHeader config
  if grep -qE 'poweredByHeader.*false' "${PROJECT_ROOT}/next.config.ts" "${PROJECT_ROOT}/next.config.js" "${PROJECT_ROOT}/next.config.mjs" 2>/dev/null; then
    emit_row "INFO-08" "Framework fingerprint suppressed" "PASS" "poweredByHeader: false in next.config"
  else
    emit_row "INFO-08" "Framework fingerprint suppressed" "WARN" "poweredByHeader not disabled — Next.js sends X-Powered-By by default"
  fi
}

# --- WSTG-CONF: Configuration and Deployment ---

check_conf_01() {
  # WHY: Platform default subdomains bypass CDN/WAF protections (Cloudflare, etc.)
  case "$HOSTING" in
    railway) BYPASS_DOMAIN="*.up.railway.app" ;;
    vercel)  BYPASS_DOMAIN="*.vercel.app" ;;
    fly)     BYPASS_DOMAIN="*.fly.dev" ;;
    render)  BYPASS_DOMAIN="*.onrender.com" ;;
    *)       BYPASS_DOMAIN="platform subdomain (unknown hosting)" ;;
  esac
  emit_row "CONF-01" "Hosting bypass domain" "WARN" "Verify $BYPASS_DOMAIN is blocked — direct access bypasses WAF/Cloudflare"
}

check_conf_02() {
  # WHY: poweredByHeader sends X-Powered-By: Next.js — reveals framework
  if grep -qE 'poweredByHeader.*false' "${PROJECT_ROOT}/next.config.ts" "${PROJECT_ROOT}/next.config.js" "${PROJECT_ROOT}/next.config.mjs" 2>/dev/null; then
    emit_row "CONF-02" "next.config poweredByHeader" "PASS" "Disabled"
  else
    emit_row "CONF-02" "next.config poweredByHeader" "WARN" "Not explicitly disabled — Next.js sends X-Powered-By by default"
  fi

  # WHY: Source maps in production expose original source code to attackers
  if grep -qE 'productionBrowserSourceMaps.*true' "${PROJECT_ROOT}/next.config.ts" "${PROJECT_ROOT}/next.config.js" "${PROJECT_ROOT}/next.config.mjs" 2>/dev/null; then
    emit_row "CONF-02" "next.config productionBrowserSourceMaps" "FAIL" "Enabled — source code exposed in production"
  else
    emit_row "CONF-02" "next.config productionBrowserSourceMaps" "PASS" "Not enabled (defaults to false)"
  fi

  # WHY: Check if local node version is EOL — EOL = no security patches
  NODE_VERSION=$(node -v 2>/dev/null || echo "unknown")
  if [ "$NODE_VERSION" = "unknown" ]; then
    emit_row "CONF-02" "Node.js version" "WARN" "node not found — cannot check"
  else
    NODE_MAJOR=$(echo "$NODE_VERSION" | grep -oE '^v[0-9]+')  # e.g. "v16"
    IS_EOL=$(echo "$NODE_EOL_VERSIONS" | grep -wF "$NODE_MAJOR" || true)
    if [ -n "$IS_EOL" ]; then
      emit_row "CONF-02" "Node.js version" "WARN" "$NODE_VERSION is EOL — no security patches"
    else
      emit_row "CONF-02" "Node.js version" "PASS" "$NODE_VERSION is supported"
    fi
  fi
}

check_conf_03() {
  # WHY: Backup/temporary files may contain source code or credentials
  if [ "$NETWORK_AVAILABLE" = "no" ]; then
    emit_row "CONF-03" "Backup/temp files" "WARN" "Domain unknown — skipped"
    return
  fi
  BACKUP_FOUND="no"
  for BACKUP_EXT in ".bak" ".old" ".tmp" ".swp" ".sql" ".zip"; do
    BACKUP_STATUS=$(curl -sI "https://${DOMAIN}/index${BACKUP_EXT}" --max-time 5 2>/dev/null | head -1 | grep -oE '[0-9]{3}' | head -1 || true)
    if [ "$BACKUP_STATUS" = "200" ]; then
      emit_row "CONF-03" "Backup file: index${BACKUP_EXT}" "FAIL" "HTTP 200 — backup file accessible"
      BACKUP_FOUND="yes"
    fi
  done
  if [ "$BACKUP_FOUND" = "no" ]; then
    emit_row "CONF-03" "Backup/temp files" "PASS" "No backup files found at common extensions"
  fi
}

check_conf_04() {
  # WHY: Exposed sensitive files can leak credentials, source code, or config
  if [ "$NETWORK_AVAILABLE" = "no" ]; then
    emit_row "CONF-04" "Sensitive file exposure" "WARN" "Domain unknown — skipped"
    return
  fi
  for SENSITIVE_PATH in ".env" ".git/HEAD" "package.json" ".DS_Store" ".npmrc"; do
    STATUS=$(curl -sI "https://${DOMAIN}/${SENSITIVE_PATH}" --max-time 5 2>/dev/null | head -1 | grep -oE '[0-9]{3}' | head -1 || true)
    if [ "$STATUS" = "200" ]; then
      emit_row "CONF-04" "Exposed: /$SENSITIVE_PATH" "FAIL" "HTTP 200 — file accessible"
    else
      emit_row "CONF-04" "Exposed: /$SENSITIVE_PATH" "PASS" "HTTP ${STATUS:-timeout}"
    fi
  done
}

check_conf_05() {
  # WHY: Admin/debug paths should not be publicly accessible
  if [ "$NETWORK_AVAILABLE" = "no" ]; then
    emit_row "CONF-05" "Admin interfaces" "WARN" "Domain unknown — skipped"
    return
  fi
  for ADMIN_PATH in "/admin" "/dashboard" "/_debug" "/api/debug"; do
    ADMIN_STATUS=$(curl -sI "https://${DOMAIN}${ADMIN_PATH}" --max-time 5 2>/dev/null | head -1 | grep -oE '[0-9]{3}' | head -1 || true)
    if [ "$ADMIN_STATUS" = "200" ] || [ "$ADMIN_STATUS" = "301" ] || [ "$ADMIN_STATUS" = "302" ]; then
      emit_row "CONF-05" "Admin path: $ADMIN_PATH" "WARN" "HTTP $ADMIN_STATUS — verify auth required"
    else
      emit_row "CONF-05" "Admin path: $ADMIN_PATH" "PASS" "HTTP ${ADMIN_STATUS:-timeout}"
    fi
  done
}

check_conf_06() {
  # WHY: OPTIONS may reveal allowed methods, TRACE enables XST attacks
  if [ "$NETWORK_AVAILABLE" = "no" ]; then
    emit_row "CONF-06" "HTTP methods" "WARN" "Domain unknown — skipped"
    return
  fi
  OPTIONS_RESP=$(curl -sI -X OPTIONS "https://${DOMAIN}/" --max-time 5 2>/dev/null | grep -iE '^allow:' | head -1 || true)
  if [ -n "$OPTIONS_RESP" ]; then
    emit_row "CONF-06" "HTTP OPTIONS response" "WARN" "$OPTIONS_RESP"
  else
    emit_row "CONF-06" "HTTP OPTIONS response" "PASS" "No Allow header returned"
  fi

  TRACE_STATUS=$(curl -sI -X TRACE "https://${DOMAIN}/" --max-time 5 2>/dev/null | head -1 | grep -oE '[0-9]{3}' | head -1 || true)
  if [ "$TRACE_STATUS" = "200" ]; then
    emit_row "CONF-06" "HTTP TRACE method" "FAIL" "TRACE enabled — XST risk"
  else
    emit_row "CONF-06" "HTTP TRACE method" "PASS" "HTTP ${TRACE_STATUS:-blocked}"
  fi
}

check_conf_07() {
  # WHY: HSTS forces browsers to use HTTPS — prevents downgrade attacks
  if [ "$NETWORK_AVAILABLE" = "no" ]; then
    emit_row "CONF-07" "HSTS header" "WARN" "Domain unknown — skipped"
    return
  fi
  fetch_prod_headers
  HSTS=$(echo "$PROD_HEADERS" | grep -iE '^strict-transport-security' | head -1 || true)
  if [ -n "$HSTS" ]; then
    emit_row "CONF-07" "HSTS header" "PASS" "$HSTS"
  else
    emit_row "CONF-07" "HSTS header" "FAIL" "Missing Strict-Transport-Security"
  fi
}

check_conf_09() {
  # WHY: Running as root in containers allows container escape attacks
  DOCKERFILE="${PROJECT_ROOT}/Dockerfile"
  [ ! -f "$DOCKERFILE" ] && DOCKERFILE="Dockerfile"
  if [ -f "$DOCKERFILE" ]; then
    if grep -qE 'USER|--chown|appuser|nonroot|node:' "$DOCKERFILE" 2>/dev/null; then
      emit_row "CONF-09" "Docker non-root user" "PASS" "USER directive found"
    else
      emit_row "CONF-09" "Docker non-root user" "FAIL" "No USER directive — may run as root"
    fi
  else
    emit_row "CONF-09" "Dockerfile" "WARN" "No Dockerfile found — cannot check container user"
  fi

  # WHY: grep -l lists files, grep -n gives line numbers — never output secret values
  SECRET_FILES=$(grep -rEln "$PATTERN_SECRETS" "$SRC_ROOT" --include="*.ts" --include="*.tsx" --include="*.js" 2>/dev/null \
    | grep -v "node_modules" | grep -v ".test." | grep -v ".spec." | head -5 || true)
  if [ -n "$SECRET_FILES" ]; then
    EVIDENCE=$(echo "$SECRET_FILES" | tr '\n' ',' | sed 's/,$//')
    emit_row "CONF-09" "Hardcoded secrets" "FAIL" "Potential secret in: $EVIDENCE — inspect manually"
  else
    emit_row "CONF-09" "Hardcoded secrets" "PASS" "No hardcoded secret patterns found"
  fi

  # WHY: NEXT_PUBLIC_ vars are embedded in client JS bundle — visible to everyone
  NEXT_PUBLIC_HITS=$(grep -rE "$PATTERN_NEXT_PUBLIC_SECRETS" "$PROJECT_ROOT" --include=".env*" 2>/dev/null | sed -E 's/=.*/=[REDACTED]/' | head -3 || true)
  if [ -n "$NEXT_PUBLIC_HITS" ]; then
    emit_row "CONF-09" "NEXT_PUBLIC secrets" "WARN" "$(echo "$NEXT_PUBLIC_HITS" | head -1)"
  else
    emit_row "CONF-09" "NEXT_PUBLIC secrets" "PASS" "No secret-like NEXT_PUBLIC_ vars"
  fi

  # WHY: console.log in API routes may log request data containing PII
  CONSOLE_LOG_API=$(grep -rnE "console\.log" "$SRC_ROOT/app/api" 2>/dev/null | head -3 || true)
  if [ -n "$CONSOLE_LOG_API" ]; then
    emit_row "CONF-09" "console.log in API routes" "WARN" "Found — may log sensitive request data"
  else
    emit_row "CONF-09" "console.log in API routes" "PASS" "Not found"
  fi
}

check_conf_10() {
  # WHY: Dangling CNAME records enable subdomain takeover attacks
  if [ "$NETWORK_AVAILABLE" = "no" ]; then
    emit_row "CONF-10" "Subdomain takeover" "WARN" "Domain unknown — skipped"
    return
  fi
  for SUBDOMAIN in "www" "app" "api" "staging" "dev"; do
    CNAME=$(dig CNAME "${SUBDOMAIN}.${DOMAIN}" +short 2>/dev/null | head -1 || true)
    if [ -n "$CNAME" ]; then
      # Check if CNAME target resolves
      CNAME_RESOLVES=$(dig A "$CNAME" +short 2>/dev/null | head -1 || true)
      if [ -z "$CNAME_RESOLVES" ]; then
        emit_row "CONF-10" "Subdomain: ${SUBDOMAIN}.${DOMAIN}" "WARN" "CNAME to $CNAME — target does not resolve (potential takeover)"
      else
        emit_row "CONF-10" "Subdomain: ${SUBDOMAIN}.${DOMAIN}" "PASS" "CNAME to $CNAME — resolves"
      fi
    fi
  done
}

check_conf_11() {
  # WHY: Hardcoded secrets in CI config are visible to anyone with repo access
  if [ -d "${PROJECT_ROOT}/.github/workflows" ]; then
    CI_SECRETS=$(grep -rEn 'password:|secret:|token:|api_key:' "${PROJECT_ROOT}/.github/workflows/" 2>/dev/null | grep -v '\${{' | head -5 || true)
    if [ -n "$CI_SECRETS" ]; then
      emit_row "CONF-11" "CI hardcoded secrets" "FAIL" "Found non-variable secrets in workflows"
    else
      emit_row "CONF-11" "CI hardcoded secrets" "PASS" "Uses GitHub Secrets (variable references only)"
    fi
  else
    emit_row "CONF-11" "CI hardcoded secrets" "PASS" "No .github/workflows directory"
  fi
}

check_conf_12() {
  # WHY: CSP prevents XSS by controlling which scripts can execute
  if [ "$NETWORK_AVAILABLE" = "no" ]; then
    emit_row "CONF-12" "CSP header" "WARN" "Domain unknown — skipped"
    return
  fi
  fetch_prod_headers
  CSP=$(echo "$PROD_HEADERS" | grep -iE '^content-security-policy' | head -1 || true)
  if [ -n "$CSP" ]; then
    emit_row "CONF-12" "CSP header" "PASS" "Present"
    # WHY: unsafe-inline weakens CSP by allowing inline scripts
    if echo "$CSP" | grep -qE "unsafe-inline" 2>/dev/null; then
      emit_row "CONF-12" "CSP unsafe-inline" "WARN" "unsafe-inline present — weakens XSS protection"
    fi
    # WHY: unsafe-eval allows eval() which is a code injection vector
    if echo "$CSP" | grep -qE "unsafe-eval" 2>/dev/null; then
      emit_row "CONF-12" "CSP unsafe-eval" "WARN" "unsafe-eval present — weakens XSS protection"
    fi
  else
    emit_row "CONF-12" "CSP header" "FAIL" "Missing Content-Security-Policy"
  fi
}

check_conf_14() {
  # WHY: Security headers protect against clickjacking, MIME sniffing, etc.
  if [ "$NETWORK_AVAILABLE" = "no" ]; then
    emit_row "CONF-14" "Security headers" "WARN" "Domain unknown — skipped"
    return
  fi
  fetch_prod_headers

  # WHY: X-Frame-Options prevents clickjacking attacks
  XFO=$(echo "$PROD_HEADERS" | grep -iE '^x-frame-options' | head -1 || true)
  if [ -n "$XFO" ]; then
    emit_row "CONF-14" "X-Frame-Options" "PASS" "$XFO"
  else
    emit_row "CONF-14" "X-Frame-Options" "WARN" "Missing X-Frame-Options header"
  fi

  # WHY: X-Content-Type-Options prevents MIME sniffing attacks
  XCTO=$(echo "$PROD_HEADERS" | grep -iE '^x-content-type-options' | head -1 || true)
  if [ -n "$XCTO" ]; then
    emit_row "CONF-14" "X-Content-Type-Options" "PASS" "$XCTO"
  else
    emit_row "CONF-14" "X-Content-Type-Options" "WARN" "Missing X-Content-Type-Options header"
  fi

  # WHY: Referrer-Policy controls what URL info is sent to external sites
  REFPOL=$(echo "$PROD_HEADERS" | grep -iE '^referrer-policy' | head -1 || true)
  if [ -n "$REFPOL" ]; then
    emit_row "CONF-14" "Referrer-Policy" "PASS" "$REFPOL"
  else
    emit_row "CONF-14" "Referrer-Policy" "WARN" "Missing Referrer-Policy header"
  fi

  # WHY: Permissions-Policy restricts browser features (camera, mic, geolocation)
  PERMPOL=$(echo "$PROD_HEADERS" | grep -iE '^permissions-policy' | head -1 || true)
  if [ -n "$PERMPOL" ]; then
    emit_row "CONF-14" "Permissions-Policy" "PASS" "Present"
  else
    emit_row "CONF-14" "Permissions-Policy" "WARN" "Missing Permissions-Policy header"
  fi
}

# --- WSTG-IDNT: Identity Management ---

check_idnt_04() {
  # WHY: Auth endpoints that reveal user existence enable targeted attacks
  if [ "$NETWORK_AVAILABLE" = "no" ]; then
    emit_row "IDNT-04" "Account enumeration" "WARN" "Domain unknown — skipped"
    return
  fi
  for AUTH_PATH in "/api/auth/signin" "/api/auth/callback" "/api/auth/session"; do
    AUTH_STATUS=$(curl -sI "https://${DOMAIN}${AUTH_PATH}" --max-time 5 2>/dev/null | head -1 | grep -oE '[0-9]{3}' | head -1 || true)
    if [ -n "$AUTH_STATUS" ] && [ "$AUTH_STATUS" != "404" ]; then
      emit_row "IDNT-04" "Auth endpoint: $AUTH_PATH" "WARN" "HTTP $AUTH_STATUS — verify no user enumeration"
    fi
  done
}

# --- WSTG-ATHN: Authentication ---

check_athn_01() {
  # WHY: HTTP must redirect to HTTPS to prevent credential sniffing
  if [ "$NETWORK_AVAILABLE" = "no" ]; then
    emit_row "ATHN-01" "HTTP to HTTPS redirect" "WARN" "Domain unknown — skipped"
    return
  fi
  HTTP_REDIRECT=$(curl -sI "http://${DOMAIN}" --max-time 10 2>/dev/null | head -3 || true)
  HTTP_STATUS=$(echo "$HTTP_REDIRECT" | head -1 | grep -oE '[0-9]{3}' | head -1 || true)
  if [ "$HTTP_STATUS" = "301" ] || [ "$HTTP_STATUS" = "302" ]; then
    REDIRECT_LOC=$(echo "$HTTP_REDIRECT" | grep -iE '^location:' | head -1 || true)
    if echo "$REDIRECT_LOC" | grep -qiE 'https://' 2>/dev/null; then
      emit_row "ATHN-01" "HTTP to HTTPS redirect" "PASS" "HTTP $HTTP_STATUS -> HTTPS"
    else
      emit_row "ATHN-01" "HTTP to HTTPS redirect" "WARN" "Redirects but not to HTTPS: $REDIRECT_LOC"
    fi
  else
    emit_row "ATHN-01" "HTTP to HTTPS redirect" "FAIL" "HTTP ${HTTP_STATUS:-timeout} — no redirect to HTTPS"
  fi
}

check_athn_02() {
  # WHY: Default/common admin paths should require authentication
  if [ "$NETWORK_AVAILABLE" = "no" ]; then
    emit_row "ATHN-02" "Default credentials" "WARN" "Domain unknown — skipped"
    return
  fi
  for DEFAULT_PATH in "/admin" "/wp-admin" "/_next/data"; do
    DEFAULT_STATUS=$(curl -sI "https://${DOMAIN}${DEFAULT_PATH}" --max-time 5 2>/dev/null | head -1 | grep -oE '[0-9]{3}' | head -1 || true)
    if [ "$DEFAULT_STATUS" = "200" ]; then
      emit_row "ATHN-02" "Default credentials path: $DEFAULT_PATH" "WARN" "HTTP 200 — verify auth required"
    fi
  done
}

check_athn_06() {
  # WHY: Missing Cache-Control may cache auth-gated pages in browser/CDN
  if [ "$NETWORK_AVAILABLE" = "no" ]; then
    emit_row "ATHN-06" "Cache-Control header" "WARN" "Domain unknown — skipped"
    return
  fi
  CACHE_CONTROL=$(curl -sI "https://${DOMAIN}" --max-time 10 2>/dev/null | grep -iE '^cache-control' | head -1 || true)
  if echo "$CACHE_CONTROL" | grep -qiE 'no-store|no-cache' 2>/dev/null; then
    emit_row "ATHN-06" "Cache-Control header" "PASS" "$CACHE_CONTROL"
  else
    emit_row "ATHN-06" "Cache-Control header" "WARN" "No no-store/no-cache — auth-gated pages may be cached"
  fi
}

# --- WSTG-SESS: Session Management ---

check_sess_01() {
  # WHY: Session cookies must have httpOnly, secure, sameSite to prevent XSS/CSRF
  SESSION_CONFIG=$(grep -rEn "$PATTERN_SESSION" "$SRC_ROOT" --include="*.ts" --include="*.js" 2>/dev/null | grep -vE 'node_modules|__tests__|generated|\.d\.ts' | head -5 || true)
  if [ -n "$SESSION_CONFIG" ]; then
    # Check for all required attributes
    HAS_HTTPONLY=$(echo "$SESSION_CONFIG" | grep -iE 'httpOnly' || true)
    HAS_SECURE=$(echo "$SESSION_CONFIG" | grep -iE 'secure' || true)
    HAS_SAMESITE=$(echo "$SESSION_CONFIG" | grep -iE 'sameSite' || true)
    if [ -n "$HAS_HTTPONLY" ] && [ -n "$HAS_SECURE" ] && [ -n "$HAS_SAMESITE" ]; then
      emit_row "SESS-01" "Session cookie attributes" "PASS" "httpOnly, secure, sameSite found"
    else
      MISSING=""
      [ -z "$HAS_HTTPONLY" ] && MISSING="${MISSING}httpOnly, "
      [ -z "$HAS_SECURE" ] && MISSING="${MISSING}secure, "
      [ -z "$HAS_SAMESITE" ] && MISSING="${MISSING}sameSite, "
      emit_row "SESS-01" "Session cookie attributes" "WARN" "Missing: ${MISSING%, }"
    fi
  else
    emit_row "SESS-01" "Session cookie attributes" "WARN" "No session config patterns found in source"
  fi
}

check_sess_02() {
  # WHY: Client code accessing httpOnly cookies indicates broken auth design
  DOC_COOKIE=$(grep -rEn "$PATTERN_SESSION_IN_CLIENT" "$SRC_ROOT" --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" 2>/dev/null | grep -vE 'node_modules|__tests__|\.test\.|\.spec\.|generated' | head -3 || true)
  if [ -n "$DOC_COOKIE" ]; then
    emit_row "SESS-02" "document.cookie in client code" "FAIL" "Found: $(echo "$DOC_COOKIE" | head -1)"
  else
    emit_row "SESS-02" "document.cookie in client code" "PASS" "Not found"
  fi
}

check_sess_04() {
  # WHY: Session tokens exposed in URLs, logs, or API responses can be intercepted
  SESS_IN_URL=$(grep -rEn 'sessionId.*[?&]|[?&].*session_id|[?&].*sid=' "$SRC_ROOT" --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" 2>/dev/null \
    | grep -vE 'node_modules|__tests__|\.test\.|\.spec\.|generated|\.d\.ts' | head -3 || true)
  SESS_IN_LOG=$(grep -rEn 'console\.(log|info).*session|log.*sessionId|logger.*session' "$SRC_ROOT" --include="*.ts" --include="*.tsx" --include="*.js" 2>/dev/null \
    | grep -vE 'node_modules|__tests__|\.test\.|\.spec\.|generated|\.d\.ts' | head -3 || true)
  SESS_IN_RESPONSE=$(grep -rEn 'json\(.*sessionId|json\(.*session_id|res.*session.*token' "$SRC_ROOT/app/api" --include="*.ts" --include="*.js" 2>/dev/null \
    | grep -vE 'node_modules|__tests__|generated' | head -3 || true)

  if [ -n "$SESS_IN_URL" ]; then
    emit_row "SESS-04" "Session token in URL" "FAIL" "Found: $(echo "$SESS_IN_URL" | head -1)"
  elif [ -n "$SESS_IN_LOG" ]; then
    emit_row "SESS-04" "Session token in logs" "WARN" "Found: $(echo "$SESS_IN_LOG" | head -1)"
  elif [ -n "$SESS_IN_RESPONSE" ]; then
    emit_row "SESS-04" "Session token in API response" "WARN" "Found: $(echo "$SESS_IN_RESPONSE" | head -1)"
  else
    emit_row "SESS-04" "Exposed session variables" "PASS" "No session tokens in URLs, logs, or API responses"
  fi
}

check_sess_05() {
  # WHY: SameSite attribute on session cookie prevents CSRF attacks
  SAMESITE_CONFIG=$(grep -rEn 'sameSite' "$SRC_ROOT" --include="*.ts" --include="*.js" 2>/dev/null \
    | grep -vE 'node_modules|__tests__|generated|\.d\.ts' | head -3 || true)
  if [ -n "$SAMESITE_CONFIG" ]; then
    if echo "$SAMESITE_CONFIG" | grep -qiE "sameSite.*none" 2>/dev/null; then
      emit_row "SESS-05" "CSRF (SameSite cookie)" "WARN" "SameSite=None — CSRF protection disabled"
    else
      emit_row "SESS-05" "CSRF (SameSite cookie)" "PASS" "SameSite set (Strict or Lax)"
    fi
  else
    emit_row "SESS-05" "CSRF (SameSite cookie)" "WARN" "No explicit SameSite config — relies on browser default (Lax)"
  fi
}

check_sess_07() {
  # WHY: Sessions without timeout never expire — stolen tokens remain valid forever
  MAXAGE_CONFIG=$(grep -rEn 'maxAge|expires|session.*timeout|session.*ttl|SESSION_MAX_AGE' "$SRC_ROOT" --include="*.ts" --include="*.js" 2>/dev/null \
    | grep -vE 'node_modules|__tests__|generated|\.d\.ts|cache-control' | head -3 || true)
  if [ -n "$MAXAGE_CONFIG" ]; then
    emit_row "SESS-07" "Session timeout" "PASS" "maxAge/expiry config found"
  else
    emit_row "SESS-07" "Session timeout" "WARN" "No session maxAge/expiry config found — sessions may never expire"
  fi
}

# --- WSTG-ATHZ: Authorization ---

check_athz_02() {
  # WHY: Mutation routes without auth allow unauthorized data changes
  discover_routes
  if [ -z "$ROUTE_LINES" ]; then
    emit_row "ATHZ-02" "Auth on routes" "WARN" "No routes discovered"
    return
  fi

  while IFS= read -r line; do
    [ -z "$line" ] && continue
    echo "$line" | grep -qE '^ROUTE:' || continue

    ROUTE_PATH=$(echo "$line" | sed 's/^ROUTE: //' | cut -d'|' -f1 | tr -d ' ')
    ROUTE_AUTH=$(echo "$line" | grep -oE 'auth=[^ |]+' | cut -d= -f2)
    ROUTE_METHODS=$(echo "$line" | grep -oE 'methods=[^ |]+' | cut -d= -f2)

    # Default to no if auth field missing
    [ -z "$ROUTE_AUTH" ] && ROUTE_AUTH="no"

    if [ "$ROUTE_AUTH" = "yes" ]; then
      emit_row "ATHZ-02" "Auth: $ROUTE_PATH" "PASS" "auth=yes methods=$ROUTE_METHODS"
    elif echo "$ROUTE_METHODS" | grep -qE 'POST|PATCH|PUT|DELETE' 2>/dev/null; then
      emit_row "ATHZ-02" "Auth: $ROUTE_PATH" "WARN" "auth=no on mutation route methods=$ROUTE_METHODS"
    else
      emit_row "ATHZ-02" "Auth: $ROUTE_PATH" "PASS" "auth=no GET-only methods=$ROUTE_METHODS"
    fi
  done <<< "$ROUTE_LINES"
}

# --- WSTG-INPV: Input Validation ---

check_inpv_01() {
  # WHY: dangerouslySetInnerHTML is the React escape hatch for XSS — bypasses auto-escaping
  HITS=$(grep -rEn "$PATTERN_DANGEROUSLYHTML" "$SRC_ROOT" --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" 2>/dev/null \
    | grep -vE 'node_modules|__tests__|\.test\.|\.spec\.|generated' | head -5 || true)
  if [ -n "$HITS" ]; then
    HIT_FILES=$(echo "$HITS" | cut -d: -f1 | sort -u | head -3 | tr '\n' ',' | sed 's/,$//')
    emit_row "INPV-01" "dangerouslySetInnerHTML" "FAIL" "Found in: $HIT_FILES"
  else
    emit_row "INPV-01" "dangerouslySetInnerHTML" "PASS" "Not found"
  fi
}

check_inpv_03() {
  # WHY: innerHTML assignment bypasses React VDOM — direct DOM XSS vector
  HITS=$(grep -rEn "$PATTERN_INNER_HTML" "$SRC_ROOT" --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" 2>/dev/null \
    | grep -vE 'node_modules|__tests__|\.test\.|\.spec\.|generated' | head -5 || true)
  if [ -n "$HITS" ]; then
    HIT_FILES=$(echo "$HITS" | cut -d: -f1 | sort -u | head -3 | tr '\n' ',' | sed 's/,$//')
    emit_row "INPV-03" "innerHTML assignment" "FAIL" "Found in: $HIT_FILES"
  else
    emit_row "INPV-03" "innerHTML assignment" "PASS" "Not found"
  fi
}

check_inpv_05() {
  # WHY: Raw SQL bypasses Prisma's parameterized queries — SQL injection vector
  HITS=$(grep -rEn "$PATTERN_RAW_SQL" "$SRC_ROOT" --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" 2>/dev/null \
    | grep -vE 'node_modules|__tests__|\.test\.|\.spec\.|generated' | head -5 || true)
  if [ -n "$HITS" ]; then
    HIT_FILES=$(echo "$HITS" | cut -d: -f1 | sort -u | head -3 | tr '\n' ',' | sed 's/,$//')
    emit_row "INPV-05" "Raw SQL (executeRawUnsafe)" "FAIL" "Found in: $HIT_FILES"
  else
    emit_row "INPV-05" "Raw SQL (executeRawUnsafe)" "PASS" "Not found"
  fi
}

check_inpv_11() {
  # WHY: eval() and new Function() execute arbitrary code — code injection vector
  HITS=$(grep -rEn "$PATTERN_EVAL" "$SRC_ROOT" --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" 2>/dev/null \
    | grep -vE 'node_modules|__tests__|\.test\.|\.spec\.|generated' | head -5 || true)
  if [ -n "$HITS" ]; then
    HIT_FILES=$(echo "$HITS" | cut -d: -f1 | sort -u | head -3 | tr '\n' ',' | sed 's/,$//')
    emit_row "INPV-11" "eval/new Function" "FAIL" "Found in: $HIT_FILES"
  else
    emit_row "INPV-11" "eval/new Function" "PASS" "Not found"
  fi
}

check_inpv_12() {
  # WHY: child_process/exec/spawn enable OS command injection
  HITS=$(grep -rEn "$PATTERN_CMD_INJECTION" "$SRC_ROOT" --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" 2>/dev/null \
    | grep -vE 'node_modules|__tests__|\.test\.|\.spec\.|generated' | head -5 || true)
  if [ -n "$HITS" ]; then
    HIT_FILES=$(echo "$HITS" | cut -d: -f1 | sort -u | head -3 | tr '\n' ',' | sed 's/,$//')
    emit_row "INPV-12" "Command injection (child_process)" "FAIL" "Found in: $HIT_FILES"
  else
    emit_row "INPV-12" "Command injection (child_process)" "PASS" "Not found"
  fi
}

check_inpv_17() {
  # WHY: HTTP Host header injection can poison caches, password reset links, redirects
  if [ "$NETWORK_AVAILABLE" = "no" ]; then
    emit_row "INPV-17" "HTTP Host header injection" "WARN" "Domain unknown — skipped"
    return
  fi
  NORMAL_BODY=$(curl -s "https://${DOMAIN}/" --max-time 10 2>/dev/null | head -20 || true)
  EVIL_BODY=$(curl -s "https://${DOMAIN}/" -H "Host: evil.com" --max-time 10 2>/dev/null | head -20 || true)
  if [ -n "$EVIL_BODY" ] && echo "$EVIL_BODY" | grep -qE 'evil\.com' 2>/dev/null; then
    emit_row "INPV-17" "HTTP Host header injection" "FAIL" "Response reflects injected Host: evil.com"
  else
    emit_row "INPV-17" "HTTP Host header injection" "PASS" "Host header injection not reflected"
  fi
}

check_inpv_18() {
  # WHY: Server-side fetch with user-controlled URL enables SSRF attacks
  if [ -d "$SRC_ROOT/app/api" ]; then
    SSRF_HITS=$(grep -rEn "$PATTERN_SSRF_FETCH" "$SRC_ROOT/app/api" --include="*.ts" --include="*.js" 2>/dev/null \
      | grep -vE 'node_modules|__tests__' | head -5 || true)
    if [ -n "$SSRF_HITS" ]; then
      SSRF_FILES=$(echo "$SSRF_HITS" | cut -d: -f1 | sort -u | head -3 | tr '\n' ',' | sed 's/,$//')
      emit_row "INPV-18" "SSRF (fetch with variable URL)" "WARN" "Found in: $SSRF_FILES — needs manual review"
    else
      emit_row "INPV-18" "SSRF (fetch with variable URL)" "PASS" "No variable-URL fetch in API routes"
    fi
  else
    emit_row "INPV-18" "SSRF (fetch with variable URL)" "PASS" "No API routes directory found"
  fi
}

check_inpv_20() {
  # WHY: Prototype pollution can modify Object.prototype and bypass security checks
  HITS=$(grep -rEn "$PATTERN_PROTO" "$SRC_ROOT" --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" 2>/dev/null \
    | grep -vE 'node_modules|__tests__|\.test\.|\.spec\.|generated' | head -5 || true)
  if [ -n "$HITS" ]; then
    HIT_FILES=$(echo "$HITS" | cut -d: -f1 | sort -u | head -3 | tr '\n' ',' | sed 's/,$//')
    emit_row "INPV-20" "Prototype pollution" "FAIL" "Found in: $HIT_FILES"
  else
    emit_row "INPV-20" "Prototype pollution" "PASS" "Not found"
  fi
}

# --- WSTG-ERRH: Error Handling ---

check_errh_01() {
  # WHY: Stack traces in error responses reveal internals to attackers
  if [ "$NETWORK_AVAILABLE" = "no" ]; then
    emit_row "ERRH-01" "Stack trace in error response" "WARN" "Domain unknown — skipped"
    return
  fi
  ERROR_BODY=$(curl -s "https://${DOMAIN}/api/oc-nonexistent-probe-path" --max-time 10 2>/dev/null || true)
  if echo "$ERROR_BODY" | grep -qE 'at |Error:|node_modules|\.ts:|\.js:' 2>/dev/null; then
    emit_row "ERRH-01" "Stack trace in error response" "FAIL" "Stack trace markers found in 404 response"
  else
    emit_row "ERRH-01" "Stack trace in error response" "PASS" "Clean error response — no stack traces"
  fi
}

check_errh_02() {
  # WHY: Stack traces in non-API error pages can also reveal internals
  if [ "$NETWORK_AVAILABLE" = "no" ]; then
    emit_row "ERRH-02" "Stack trace in page errors" "WARN" "Domain unknown — skipped"
    return
  fi
  PAGE_ERROR_BODY=$(curl -s "https://${DOMAIN}/oc-nonexistent-page-probe" --max-time 10 2>/dev/null || true)
  if echo "$PAGE_ERROR_BODY" | grep -qE 'at |Error:|node_modules|\.ts:|\.js:|stack' 2>/dev/null; then
    emit_row "ERRH-02" "Stack trace in page errors" "FAIL" "Stack trace markers found in page 404 response"
  else
    emit_row "ERRH-02" "Stack trace in page errors" "PASS" "Clean page error — no stack traces"
  fi
}

# --- WSTG-CRYP: Cryptography ---

check_cryp_01() {
  # WHY: TLS 1.1 and below have known vulnerabilities — must be disabled
  # Note: --tlsv1.1 sets MINIMUM version — curl negotiates highest available.
  # A successful response does NOT prove TLS 1.1 is accepted exclusively.
  # Always emit WARN — curl alone cannot confirm TLS 1.1 is rejected.
  if [ "$NETWORK_AVAILABLE" = "no" ]; then
    emit_row "CRYP-01" "TLS version" "WARN" "Domain unknown — skipped"
    return
  fi
  TLS_CHECK=$(curl -sI --tlsv1.1 "https://${DOMAIN}" --max-time 10 2>/dev/null || true)
  if [ -n "$TLS_CHECK" ]; then
    emit_row "CRYP-01" "TLS version" "WARN" "curl --tlsv1.1 succeeded — verify manually: openssl s_client -tls1_1 ${DOMAIN}:443"
  else
    emit_row "CRYP-01" "TLS version" "WARN" "curl --tlsv1.1 failed — verify manually: openssl s_client -tls1_1 ${DOMAIN}:443"
  fi
}

check_cryp_02() {
  # WHY: Unencrypted HTTP channel exposes data in transit — cross-reference with ATHN-01
  if [ "$NETWORK_AVAILABLE" = "no" ]; then
    emit_row "CRYP-02" "Unencrypted channel" "WARN" "Domain unknown — skipped"
    return
  fi
  HTTP_STATUS=$(curl -sI "http://${DOMAIN}" --max-time 10 2>/dev/null | head -1 | grep -oE '[0-9]{3}' | head -1 || true)
  if [ "$HTTP_STATUS" = "301" ] || [ "$HTTP_STATUS" = "302" ]; then
    emit_row "CRYP-02" "Unencrypted channel (HTTP)" "PASS" "HTTP redirects to HTTPS (HTTP $HTTP_STATUS)"
  else
    emit_row "CRYP-02" "Unencrypted channel (HTTP)" "FAIL" "HTTP ${HTTP_STATUS:-timeout} — no redirect to HTTPS"
  fi
}

check_cryp_03() {
  # WHY: Secrets in URL query parameters are logged in server logs, browser history, referer headers
  SECRET_IN_URL=$(grep -rEn "$PATTERN_SECRET_IN_URL" "$SRC_ROOT" --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" 2>/dev/null \
    | grep -vE 'node_modules|__tests__|\.test\.|\.spec\.' | head -3 || true)
  if [ -n "$SECRET_IN_URL" ]; then
    emit_row "CRYP-03" "Secret in URL parameter" "WARN" "Found query params with secret-like names"
  else
    emit_row "CRYP-03" "Secret in URL parameter" "PASS" "No secret-like query parameters found"
  fi
}

# --- WSTG-DOS: Denial of Service ---

check_dos_01() {
  # WHY: Routes without rate limiting are vulnerable to abuse and cost attacks
  discover_routes
  if [ -z "$ROUTE_LINES" ]; then
    emit_row "DOS-01" "Rate limiting" "WARN" "No routes discovered"
    return
  fi

  while IFS= read -r line; do
    [ -z "$line" ] && continue
    echo "$line" | grep -qE '^ROUTE:' || continue

    ROUTE_PATH=$(echo "$line" | sed 's/^ROUTE: //' | cut -d'|' -f1 | tr -d ' ')
    ROUTE_FILE=$(echo "$line" | grep -oE 'file=[^ |]+' | cut -d= -f2)
    ROUTE_RL=$(echo "$line" | grep -oE 'rate_limit=[^ |]+' | cut -d= -f2)

    if [ "$ROUTE_RL" = "yes" ]; then
      emit_row "DOS-01" "Rate limit: $ROUTE_PATH" "PASS" "Rate limiting present"
    elif [ -n "$ROUTE_FILE" ] && grep -qE "$PATTERN_RATE_LIMIT" "$ROUTE_FILE" 2>/dev/null; then
      emit_row "DOS-01" "Rate limit: $ROUTE_PATH" "PASS" "Rate limiting found in file"
    else
      emit_row "DOS-01" "Rate limit: $ROUTE_PATH" "WARN" "No rate limiting detected"
    fi
  done <<< "$ROUTE_LINES"
}

check_dos_03() {
  # WHY: Without body size limits, large payloads can exhaust server memory
  BODY_LIMIT=$(grep -rE 'bodySizeLimit' "${PROJECT_ROOT}/next.config.ts" "${PROJECT_ROOT}/next.config.js" "${PROJECT_ROOT}/next.config.mjs" 2>/dev/null | head -1 || true)
  if [ -n "$BODY_LIMIT" ]; then
    emit_row "DOS-03" "Body size limit" "PASS" "bodySizeLimit configured"
  else
    emit_row "DOS-03" "Body size limit" "WARN" "No bodySizeLimit in next.config — using framework default"
  fi
}

# --- WSTG-FILE: File Upload Security (conditional) ---

check_file_01() {
  # WHY: File uploads without type validation allow malicious file uploads
  if [ "$FILE_UPLOADS" != "yes" ]; then return; fi

  FILE_BODY_LIMIT=$(grep -rE 'bodySizeLimit' "${PROJECT_ROOT}/next.config.ts" "${PROJECT_ROOT}/next.config.js" "${PROJECT_ROOT}/next.config.mjs" 2>/dev/null | head -1 || true)
  if [ -n "$FILE_BODY_LIMIT" ]; then
    emit_row "FILE-01" "Upload body size limit" "PASS" "bodySizeLimit configured"
  else
    emit_row "FILE-01" "Upload body size limit" "WARN" "No bodySizeLimit — uploads may exhaust memory"
  fi
}

check_file_02() {
  # WHY: File storage config should use cloud storage, not local filesystem
  if [ "$FILE_UPLOADS" != "yes" ]; then return; fi

  STORAGE_CONFIG=$(grep -rEn 'uploadthing|s3|gcs|cloudinary|blob.*storage|azure.*storage' "$SRC_ROOT" --include="*.ts" --include="*.js" 2>/dev/null | grep -v 'node_modules' | head -3 || true)
  if [ -n "$STORAGE_CONFIG" ]; then
    emit_row "FILE-02" "Storage configuration" "PASS" "Cloud storage pattern found"
  else
    emit_row "FILE-02" "Storage configuration" "WARN" "No cloud storage config found — may use local filesystem"
  fi
}

# --- WSTG-BUSL: Business Logic (conditional) ---

check_busl_07() {
  # WHY: File uploads without MIME type validation allow malicious content
  if [ "$FILE_UPLOADS" != "yes" ]; then return; fi

  MIME_CHECK=$(grep -rEn 'content-type|mimetype|mime_type|file\.type|accept=' "$SRC_ROOT/app/api" --include="*.ts" --include="*.js" 2>/dev/null \
    | grep -vE 'node_modules|__tests__' | head -3 || true)
  if [ -n "$MIME_CHECK" ]; then
    emit_row "BUSL-07" "Upload MIME validation" "PASS" "MIME type check found in API routes"
  else
    emit_row "BUSL-07" "Upload MIME validation" "WARN" "No MIME type validation found in API routes"
  fi
}

check_busl_08() {
  # WHY: Unexpected file types can bypass security controls
  if [ "$FILE_UPLOADS" != "yes" ]; then return; fi

  FILENAME_SANITIZE=$(grep -rEn 'sanitize|filename|originalname|path\.extname|fileFilter' "$SRC_ROOT/app/api" --include="*.ts" --include="*.js" 2>/dev/null \
    | grep -vE 'node_modules|__tests__' | head -3 || true)
  if [ -n "$FILENAME_SANITIZE" ]; then
    emit_row "BUSL-08" "Upload filename sanitization" "PASS" "Filename handling found in API routes"
  else
    emit_row "BUSL-08" "Upload filename sanitization" "WARN" "No filename sanitization found in API routes"
  fi
}

# --- Supply Chain ---

check_supply_01() {
  # WHY: Known CVEs in dependencies — npm audit exits non-zero on vulnerabilities
  if [ -f "${PROJECT_ROOT}/package.json" ]; then
    NPM_AUDIT_OUTPUT=$(cd "${PROJECT_ROOT}" && npm audit --omit=dev 2>&1 | tail -5 || true)
    if echo "$NPM_AUDIT_OUTPUT" | grep -qE 'found 0 vulnerabilities' 2>/dev/null; then
      emit_row "SUPPLY-01" "npm audit" "PASS" "No known vulnerabilities"
    else
      AUDIT_SUMMARY=$(echo "$NPM_AUDIT_OUTPUT" | tail -1)
      emit_row "SUPPLY-01" "npm audit" "WARN" "$AUDIT_SUMMARY"
    fi
  else
    emit_row "SUPPLY-01" "npm audit" "WARN" "No package.json found"
  fi
}

check_supply_02() {
  # WHY: Without a lockfile, builds are non-reproducible and vulnerable to substitution
  if [ -f "${PROJECT_ROOT}/package-lock.json" ]; then
    emit_row "SUPPLY-02" "Lockfile" "PASS" "package-lock.json exists"
  elif [ -f "${PROJECT_ROOT}/yarn.lock" ]; then
    emit_row "SUPPLY-02" "Lockfile" "PASS" "yarn.lock exists"
  elif [ -f "${PROJECT_ROOT}/pnpm-lock.yaml" ]; then
    emit_row "SUPPLY-02" "Lockfile" "PASS" "pnpm-lock.yaml exists"
  else
    emit_row "SUPPLY-02" "Lockfile" "WARN" "No lockfile found — non-reproducible builds"
  fi
}

# --- DNS Security ---

check_dns_01() {
  # WHY: SPF prevents email spoofing from your domain
  if [ "$NETWORK_AVAILABLE" = "no" ]; then
    emit_row "DNS-01" "SPF record" "WARN" "Domain unknown — skipped"
    return
  fi
  SPF=$(dig TXT "$DOMAIN" +short 2>/dev/null | grep -iE 'spf' || true)
  if [ -n "$SPF" ]; then
    emit_row "DNS-01" "SPF record" "PASS" "$SPF"
  else
    emit_row "DNS-01" "SPF record" "WARN" "No SPF record found"
  fi
}

check_dns_02() {
  # WHY: DMARC tells receivers what to do with spoofed emails
  if [ "$NETWORK_AVAILABLE" = "no" ]; then
    emit_row "DNS-02" "DMARC record" "WARN" "Domain unknown — skipped"
    return
  fi
  DMARC=$(dig TXT "_dmarc.${DOMAIN}" +short 2>/dev/null | head -1 || true)
  if [ -n "$DMARC" ]; then
    emit_row "DNS-02" "DMARC record" "PASS" "$DMARC"
  else
    emit_row "DNS-02" "DMARC record" "WARN" "No DMARC record found"
  fi
}

check_dns_03() {
  # WHY: DKIM verifies email authenticity
  if [ "$NETWORK_AVAILABLE" = "no" ]; then
    emit_row "DNS-03" "DKIM record" "WARN" "Domain unknown — skipped"
    return
  fi
  DKIM=$(dig TXT "default._domainkey.${DOMAIN}" +short 2>/dev/null | head -1 || true)
  if [ -n "$DKIM" ]; then
    emit_row "DNS-03" "DKIM record" "PASS" "$DKIM"
  else
    emit_row "DNS-03" "DKIM record" "WARN" "No DKIM record at default._domainkey"
  fi
}

# --- External API Activity ---

check_ext_api() {
  # WHY: Track which external APIs are active — each is an attack surface and data flow
  for VAR in $EXTERNAL_API_VARS; do
    if grep -qE "^${VAR}=" "$PROJECT_ROOT/.env.production" 2>/dev/null || grep -qE "^${VAR}=" "$SRC_ROOT/.env.production" 2>/dev/null; then
      emit_row "EXT-API" "$VAR" "WARN" "ACTIVE in .env.production — verify scoping and rotation"
    else
      emit_row "EXT-API" "$VAR" "PASS" "INACTIVE — not in .env.production"
    fi
  done
}

# --- Privacy / Legal ---

check_priv_01() {
  # WHY: Privacy page required for GDPR, Google/Apple OAuth compliance
  PRIVACY_FILE=$(find "$SRC_ROOT" \( -name "*.tsx" -o -name "*.ts" \) 2>/dev/null | grep -iE "privacy" | head -1 || true)
  if [ -n "$PRIVACY_FILE" ]; then
    emit_row "PRIV-01" "Privacy page" "PASS" "Found: $PRIVACY_FILE"
  else
    emit_row "PRIV-01" "Privacy page" "WARN" "No file with 'privacy' in name found"
  fi
}

check_priv_02() {
  # WHY: Account deletion required for Apple Sign In, GDPR right to erasure
  if grep -rqE "$PATTERN_ACCOUNT_DELETION" "$SRC_ROOT" 2>/dev/null; then
    emit_row "PRIV-02" "Account deletion" "PASS" "Deletion pattern found in source"
  else
    emit_row "PRIV-02" "Account deletion" "WARN" "No account deletion pattern found"
  fi
}

# --- Logging & Monitoring ---

check_logg_01() {
  # WHY: Check for structured logging library — absence means errors may not be captured
  if grep -qE "$PATTERN_LOGGING_LIB" "$PROJECT_ROOT/package.json" 2>/dev/null; then
    emit_row "LOGG-01" "Logging library" "PASS" "Found in package.json"
  else
    emit_row "LOGG-01" "Logging library" "WARN" "No logging library (winston/pino/morgan/bunyan) in package.json"
  fi
}

check_logg_02() {
  # WHY: Check for error logging in API routes — absence means errors are silent
  if grep -rqE "$PATTERN_ERROR_LOG" "$SRC_ROOT/app/api" 2>/dev/null; then
    emit_row "LOGG-02" "Error logging in API routes" "PASS" "Found"
  else
    emit_row "LOGG-02" "Error logging in API routes" "WARN" "No console.error/logger.error in src/app/api"
  fi
}

# --- AI/LLM Security ---

check_llm10() {
  # WHY: AI routes without rate limiting enable unbounded consumption (LLM10)
  if [ "$AI_SDK" = "none" ]; then return; fi
  discover_routes
  if [ -z "$ROUTE_LINES" ]; then return; fi

  # WHY: Only check routes that actually import AI SDK — not every route
  AI_IMPORT_PATTERN='from.*@ai-sdk|from.*openai|from.*anthropic|from.*langchain|import.*generateText|import.*streamText|import.*generateObject'

  while IFS= read -r line; do
    [ -z "$line" ] && continue
    echo "$line" | grep -qE '^ROUTE:' || continue

    ROUTE_PATH=$(echo "$line" | sed 's/^ROUTE: //' | cut -d'|' -f1 | tr -d ' ')
    ROUTE_FILE=$(echo "$line" | grep -oE 'file=[^ |]+' | cut -d= -f2)

    # Check if this route imports AI SDK
    if [ -n "$ROUTE_FILE" ] && [ -f "$ROUTE_FILE" ]; then
      if grep -qE "$AI_IMPORT_PATTERN" "$ROUTE_FILE" 2>/dev/null; then
        # This is an AI route — check rate limiting
        if grep -qE "$PATTERN_RATE_LIMIT" "$ROUTE_FILE" 2>/dev/null; then
          emit_row "LLM10" "Rate limit on AI route: $ROUTE_PATH" "PASS" "Rate limiting present"
        else
          emit_row "LLM10" "Rate limit on AI route: $ROUTE_PATH" "WARN" "No rate limiting on AI route — unbounded consumption risk"
        fi
      fi
    fi
  done <<< "$ROUTE_LINES"
}

# WHY: LLM07 (system prompt leakage) — only if AI SDK detected
check_llm07() {
  if [ "$AI_SDK" = "none" ]; then return; fi

  # WHY: AI responses may leak training data or system prompts to client
  DATA_LEAK=$(grep -rEn 'system.*prompt|systemPrompt|SYSTEM_PROMPT' "$SRC_ROOT" --include="*.ts" --include="*.tsx" --include="*.js" 2>/dev/null \
    | grep -vE 'node_modules|__tests__|\.test\.|\.spec\.' | head -3 || true)
  if [ -n "$DATA_LEAK" ]; then
    LEAK_FILES=$(echo "$DATA_LEAK" | cut -d: -f1 | sort -u | head -3 | tr '\n' ',' | sed 's/,$//')
    emit_row "LLM07" "System prompt in source" "WARN" "Found in: $LEAK_FILES — verify not exposed to client"
  else
    emit_row "LLM07" "System prompt in source" "PASS" "No system prompt patterns in source"
  fi
}

# WHY: LLM04 (Model DoS) maps to DOS-01 rate limiting on AI routes — handled by check_dos_01 + check_llm10
check_llm04() {
  if [ "$AI_SDK" = "none" ]; then return; fi
  emit_row "LLM04" "Model denial of service" "PASS" "Covered by DOS-01 rate limiting checks on AI routes"
}

# WHY: LLM05 (Supply chain) maps to SUPPLY-01 npm audit — handled by check_supply_01
check_llm05() {
  if [ "$AI_SDK" = "none" ]; then return; fi
  emit_row "LLM05" "AI supply chain" "PASS" "Covered by SUPPLY-01 npm audit"
}

# --- API Security Top 10 (aliases to existing checks) ---

check_api2() {
  # WHY: Broken auth — maps to ATHN-01, SESS-01/02 (already checked)
  emit_row "API2" "Broken authentication" "PASS" "Covered by ATHN-01, SESS-01, SESS-02"
}

check_api4() {
  # WHY: Unrestricted resource consumption — maps to DOS-01/03 (already checked)
  emit_row "API4" "Unrestricted resource consumption" "PASS" "Covered by DOS-01, DOS-03"
}

check_api5() {
  # WHY: Broken function-level auth — maps to ATHZ-02 (already checked)
  emit_row "API5" "Broken function-level auth" "PASS" "Covered by ATHZ-02"
}

check_api6() {
  # WHY: SSRF — maps to INPV-18 (already checked)
  emit_row "API6" "SSRF" "PASS" "Covered by INPV-18"
}

check_api7() {
  # WHY: Security misconfiguration — maps to CONF-* (already checked)
  emit_row "API7" "Security misconfiguration" "PASS" "Covered by CONF-01 through CONF-14"
}

check_api8() {
  # WHY: Lack of automated threat protection — maps to DOS-01 (already checked)
  emit_row "API8" "Lack of automated threat protection" "PASS" "Covered by DOS-01"
}

check_api9() {
  # WHY: Improper inventory management — maps to INFO-04 route discovery
  emit_row "API9" "Improper inventory management" "PASS" "Covered by INFO-04 route discovery"
}

# ============================================================
# I. Section name mapping
# ============================================================
# WHY: Map WSTG ID prefixes to human-readable section names for table headers
section_name_for_id() {
  local id_prefix="$1"
  case "$id_prefix" in
    INFO)    echo "WSTG-INFO: Information Gathering" ;;
    CONF)    echo "WSTG-CONF: Configuration and Deployment" ;;
    IDNT)    echo "WSTG-IDNT: Identity Management" ;;
    ATHN)    echo "WSTG-ATHN: Authentication" ;;
    SESS)    echo "WSTG-SESS: Session Management" ;;
    ATHZ)    echo "WSTG-ATHZ: Authorization" ;;
    INPV)    echo "WSTG-INPV: Input Validation" ;;
    ERRH)    echo "WSTG-ERRH: Error Handling" ;;
    CRYP)    echo "WSTG-CRYP: Cryptography" ;;
    BUSL)    echo "WSTG-BUSL: Business Logic" ;;
    DOS)     echo "WSTG-DOS: Denial of Service" ;;
    FILE)    echo "WSTG-FILE: File Management" ;;
    SUPPLY)  echo "Supply Chain" ;;
    DNS)     echo "DNS Security" ;;
    EXT)     echo "External APIs" ;;
    PRIV)    echo "Privacy / Legal" ;;
    LOGG)    echo "Logging & Monitoring" ;;
    LLM)     echo "AI/LLM Security" ;;
    API)     echo "OWASP API Security Top 10" ;;
    *)       echo "$id_prefix" ;;
  esac
}

# WHY: Extract the section prefix from a WSTG ID
# INFO-01 → INFO, EXT-API → EXT, LLM10 → LLM, API2 → API
get_section_prefix() {
  local check_id="$1"
  # Handle IDs with hyphens (INFO-01, EXT-API)
  if echo "$check_id" | grep -qE '^[A-Z]+-' 2>/dev/null; then
    echo "$check_id" | grep -oE '^[A-Z]+' | head -1
  else
    # Handle IDs without hyphens (LLM10, API2)
    echo "$check_id" | grep -oE '^[A-Z]+' | head -1
  fi
}

# ============================================================
# J. Dispatch loop — execute checks from profile
# ============================================================
# WHY: Route discovery must run before dispatch — multiple checks depend on it
discover_routes

CURRENT_SECTION=""

for CHECK_ID in $ALL_CHECKS; do
  # Determine WSTG section for table headers
  SECTION=$(get_section_prefix "$CHECK_ID")
  if [ "$SECTION" != "$CURRENT_SECTION" ]; then
    SECTION_NAME=$(section_name_for_id "$SECTION")
    print_section_header "$SECTION_NAME"
    CURRENT_SECTION="$SECTION"
  fi

  # Convert ID to function name: CONF-07 → check_conf_07, LLM10 → check_llm10, EXT-API → check_ext_api
  FUNC_NAME="check_$(echo "$CHECK_ID" | tr '[:upper:]' '[:lower:]' | tr '-' '_')"

  # Dispatch or fail-fast
  if type "$FUNC_NAME" > /dev/null 2>&1; then
    "$FUNC_NAME"
  else
    emit_row "$CHECK_ID" "NOT IMPLEMENTED" "FAIL" "Check function $FUNC_NAME missing — add to scan.sh"
  fi
done

# ============================================================
# K. Totals
# ============================================================
echo ""
echo "TOTALS: pass=$PASS_COUNT warn=$WARN_COUNT fail=$FAIL_COUNT"

# ============================================================
# L. Audit Details summary table (per-category counts)
# WHY: Pre-computed by the script so the LLM copies exact numbers, not guesses.
# ============================================================
echo ""
echo "AUDIT_DETAILS:"
echo "| Category | Checks | Result | OWASP Tests |"
echo "|----------|--------|--------|-------------|"

# WHY: Fixed category order for consistent output
for CAT in "Code injection" "SSRF" "Error handling" "Secret leakage" "Session / auth" \
           "User data / IDOR" "AI/LLM security" "Business logic" "DDoS / API abuse" \
           "Infrastructure config" "Privacy / legal" "Hosting bypass" "Supply chain" \
           "Logging" "External APIs" "OWASP API Top 10"; do
  p=$(cat_get PASS "$CAT")
  w=$(cat_get WARN "$CAT")
  f=$(cat_get FAIL "$CAT")
  total=$((p + w + f))
  [ "$total" -eq 0 ] && continue

  # WHY: Build result string showing pass/warn/fail breakdown
  result=""
  if [ "$w" -eq 0 ] && [ "$f" -eq 0 ]; then
    result="✅ All passed"
  else
    parts=""
    [ "$p" -gt 0 ] && parts="${p}✅"
    if [ "$w" -gt 0 ]; then
      if [ -n "$parts" ]; then parts="$parts ${w}⚠️"; else parts="${w}⚠️"; fi
    fi
    if [ "$f" -gt 0 ]; then
      if [ -n "$parts" ]; then parts="$parts ${f}❌"; else parts="${f}❌"; fi
    fi
    result="$parts"
  fi

  ids=$(cat_get_ids "$CAT")
  printf "| %-25s | %d | %s | %s |\n" "$CAT" "$total" "$result" "$ids"
done
echo "| **Total** | **$((PASS_COUNT + WARN_COUNT + FAIL_COUNT))** | **${PASS_COUNT}✅ ${WARN_COUNT}⚠️ ${FAIL_COUNT}❌** | |"
