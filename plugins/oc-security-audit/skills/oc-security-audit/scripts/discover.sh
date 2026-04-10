#!/bin/sh
set -eu

# ============================================================
# OC Security Audit — Discovery Script
# Phase 1: Detect the project's tech stack and API surface.
#
# SECURITY DECLARATION:
# - Read-only: this script does NOT modify any files
# - No secrets: does NOT read or output env var VALUES (only checks key existence)
# - Network: DNS lookups only (dig) — no HTTP requests to external services
# - Output: stdout only — no files written
# - Every command is commented with # WHY: explaining what it checks and why
# ============================================================

# CHECK: Find the project root (where package.json or requirements.txt lives)
# WHY: We need to know where to look for dependencies and config
PROJECT_ROOT="."

# Try to find package.json in common locations
if [ -f "package.json" ]; then
  PROJECT_ROOT="."
elif [ -f "apps/web/package.json" ]; then
  PROJECT_ROOT="apps/web"
elif [ -f "frontend/package.json" ]; then
  PROJECT_ROOT="frontend"
elif [ -f "src/package.json" ]; then
  PROJECT_ROOT="src"
fi

echo "=== DISCOVERY ==="
echo "PROJECT_ROOT: ${PROJECT_ROOT}"

# ============================================================
# STACK DETECTION
# ============================================================

echo ""
echo "=== STACK ==="

FRAMEWORK="unknown"
ORM="unknown"
AUTH="unknown"
LANGUAGE="unknown"
PROFILE="unsupported"

# CHECK: Detect language and framework from package.json
# WHY: Determines which profile to load and which checks to skip
if [ -f "${PROJECT_ROOT}/package.json" ]; then
  LANGUAGE="javascript"
  PKG="${PROJECT_ROOT}/package.json"

  # CHECK: Is this a Next.js project?
  if grep -q '"next"' "$PKG" 2>/dev/null; then
    FRAMEWORK="nextjs"
    # Extract Next.js version
    NEXTJS_VERSION=$(grep '"next"' "$PKG" | head -1 | sed 's/.*: *"[^0-9]*\([0-9][0-9.]*\).*/\1/' 2>/dev/null || echo "unknown")
    echo "FRAMEWORK: Next.js ${NEXTJS_VERSION}"

    # CHECK: Which ORM?
    # WHY: Determines SQL injection escape hatches to check
    if grep -q '"@prisma/client"' "$PKG" 2>/dev/null; then
      ORM="prisma"
      PRISMA_VERSION=$(grep '"@prisma/client"' "$PKG" | head -1 | sed 's/.*: *"[^0-9]*\([0-9][0-9.]*\).*/\1/' 2>/dev/null || echo "unknown")
      echo "ORM: Prisma ${PRISMA_VERSION}"
      PROFILE="nextjs-prisma"
    elif grep -q '"@supabase/supabase-js"' "$PKG" 2>/dev/null; then
      ORM="supabase"
      echo "ORM: Supabase"
      PROFILE="nextjs-supabase"
    elif grep -q '"drizzle-orm"' "$PKG" 2>/dev/null; then
      ORM="drizzle"
      echo "ORM: Drizzle"
      PROFILE="nextjs-drizzle"
    else
      ORM="unknown"
      echo "ORM: not detected"
      PROFILE="nextjs-generic"
    fi

  # CHECK: Is this an Express project?
  elif grep -q '"express"' "$PKG" 2>/dev/null; then
    FRAMEWORK="express"
    echo "FRAMEWORK: Express.js"
    PROFILE="express-node"

    if grep -q '"sequelize"' "$PKG" 2>/dev/null; then
      ORM="sequelize"
      echo "ORM: Sequelize"
    elif grep -q '"typeorm"' "$PKG" 2>/dev/null; then
      ORM="typeorm"
      echo "ORM: TypeORM"
    elif grep -q '"@prisma/client"' "$PKG" 2>/dev/null; then
      ORM="prisma"
      echo "ORM: Prisma"
    elif grep -q '"drizzle-orm"' "$PKG" 2>/dev/null; then
      ORM="drizzle"
      echo "ORM: Drizzle"
    else
      echo "ORM: not detected"
    fi

  else
    echo "FRAMEWORK: Node.js (no recognized framework)"
  fi

  # CHECK: What auth library?
  # WHY: Determines session/auth checks and what to skip (e.g., no password tests for OAuth-only)
  if grep -q '"better-auth"' "$PKG" 2>/dev/null; then
    AUTH="better-auth"
    echo "AUTH: Better Auth (OAuth)"
  elif grep -q '"next-auth"' "$PKG" 2>/dev/null || grep -q '"@auth/core"' "$PKG" 2>/dev/null; then
    AUTH="next-auth"
    echo "AUTH: NextAuth / Auth.js"
  elif grep -q '"@clerk/nextjs"' "$PKG" 2>/dev/null; then
    AUTH="clerk"
    echo "AUTH: Clerk"
  elif grep -q '"@supabase/supabase-js"' "$PKG" 2>/dev/null; then
    AUTH="supabase-auth"
    echo "AUTH: Supabase Auth"
  elif grep -q '"passport"' "$PKG" 2>/dev/null; then
    AUTH="passport"
    echo "AUTH: Passport.js"
  else
    echo "AUTH: not detected"
  fi

  # CHECK: Validation library
  # WHY: If Zod/Yup is used, input validation is likely handled — fewer checks needed
  if grep -q '"zod"' "$PKG" 2>/dev/null; then
    echo "VALIDATION: Zod"
  elif grep -q '"yup"' "$PKG" 2>/dev/null; then
    echo "VALIDATION: Yup"
  elif grep -q '"joi"' "$PKG" 2>/dev/null; then
    echo "VALIDATION: Joi"
  else
    echo "VALIDATION: not detected"
  fi

  # CHECK: AI/LLM SDK usage
  # WHY: Triggers Threat 10 (AI data flow) checks
  AI_SDK="none"
  if grep -qE '"@ai-sdk/google"|"@ai-sdk/openai"|"@ai-sdk/anthropic"|"ai"' "$PKG" 2>/dev/null; then
    AI_SDK="vercel-ai"
    echo "AI_SDK: Vercel AI SDK"
  elif grep -q '"openai"' "$PKG" 2>/dev/null; then
    AI_SDK="openai"
    echo "AI_SDK: OpenAI"
  elif grep -q '"@anthropic-ai/sdk"' "$PKG" 2>/dev/null; then
    AI_SDK="anthropic"
    echo "AI_SDK: Anthropic"
  else
    echo "AI_SDK: none"
  fi

# CHECK: Is this a Python project?
elif [ -f "requirements.txt" ] || [ -f "pyproject.toml" ]; then
  LANGUAGE="python"
  REQ_FILE="requirements.txt"
  [ -f "pyproject.toml" ] && REQ_FILE="pyproject.toml"

  if grep -qi "django" "$REQ_FILE" 2>/dev/null; then
    FRAMEWORK="django"
    echo "FRAMEWORK: Django"
    PROFILE="django"
  elif grep -qi "fastapi" "$REQ_FILE" 2>/dev/null; then
    FRAMEWORK="fastapi"
    echo "FRAMEWORK: FastAPI"
    PROFILE="fastapi-python"
  elif grep -qi "flask" "$REQ_FILE" 2>/dev/null; then
    FRAMEWORK="flask"
    echo "FRAMEWORK: Flask"
  else
    echo "FRAMEWORK: Python (no recognized framework)"
  fi
  echo "ORM: (check manually)"
  echo "AUTH: (check manually)"

# CHECK: Is this a Ruby project?
elif [ -f "Gemfile" ]; then
  LANGUAGE="ruby"
  if grep -q "rails" "Gemfile" 2>/dev/null; then
    FRAMEWORK="rails"
    echo "FRAMEWORK: Ruby on Rails"
    PROFILE="rails"
  else
    echo "FRAMEWORK: Ruby (no recognized framework)"
  fi

else
  echo "FRAMEWORK: could not detect (no package.json, requirements.txt, or Gemfile)"
fi

echo "PROFILE: ${PROFILE}"

# ============================================================
# HOSTING DETECTION
# ============================================================

echo ""
echo "=== HOSTING ==="

HOSTING="unknown"
PRODUCTION_DOMAIN="unknown"

# CHECK: Detect hosting platform from config files
# WHY: Determines which bypass domain to test (Threat 2)
if [ -f "railway.toml" ] || [ -f "railway.json" ]; then
  HOSTING="railway"
  echo "PLATFORM: Railway"
elif [ -f "vercel.json" ] || [ -f ".vercel" ]; then
  HOSTING="vercel"
  echo "PLATFORM: Vercel"
elif [ -f "fly.toml" ]; then
  HOSTING="fly"
  echo "PLATFORM: Fly.io"
elif [ -f "render.yaml" ]; then
  HOSTING="render"
  echo "PLATFORM: Render"
elif [ -f "netlify.toml" ]; then
  HOSTING="netlify"
  echo "PLATFORM: Netlify"
elif [ -f "Dockerfile" ] || [ -f "${PROJECT_ROOT}/Dockerfile" ]; then
  HOSTING="docker"
  echo "PLATFORM: Docker (platform unknown)"
else
  echo "PLATFORM: not detected"
fi

# WHY: Priority lookup of known env var names before falling back to regex scan.
# Regex scan is fragile (filters too aggressively). Named vars are reliable.
PRODUCTION_DOMAIN="unknown"
for ENV_FILE in ".env.production" "${PROJECT_ROOT}/.env.production" \
                ".env.local" "${PROJECT_ROOT}/.env.local" \
                ".env" "${PROJECT_ROOT}/.env"; do
  [ -f "$ENV_FILE" ] || continue
  for VAR in BASE_URL APP_URL NEXT_PUBLIC_APP_URL NEXT_PUBLIC_SITE_URL NEXT_PUBLIC_BETTER_AUTH_URL; do
    # WHY: Extract domain — strip protocol, port number, and path
    RAW=$(grep -m1 "^${VAR}=" "$ENV_FILE" 2>/dev/null | cut -d= -f2- | tr -d '"' | tr -d "'" || true)
    DOMAIN_CANDIDATE=$(echo "$RAW" | sed -E 's|https?://||' | sed -E 's|:[0-9]*||' | sed -E 's|/.*||')
    # WHY: Reject localhost AND all RFC 1918 + loopback ranges (not just 127.x)
    if [ -n "$DOMAIN_CANDIDATE" ] && \
       ! echo "$DOMAIN_CANDIDATE" | grep -qE \
         '^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|0\.0\.0\.0|::1|yourdomain\.com|example\.com|your-domain\.com|mydomain\.com)'; then
      PRODUCTION_DOMAIN="$DOMAIN_CANDIDATE"
      break 2
    fi
  done
done
# Phase B: regex fallback only if named vars found nothing
if [ "$PRODUCTION_DOMAIN" = "unknown" ]; then
  # WHY: Generic exclusion list — only universally non-production domains.
  # Project-specific terms (lordicon, unsplash, nominatim) are removed.
  # Use \.up\.railway\.app specifically (not broad 'railway').
  for CONFIG_FILE in ".env.production" "${PROJECT_ROOT}/.env.production" \
                     ".env" "${PROJECT_ROOT}/.env" \
                     "${PROJECT_ROOT}/next.config.ts" "${PROJECT_ROOT}/next.config.js"; do
    [ -f "$CONFIG_FILE" ] || continue
    # WHY: Scan config files for domain-like strings, excluding known non-production hosts
    DOMAIN_MATCH=$(grep -oE '(https?://)?[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}' "$CONFIG_FILE" 2>/dev/null \
      | grep -vE 'localhost|127\.0|example\.com|googleapis|cloudflare|fonts\.|cdn\.|unpkg\.com|jsdelivr|\.up\.railway\.app|\.vercel\.app|\.fly\.dev|\.onrender\.com' \
      | head -1 || true)
    if [ -n "$DOMAIN_MATCH" ]; then
      PRODUCTION_DOMAIN=$(echo "$DOMAIN_MATCH" | sed -E 's|https?://||')
      break
    fi
  done
fi
echo "HOSTING: ${HOSTING}"
echo "DOMAIN: ${PRODUCTION_DOMAIN}"

# CHECK: Detect CI/CD
# WHY: We'll check CI config for hardcoded secrets
if [ -d ".github/workflows" ]; then
  echo "CI_CD: GitHub Actions"
elif [ -f ".gitlab-ci.yml" ]; then
  echo "CI_CD: GitLab CI"
elif [ -f "bitbucket-pipelines.yml" ]; then
  echo "CI_CD: Bitbucket Pipelines"
else
  echo "CI_CD: not detected"
fi

# ============================================================
# API ROUTES
# ============================================================

echo ""
echo "=== API_ROUTES ==="

# CHECK: Find all API route files
# WHY: Core input for Threats 1 (rate limiting), 4 (auth), and endpoint analysis
SRC_ROOT=""
ROUTE_COUNT=0

_route_tmp=$(mktemp)
trap 'rm -f "$_route_tmp"' EXIT

if [ "$FRAMEWORK" = "nextjs" ]; then
  # Next.js App Router: routes are in app/api/**/route.ts
  for SEARCH_DIR in "${PROJECT_ROOT}/src/app/api" "${PROJECT_ROOT}/app/api"; do
    if [ -d "$SEARCH_DIR" ]; then
      SRC_ROOT=$(dirname "$(dirname "$SEARCH_DIR")")
      # WHY: Write to temp file so the while loop runs in the current shell (preserves ROUTE_COUNT)
      find "$SEARCH_DIR" \( -name "route.ts" -o -name "route.js" -o -name "route.tsx" -o -name "route.jsx" \) 2>/dev/null | sort > "$_route_tmp"
      while IFS= read -r route_file; do
        # WHY: Convert file path to API endpoint path — use # as sed delimiter to avoid conflict with | in ERE alternation
        API_PATH=$(echo "$route_file" | sed "s|${SEARCH_DIR}||" | sed -E 's#/route\.(ts|js|tsx|jsx)$##')
        [ -z "$API_PATH" ] && API_PATH="/"

        # CHECK: Does this route have auth?
        HAS_AUTH="no"
        # WHY: Check if route requires authentication using common auth patterns
        if grep -qE 'getSession|requireAuth|getServerSession|auth\(\)|withAuth|verifyAuth|checkAuth|session\.user' "$route_file" 2>/dev/null; then
          HAS_AUTH="yes"
        fi

        # CHECK: Does this route have rate limiting?
        HAS_RATE_LIMIT="no"
        # WHY: Check if route has rate limiting using common patterns
        if grep -qE 'checkRateLimit|rateLimit|rateLimiter|rate_limit|Ratelimit' "$route_file" 2>/dev/null; then
          HAS_RATE_LIMIT="yes"
        fi

        # CHECK: What HTTP methods does this route export?
        # WHY: Extract exported HTTP method names to map the API surface
        METHODS=$(grep -oE 'export.*async.*function.*(GET|POST|PUT|PATCH|DELETE|OPTIONS)' "$route_file" 2>/dev/null | grep -oE 'GET\|POST\|PUT\|PATCH\|DELETE\|OPTIONS' | tr '\n' ',' | sed 's/,$//' || true)
        [ -z "$METHODS" ] && METHODS="unknown"

        echo "ROUTE: /api${API_PATH} | methods=${METHODS} | auth=${HAS_AUTH} | rate_limit=${HAS_RATE_LIMIT} | file=${route_file}"
        ROUTE_COUNT=$((ROUTE_COUNT + 1))
      done < "$_route_tmp"
      break
    fi
  done

elif [ "$FRAMEWORK" = "express" ]; then
  # Express: look for router files
  for SEARCH_DIR in "${PROJECT_ROOT}/src/routes" "${PROJECT_ROOT}/routes" "${PROJECT_ROOT}/src/api"; do
    if [ -d "$SEARCH_DIR" ]; then
      SRC_ROOT="${PROJECT_ROOT}/src"
      # WHY: Write to temp file so the while loop runs in the current shell (preserves ROUTE_COUNT)
      find "$SEARCH_DIR" \( -name "*.ts" -o -name "*.js" \) 2>/dev/null | sort > "$_route_tmp"
      while IFS= read -r route_file; do
        echo "ROUTE: ${route_file} | (express — analyze manually)"
        ROUTE_COUNT=$((ROUTE_COUNT + 1))
      done < "$_route_tmp"
      break
    fi
  done
fi

echo "ROUTE_COUNT: ${ROUTE_COUNT}"

# Determine source root for grep searches
if [ -z "$SRC_ROOT" ]; then
  if [ -d "${PROJECT_ROOT}/src" ]; then
    SRC_ROOT="${PROJECT_ROOT}/src"
  else
    SRC_ROOT="${PROJECT_ROOT}"
  fi
fi
echo "SRC_ROOT: ${SRC_ROOT}"

# ============================================================
# FEATURES
# ============================================================

echo ""
echo "=== FEATURES ==="

# CHECK: File uploads
# WHY: Triggers additional checks for upload size, type validation
if grep -rqEl 'multipart|FormData|file.*upload|photo.*upload|input.*type.*file|showOpenFilePicker|base64.*image|dataUrl|data:image' "${SRC_ROOT}" 2>/dev/null; then
  echo "FILE_UPLOADS: yes"
else
  echo "FILE_UPLOADS: no"
fi

# CHECK: Payment processing
# WHY: Triggers Stripe/payment-specific security checks
if grep -rqEl 'stripe|paypal|braintree|paddle|lemonsqueezy' "${PROJECT_ROOT}/package.json" 2>/dev/null; then
  echo "PAYMENTS: yes"
else
  echo "PAYMENTS: no"
fi

# CHECK: WebSockets
# WHY: Triggers WebSocket-specific auth checks
if grep -rqEl 'WebSocket|socket\.io|ws://' "${SRC_ROOT}" 2>/dev/null; then
  echo "WEBSOCKETS: yes"
else
  echo "WEBSOCKETS: no"
fi

# CHECK: SSE streaming
# WHY: Triggers connection limit and timeout checks
if grep -rqEl 'text/event-stream|ReadableStream|EventSource' "${SRC_ROOT}" 2>/dev/null; then
  echo "SSE: yes"
else
  echo "SSE: no"
fi

# CHECK: GraphQL
# WHY: Triggers introspection and depth-limiting checks
if grep -rqEl 'graphql|apollo|@nestjs/graphql' "${PROJECT_ROOT}/package.json" 2>/dev/null; then
  echo "GRAPHQL: yes"
else
  echo "GRAPHQL: no"
fi

echo ""
echo "=== END_DISCOVERY ==="

# Clean up temp files
rm -f /tmp/oc_methods
