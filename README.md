# OC Security Audit -- OWASP-grounded pre-launch security audit for web apps

*Dedicated to [Ohad Cohen](https://www.timesofisrael.com/sgt-first-class-ohad-cohen-20-elite-fighter-who-loved-and-was-loved/), a brave Israeli soldier who gave his life protecting Kibbutz Be'eri on October 7, 2023.*

## Install

```bash
/plugin marketplace add michalaharonson/oc-security-audit
/plugin install oc-security-audit
```

Then run in any project:
```bash
/oc-security-audit
```
or just ask: "run a security audit on this project"

## What it checks

14 categories mapped to OWASP standards. Each answers a plain-language security question:

| # | Category | User question answered | OWASP source |
|---|----------|----------------------|--------------|
| 1 | DDoS / API abuse | Can someone take my app down or run up my bill? | API4:2023, WSTG-DOS |
| 2 | Hosting bypass | Can someone bypass my security layer? | WSTG-CONF-01, CONF-10 |
| 3 | User data exposure | Can someone see data they shouldn't? | API3:2023, ASVS V14 |
| 4 | Broken access control (IDOR) | Can someone access other users' data? | API1:2023, A01:2025 |
| 5 | Code injection (safety net) | Is code safe from injection? | A05:2025, WSTG-INPV |
| 6 | Supply chain | Are dependencies safe? | A03:2025 |
| 7 | Session / auth security | Can someone steal a session? | A07:2025, WSTG-SESS |
| 8 | Secret leakage | Are secrets exposed? | WSTG-CONF-04, CONF-09 |
| 9 | SSRF | Can server be tricked to fetch internal resources? | A01:2025 |
| 10 | AI/LLM risks | Is AI integration leaking user data? | LLM Top 10 2025 |
| 11 | Infrastructure config | Is production configured securely? | A02:2025, WSTG-CONF |
| 12 | Privacy / legal | Am I legally covered for user data? | ASVS V14, GDPR |
| 13 | Error handling | Does the app fail securely? | A10:2025 |
| 14 | Logging & monitoring | Will I know if someone is attacking? | A09:2025 |

## How it works

The audit runs in 6 steps with progress indicators:

```
Step 1: DISCOVER              Step 2: SELECT TESTS         Step 3: SCAN
[shell script]                [shell script]               [shell script]

discover.sh                   Read profile, count:         scan.sh
  - Detect framework            - 66 test types to run       - Profile-driven dispatch
  - Detect hosting              - 11 LLM judgment calls      - grep code patterns
  - Detect ORM                  - 33 skipped (not            - curl live domain
  - Find 12+ API routes           applicable to stack)       - npm audit
  - Find production domain      - 12 deferred to             - Check security headers
  - Detect features               /security-review           - Output TOTALS + Audit Details

Step 4: ANALYZE               Step 5: REPORT               Step 6: CLOSE
[LLM]                         [LLM]                        [LLM]

LLM reads route files         Positive-first report:       Remind about /security-review
  for 8 judgment calls:         1. What's secure            Offer to save report
  - IDOR ownership              2. Executive Summary
  - Privilege escalation         3. What needs attention
  - Feature misuse                 (issues by category,
  - Data exposure                   severity-tagged)
  - Prompt injection             4. Audit Details table
  - Workflow bypass
```

**Lightweight — shell scripts handle mechanical checks, LLM only activates for judgment calls and report writing.** Steps 1-3 use zero LLM tokens. Token usage varies by model and project size.

### Profile-driven execution (v2.2 architecture)

The profile (`profiles/nextjs-prisma.md`) is the single source of truth. It declares every OWASP WSTG test case with a decision: `RUN (script)`, `RUN (llm)`, `SKIP`, or `DEFER`. scan.sh reads the profile at startup and dispatches to named functions. If a RUN check has no matching function, scan.sh emits a FAIL row -- no silent skipping.

This follows industry-standard patterns used by OWASP ZAP, Nessus, and Checkov -- the profile drives execution, not hardcoded check lists.

## How this differs from Candlekeep + OWASP

Running the full OWASP book through an LLM (e.g., via Candlekeep) works but is expensive and inconsistent. This skill splits the work: deterministic shell scripts handle mechanical checks, and the LLM handles only the judgment calls that require reading code and reasoning.

| | Candlekeep + OWASP book | This skill |
|---|---|---|
| Token cost | High (LLM does everything) | Lightweight (scripts handle mechanical checks) |
| Consistency | Varies per run | Repeatable (scripts are deterministic) |
| Stack awareness | Generic | Profile filters irrelevant checks per stack |
| Production testing | No | Yes -- curls your live domain |
| Report format | Unstructured | Positive-first, severity-tagged, with "what could go wrong when fixing" |
| Numbers accuracy | LLM counts (error-prone) | Script-computed (exact) |

## Report structure

The report leads with the positive and uses clear severity tags:

1. **What's secure** -- categories where your app is fundamentally solid (generous: includes LLM judgment passes and categories with minor WARNs)
2. **Executive Summary** -- posture emoji + exact pass/warn/fail counts + distinct findings count
3. **What needs attention** -- issues grouped by category, ordered by priority:
   - Each issue has a severity tag: :red_circle: FIX / :yellow_circle: INVESTIGATE / :green_circle: MONITOR/ACCEPT
   - Each FIX issue includes 7 sections: WSTG Reference, Threat, What's wrong, What could happen, **What could go wrong when fixing**, How others solve this, Recommended action
4. **Audit Details** -- script-computed category summary table with OWASP test IDs (numbers guaranteed accurate)

## What it doesn't check

These checks are deferred to Anthropic's `/security-review` skill, which does deep code-level analysis:

| Check | Why deferred | Where to check instead |
|-------|-------------|----------------------|
| INFO-07: Map app execution paths | Code-level control flow analysis | `/security-review` |
| IDNT-01: Role definitions | Code-level role logic | `/security-review` |
| ATHN-04: Bypass authentication schema | Logic-level bypass analysis | `/security-review` |
| SESS-03: Session fixation | Code-level token rotation logic | `/security-review` |
| SESS-06: Logout functionality | Token invalidation logic | `/security-review` |
| SESS-08: Session puzzling | Multiple session token analysis | `/security-review` |
| ATHZ-01: Path traversal | Code-level file path logic | `/security-review` |
| CRYP-04: Weak hash algorithms | Code-level crypto review | `/security-review` |
| BUSL-02: Ability to forge requests | Code-level analysis | `/security-review` |
| BUSL-03: Integrity checks | Code-level analysis | `/security-review` |
| FILE-03: File inclusion | Code-level analysis | `/security-review` |
| LLM02: Insecure output handling | Output rendering code analysis | `/security-review` |

## Supported stacks

| Stack | Status |
|-------|--------|
| Next.js + Prisma | Supported |
| Next.js + Supabase | Planned |
| Next.js + Drizzle | Planned |

Each stack has its own profile (`profiles/{stack}.md`) with WSTG-mapped checks, grep patterns, and judgment call definitions tailored to that stack's patterns and conventions.

### Unsupported stacks

> **Note (April 2026):** We currently only support the `nextjs-prisma` profile. Adding a new profile is straightforward — copy the existing profile, adjust the RUN/SKIP/DEFER decisions for your stack, and add matching grep patterns. PRs welcome, or [open an issue](https://github.com/miclivne/oc-security-audit/issues) to request a profile for your stack.

If your stack is not yet supported, partial stack-independent checks still run (security headers, TLS, exposed files, DNS, npm audit, secret patterns) with a message noting which stack-specific checks were skipped.

## Security model

- **Read-only.** This skill does not modify any files in your project.
- **No secret values read or output.** Scripts check for key existence only (e.g., "does `STRIPE_SECRET_KEY` exist in `.env.production`?") -- never reads or prints the value.
- **Network: GET/HEAD to user's own domain only.** The only outbound HTTP requests go to the production domain discovered from your env files. No requests to third-party servers.
- **No POST to any server.** All network checks use GET or HEAD methods.
- **No eval.** Patterns are sourced from a companion `.sh` file, not eval'd from markdown.
- **stdout only.** No files are written. The report is presented in the conversation.
- **Every command is commented.** Every `curl`, `grep`, `dig`, and `find` call has a `# WHY:` comment explaining what it checks and why. 102 WHY comments in scan.sh, 27 in discover.sh.
- **Minimal allowed-tools.** Only Read, Grep, Glob, and two pattern-restricted Bash calls (discover.sh and scan.sh). No unrestricted shell access.

Safe for review by Gen Trust Hub, Socket, and Snyk.

## Legal disclaimer

Do not run against systems you do not own or have written permission to test. Authors not responsible for misuse. A passing audit does not guarantee absence of vulnerabilities.

This skill sends GET/HEAD requests to your production domain to check security headers, exposed files, and error handling behavior. These are lightweight, non-destructive requests equivalent to loading your site in a browser. No exploitation, brute-forcing, or load testing is performed.

## Standards cited

- [OWASP Web Security Testing Guide (WSTG) v4.2](https://owasp.org/www-project-web-security-testing-guide/v42/)
- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x00-header/)
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/)
- [OWASP Top 10 2025](https://owasp.org/www-project-top-ten/)
- [OWASP ASVS 5.0 Level 1](https://owasp.org/www-project-application-security-verification-standard/)
