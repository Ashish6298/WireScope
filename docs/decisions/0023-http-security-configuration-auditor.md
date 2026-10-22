# Architecture Decision Record (ADR) 0023: Defensive HTTP Security Configuration Auditor

## Status
Accepted

## Context
Phase 9.1 of Milestone 9 requires building a defensive security auditor for explicitly supplied HTTP and HTTPS endpoints. The auditor must inspect applicable security configurations—such as HSTS, CSP, `X-Content-Type-Options`, redirect behavior, framing protection, information disclosure, and cookie security attributes—while strictly enforcing response size bounds, duration limits, and redirect scope controls.

Key architectural and product requirements:
1. **Contextual Evaluation**: A missing header is a defense-in-depth gap and must never be automatically reported as an exploitable vulnerability. For instance, APIs returning JSON payloads do not require HTML Content Security Policies or clickjacking protections.
2. **Empirical Evidence & False-Positive Caveats**: Findings must include exact observed evidence, severity rationale, operational limitations, and documented false-positive caveats explaining benign conditions where the finding may be disregarded.
3. **Strict Bounds Enforcement**: The auditor must bound response sizes (`max_response_bytes`, default 1 MB), durations (`timeout_ms`, default 5000 ms), and redirect counts (`max_redirects`, default 5). Response bodies must never be persisted in heap memory or on disk.
4. **Scope Guard Redirect Policy**: Redirection to destinations outside the initial host (or assessment profile scope) is terminated pre-connection unless `--allow-redirect-scope-expansion` is explicitly configured.
5. **Non-Destructive & No-Bypass Invariant**: Under no circumstances does WireScope execute exploit payloads, SQL injection, fuzzing, or authentication bypass testing. Audits evaluate static security configuration and header posture defensively.

## Decision

### 1. Module Layout and Core Types
Defined in `src/audit/http_audit.zig`, `src/audit/fixtures.zig`, and `src/audit/root.zig`:
- **`HttpCookie`**: Normalized cookie model capturing `name`, `value_redacted` (strictly `[REDACTED]` to preserve privacy), `secure`, `httponly`, `samesite` (`strict`, `lax`, `none`, `unspecified`), `domain`, `path`, and raw syntax.
- **`HttpAuditFinding`**: Comprehensive defensive security finding capturing:
  - `rule_id`: Stable identifier (e.g., `WS-AUDIT-HTTP-HSTS-MISSING`, `WS-AUDIT-HTTP-COOKIE-NO-SECURE`).
  - `severity`: Structured `Severity` (`info`, `low`, `medium`, `high`, `critical`).
  - `severity_rationale`: Explicit justification for the assigned severity.
  - `evidence`: Empirical evidence observed in headers or status line.
  - `context_evaluation`: Architectural context (e.g. HTML vs JSON API, HTTP vs HTTPS transport).
  - `remediation`: Concrete configuration snippets for common servers (Nginx, Apache, Caddy).
  - `false_positive_caveat`: Exhaustive caveat explaining benign scenarios (e.g., browser HSTS preload list, non-sensitive cookies, internal test networks).
  - `limitations`: Explicit statement of observational boundaries.
- **`HttpAuditResult`**: Encapsulates target and effective URL, response status line, response size, redirect chain, cookie inventory, security headers inventory, and findings collection. Provides `.toTerminal()`, `.toJson()`, and `.toMarkdown()`.

### 2. Evaluated Rules & Context Matrix
- **`WS-AUDIT-HTTP-HSTS`**:
  - Missing on HTTPS: Medium severity with false-positive caveat regarding Chromium/Firefox HSTS preload lists.
  - Max-age < 126 days: Low severity.
  - Missing `includeSubDomains`: Low severity.
  - Present over unencrypted HTTP: Info severity (RFC 6797 §7.2 violation).
- **`WS-AUDIT-HTTP-CSP`**:
  - Missing on HTML documents: Low severity defense-in-depth finding.
  - JSON API endpoints: Context evaluation recognizes script execution is inapplicable; no finding raised.
  - Permitting `'unsafe-inline'`, `'unsafe-eval'`, or `*` wildcards: Low severity.
- **`WS-AUDIT-HTTP-NOSNIFF`**:
  - Missing or invalid `X-Content-Type-Options`: Low severity MIME-sniffing defense finding.
- **`WS-AUDIT-HTTP-COOKIE`**:
  - Missing `Secure` on HTTPS: Medium severity.
  - Missing `HttpOnly`: Low severity with caveat for intentional frontend tokens (CSRF tokens).
  - Missing `SameSite`: Low severity.
  - `SameSite=None` without `Secure`: Medium severity (browsers reject unencrypted cross-site cookies).
- **`WS-AUDIT-HTTP-REDIRECT`**:
  - Plain HTTP without redirect or redirecting to HTTP: Medium severity.
  - Temporary redirect (302/307) for HTTPS upgrade: Info severity.
  - Scope Guard violation (unapproved external redirect): Medium severity; navigation halted immediately.
  - Redirect loop / limit exceeded: Low severity operational finding.
- **`WS-AUDIT-HTTP-FRAMING`**:
  - Missing `X-Frame-Options` and CSP `frame-ancestors` on HTML: Low severity clickjacking defense finding.
- **`WS-AUDIT-HTTP-SERVER-VERSION-LEAK`**:
  - Detailed version strings in `Server` or `X-Powered-By`: Info severity with caveat that backported distribution packages often retain upstream version strings without remaining vulnerable.
- **`WS-AUDIT-HTTP-RESPONSE-SIZE-EXCEEDED`**:
  - Response exceeding `max_response_bytes`: Low severity; stream safely truncated.

### 3. Controlled Local Fixtures
Defined in `src/audit/fixtures.zig`:
Hermetic fixtures cover every single rule, variant, and failure mode without requiring live external network connectivity:
- Fully hardened HTTPS response.
- Missing HSTS, weak max-age HSTS, and unencrypted HTTP HSTS.
- Missing CSP (HTML vs JSON API), and relaxed CSP policies (`unsafe-inline`, `unsafe-eval`, wildcard).
- Insecure cookie configurations (missing Secure, missing HttpOnly, missing SameSite, SameSite=None without Secure).
- Redirection permutations (permanent, temporary, out-of-scope, and loops).
- Framing protection and server version disclosures.
- Oversized responses.

### 4. CLI Dispatch and Reporting
- `wirescope audit http <url> [options]`
- Supported options: `--format <terminal|json|markdown>`, `--max-redirects`, `--max-response-size`, `--allow-redirect-scope-expansion`, `--insecure`, `--ca-bundle`, `--timeout`.
- Exit codes:
  - `0`: Successful execution with zero security findings.
  - `1`: Security findings or policy violations detected.
  - `2`: Invalid URL syntax, missing target, or Scope Guard redirect violation.
  - `3`: Operational network failure.

## Consequences
- The WireScope CLI and library can perform defensible, explainable, and bounded HTTP security configuration audits.
- No remote network dependencies are needed for unit or integration testing.
- Operators receive actionable remediation guidance alongside false-positive caveats, avoiding alarm fatigue.
