# Architecture Decision Record (ADR) 0025: Versioned Local Rules Engine

## Status
Accepted

## Context
Phase 9.3 of Milestone 9 requires defining a versioned rule schema with stable IDs, titles, severity, rationale, preconditions, required evidence, evaluation logic, limitations, and remediation. The engine must cover supported TLS/HTTP configuration, listener exposure, and baseline-deviation checks, separate severity from confidence, validate rule inputs safely, reject malformed rules without panicking, and make no claim of comprehensive CVE vulnerability coverage.

Key architectural and product invariants:
1. **Stable IDs and Versions**: Every rule must have a persistent identifier prefixed with `WS-RULE-` and an explicit positive integer version (`version >= 1`).
2. **Severity vs. Confidence Separation**:
   - `Severity` (`info`, `low`, `medium`, `high`, `critical`) denotes the inherent architectural impact of a defensive violation.
   - `Confidence` (`tentative`, `likely`, `confirmed`) denotes observational certainty and proof quality.
3. **Four-Outcome Evaluation Model**:
   - `pass`: Preconditions satisfied and observation complies with defensive standard.
   - `fail`: Preconditions satisfied and observation violates defensive standard (generates structured finding).
   - `inconclusive`: Preconditions satisfied but observation was truncated, timed out, or restricted by OS permissions.
   - `not_applicable`: Preconditions not satisfied for target context (e.g. HTML CSP rule on a JSON API, or HSTS rule on plain HTTP).
4. **Safe Malformed Rule Rejection**: Rules missing mandatory fields (empty title, missing rationale, empty preconditions, missing required evidence, missing limitations, or missing remediation) or with invalid IDs/versions are strictly rejected at registration time with descriptive errors without panic or memory leaks.
5. **No Claim of Comprehensive CVE Coverage**: WireScope evaluates observable exposures and defensive security headers only. It explicitly disclaims comprehensive CVE vulnerability scanning, exploit verification, or proof-of-concept testing.

## Decision

### 1. Module Layout and Architecture
Implemented in `src/audit/rules.zig` and re-exported via `src/audit/root.zig` and `src/policy/root.zig`:
- **`VersionedRule`**: Struct containing:
  - `id`: Stable identifier (e.g. `WS-RULE-TLS-MIN-VERSION`).
  - `version`: Version integer (e.g. `1`).
  - `title`: Concise human-readable title.
  - `description`: Narrative rule explanation.
  - `category`: `RuleCategory` (`tls_configuration`, `http_configuration`, `listener_exposure`, `baseline_deviation`).
  - `severity`: Structured `Severity`.
  - `confidence`: Structured `Confidence`.
  - `rationale`: Defensive justification.
  - `preconditions`: Prerequisites required for evaluation.
  - `required_evidence`: Necessary observation fields.
  - `limitations`: Explicit statement of operational boundaries.
  - `remediation`: Concrete operational guidance.
  - `evaluator`: Pure function pointer evaluating `RuleInput` against the rule.
- **`RuleInput`**: Tagged union accepting:
  - `tls_observation`: `TlsObservation` (protocol version, hostname match, certificate expiration days, timeout/permission flags).
  - `http_observation`: `HttpObservation` (status code, HTTPS flag, HTML vs JSON API flags, HSTS, CSP, nosniff, cookies, timeout flag).
  - `listener_observation`: `ListenerObservation` (address, port, transport, binding type, process name, unlisted flag, permission limited flag).
  - `baseline_observation`: `BaselineObservation` (item ID, baseline vs current value, new/removed/modified flags, incomplete evidence flag).
- **`RuleFinding`**: Structured finding containing rule metadata, rationale, evidence, context evaluation, remediation, limitations, and `cve_disclaimer`.
- **`RuleRegistry`**: In-memory registry with safe validation (`validate()`), duplicate detection, and format renderers (`.toTerminal()`, `.toJson()`, `.toMarkdown()`). Pre-populated with 12 built-in versioned rules (`registerDefaults()`).
- **`RuleEngine`**: Evaluator executing single rules or batch evaluations across observation inputs, producing `RuleEvaluationReport`.

### 2. Built-in Versioned Rules Catalog
- **TLS Configuration**:
  1. `WS-RULE-TLS-MIN-VERSION` (v1, High, Confirmed): Enforce TLS 1.2+; reject TLS 1.0, 1.1, SSLv3.
  2. `WS-RULE-TLS-CERT-EXPIRATION` (v1, Medium, Confirmed): Warn on certificate expiration or remaining days <= 14.
  3. `WS-RULE-TLS-HOSTNAME-MATCH` (v1, High, Confirmed): Enforce certificate Subject Alternative Name / CN identity match.
- **HTTP Configuration**:
  4. `WS-RULE-HTTP-HSTS-POLICY` (v1, Medium, Confirmed): Require HSTS header with max-age on HTTPS; mark N/A on plain HTTP.
  5. `WS-RULE-HTTP-CSP-SCRIPT-RESTRICTION` (v1, Medium, Confirmed): Enforce script restriction on HTML documents; mark N/A on JSON APIs.
  6. `WS-RULE-HTTP-NOSNIFF-HEADER` (v1, Low, Confirmed): Require `X-Content-Type-Options: nosniff`.
  7. `WS-RULE-HTTP-COOKIE-FLAGS` (v1, Medium, Confirmed): Require `Secure` and `HttpOnly` on sensitive session cookies.
- **Listener Exposure**:
  8. `WS-RULE-EXPOSURE-WILDCARD-BINDING` (v1, Medium, Confirmed): Audit wildcard `0.0.0.0`/`::` socket bindings.
  9. `WS-RULE-EXPOSURE-UNEXPECTED-LISTENER` (v1, Medium, Confirmed): Detect unlisted listening services.
  10. `WS-RULE-EXPOSURE-PERMISSION-BOUNDARY` (v1, Info, Confirmed): Report when unprivileged execution restricts socket audit.
- **Baseline Deviation**:
  11. `WS-RULE-BASELINE-UNEXPECTED-SERVICE` (v1, Medium, Confirmed): Flag new services not in approved baseline.
  12. `WS-RULE-BASELINE-SERVICE-REMOVED` (v1, Low, Confirmed): Flag missing baseline services (with timeout protection).

### 3. CVE Non-Coverage Disclaimer
Defined as a constant and surfaced in all outputs:
> *"WireScope evaluates defensive configuration and observable exposures only. WireScope makes no claim of comprehensive CVE vulnerability coverage, exploit verification, or proof-of-concept testing. Absence of findings does not indicate absence of application-layer vulnerabilities."*

## Consequences

### Positive
- Fully testable, deterministic rule evaluation engine decoupling observation capture from security assessment logic.
- Standardized separation between severity (impact) and confidence (observational certainty).
- Explicit non-exploitative posture with pervasive CVE disclaimers preventing misinterpretation of tool scope.
- Zero-panic guarantees on malformed rules or unexpected observation payloads.

### Verification
- 173 library unit tests covering positive, negative, inconclusive, and not-applicable rule evaluations, schema validations, and malformed rule rejections.
- CLI integration tests verifying `wirescope audit rules` and `wirescope policy` across terminal, JSON, and Markdown formats.
