# Architecture Decision Record (ADR) 0029: Offline Policy Evaluation

## Status
Accepted

## Context
Phase 10.4 of Milestone 10 requires implementing offline policy evaluation. The evaluator must allow assessment profiles and standalone policies to define expected services, supported TLS configurations, HTTP security header requirements, and listener exposure boundaries. It must evaluate stored observations without performing new network activity, utilize an explicit four-state outcome model (`pass`, `fail`, `inconclusive`, `not_applicable`), enforce that inconclusive checks never silently count as pass, and map policy evaluation results deterministically to documented CLI exit codes.

Key Architectural Invariants:
1. **Zero Network Activity**: Policy evaluation over saved observations or baselines runs completely in-memory, initiating zero network sockets, DNS queries, or HTTP requests.
2. **Inconclusive Check Non-Pass Invariant**: A missing observation, unobserved port, connection failure, or permission-limited query must **never** silently count as pass. Any unverified requirement is classified as `inconclusive` and marks the policy as non-compliant.
3. **Four-State Outcome Model**:
   - `pass`: Requirement evaluated against affirmative observation and satisfied.
   - `fail`: Requirement evaluated against observation and violated.
   - `inconclusive`: Observation data missing, incomplete, permission-limited, or failed upstream.
   - `not_applicable`: Requirement does not apply to the given endpoint or transport (e.g., CSP on non-HTML API or HSTS on plain HTTP).
4. **Deterministic Exit Code Mapping**:
   - `ExitCodes.success` (0): Execution succeeded and all evaluated rules passed (or are not applicable).
   - `ExitCodes.findings_or_violations` (1): Policy violations detected (`failed_count > 0`) or compliance unverified due to missing evidence (`inconclusive_count > 0`).
   - `ExitCodes.invalid_input` (2): Malformed policy specification or unknown arguments.
   - `ExitCodes.operational_failure` (3): Storage or I/O failure.
5. **Versioned Policies & Rules**:
   - Rules maintain stable versioned IDs (e.g. `WS-RULE-TLS-MIN-VERSION`, `v1`).
   - Policies maintain stable versioned IDs (e.g. `WS-POL-LOCAL-HARDENED`, `v1`, `schema_version = 1`).

## Decision

### 1. Versioned Policy Schema (`src/policy/types.zig`)
Defined `PolicyDefinition` with composite sub-policies:
- **`ExpectedServicesPolicy`**: Whitelist of allowed TCP ports (`allowed_ports`), disallowing unlisted ports, and enforcing TLS on sensitive services (e.g. 443, 8443).
- **`TlsPolicyRequirements`**: Enforces modern minimum protocol (`TLSv1.2`+), valid trusted CA certificate chains, SAN/CN hostname identity matching, and minimum remaining validity days buffer.
- **`HttpPolicyRequirements`**: Enforces HTTPS transport, HSTS header with minimum `max-age`, Content-Security-Policy (with `unsafe-inline`/`unsafe-eval` prohibitions), `X-Content-Type-Options: nosniff`, and clickjacking frame protection (`X-Frame-Options` or CSP `frame-ancestors`).
- **`ExposurePolicyRequirements`**: Prohibits wildcard (`0.0.0.0` or `[::]`) socket bindings, restricts listeners to allowed ports, and optionally requires loopback-only binding.

### 2. Offline Policy Evaluator (`src/policy/evaluator.zig`)
Implemented `OfflinePolicyEvaluator`:
- `evaluateObservations(observations, target_context)`: Inspects in-memory `AssessmentObservations`.
- `evaluateAssessment(result)`: Evaluates observations from an `AssessmentResult`.
- `evaluateBaseline(snapshot)`: Evaluates normalized baseline snapshot items completely offline.
- Generates `PolicyEvaluationReport` tracking metrics (`total_evaluated`, `passed_count`, `failed_count`, `inconclusive_count`, `not_applicable_count`) and individual `PolicyRuleEvaluation` records with observed vs expected values.
- Multi-format output renderers: `.toTerminal()`, `.toJson()`, and `.toMarkdown()`.

### 3. CLI Command Dispatch (`src/cli/root.zig`)
- Subcommand `wirescope policy check` / `wirescope policy eval`:
  - Evaluates designated profile or default policy offline against stored observations.
  - Returns `ExitCodes.success` (0) if compliant (`failed == 0 and inconclusive == 0`).
  - Returns `ExitCodes.findings_or_violations` (1) if violations or inconclusive checks are detected.
- Retained `wirescope policy` / `wirescope policy list` for rules catalog inspection to preserve backward compatibility.

## Consequences

### Positive
- Enables continuous CI/CD audit and offline compliance verification without live network dependencies.
- Eliminates false passes caused by dropped scans or unobserved ports.
- Provides consistent terminal, JSON, and Markdown compliance reporting.
