# Architecture Decision Record (ADR) 0006: Versioned Configuration, Assessment Profiles, and Scope Guard

## Status
Accepted

## Context
Phase 2.2 of Milestone 2 requires establishing versioned system configurations and assessment profiles with:
1. Shared operational controls (timeouts, concurrency, retries, response buffer limits, retention).
2. Assessment profiles defining explicit targets, ports, checks, and exclusions.
3. Strict validation rules preventing silent scope expansion, oversized ranges, or unauthorized remote probing.
4. Safe built-in loopback examples.
5. Redaction of sensitive values and credentials in diagnostic outputs.

## Decision

### 1. Global Versioned Configuration (`WireScopeConfig`)
Located in `src/assessment/config.zig`:
- `timeouts`: Default timeout (5000 ms), connect timeout (3000 ms), total assessment deadline (300 s).
- `concurrency`: Default max parallel probes (10), rate limit (20 probes/s).
- `limits`: Max retries (1, hard cap 3), max response size (64 KB), max hosts (256), max ports per host (100), max total operations (1000, hard cap 5000).
- `storage`: Data directory (`data/`), auto-prune period (30 days).
- `output`: Default format (`terminal`), sensitive redaction enabled.

Hard limits prevent dangerous operational values even if requested via configuration file:
- Concurrency capped at 50 parallel workers.
- Timeout bounded between 100 ms and 60,000 ms.

### 2. Assessment Profiles & Scope Guard (`AssessmentProfile`)
Located in `src/assessment/profile.zig`:
- Every profile defines explicit `scope.targets` (IPs, hostnames, CIDRs) and `scope.ports`.
- Invariant 1: Unbounded CIDR ranges (such as `0.0.0.0/0` or any range broader than `/24`) are strictly rejected (`error.ExcessiveCidrRange`).
- Invariant 2: Remote (non-loopback) targets require explicit user authorization acknowledgement (`authorization_acknowledged = true`); otherwise rejected with `error.MissingAuthorizationAcknowledgement`.
- Invariant 3: Port count per assessment cannot exceed 1000 (`error.ExcessivePortCount`).
- Invariant 4: No silent scope expansion. Planned operation count is calculated deterministically (`calculatePlannedOperations()`).

### 3. Safe Built-In Profiles & Examples
Shipped in `src/assessment/profile.zig` and serialized under `examples/profiles/`:
- `loopback-diagnostics.json`: Restricted strictly to `127.0.0.1` and safe diagnostic ports (80, 443, 8080).
- `local-defensive-audit.json`: Restricted strictly to `localhost` and service ports (8080, 8443).
- `examples/config.json`: Standard version 1 global configuration.

### 4. Diagnostic Redaction Engine (`src/assessment/redact.zig`)
Scans messages for credential patterns (`password`, `secret`, `api_key`, `token`, `bearer`, `authorization`) and replaces sensitive values with `[REDACTED]` prior to formatting or logging.

## Consequences
- Impossible to execute unbounded Internet-wide scans.
- Remote assessments require deliberate user acknowledgement.
- Configuration and profile validation executes completely offline before any probe scheduling.
