# Architecture Decision Record (ADR) 0024: Defensive Local Exposure Auditor

## Status
Accepted

## Context
Phase 9.2 of Milestone 9 requires building a defensive local exposure auditor. The auditor must combine local listener inventory with user-defined expected services and binding policies to identify unexpected listeners or wildcard/interface exposure for review.

Key architectural and product invariants:
1. **Strictly Read-Only Invariant**: The auditor must never modify firewall rules, kernel routing tables, network interface states, or socket configurations. It is purely observational.
2. **Permission Limitations Transparency**: If process/listener data is unavailable due to OS permission boundaries or unprivileged execution, the system must explicitly report the limitation (`WS-AUDIT-EXPOSURE-PERMISSION-LIMITED`) rather than asserting that zero exposure exists.
3. **No Presumption of Exploitability**: No listener is called exploitable solely because it exists. Listening sockets are evaluated against expected administrative baselines and exposure scope (e.g., wildcard binding vs loopback isolation).
4. **Empirical Evidence & False-Positive Caveats**: Findings must document exact observed network addresses, ports, PIDs, processes, severity rationale, remediation guidance, operational limitations, and false-positive caveats (such as ephemeral dev servers or benign OS services).
5. **Deterministic Policy Comparison**: Sockets must be evaluated against expected policy bindings (`loopback_only`, `wildcard_allowed`, `specific_only`) and process name expectations.

## Decision

### 1. Module Layout and Architecture
Implemented in `src/audit/exposure_audit.zig` and exposed via `src/audit/root.zig`:
- **`BindingPolicy`**: Enumerates permitted socket bindings:
  - `loopback_only`: Service must only bind to 127.0.0.1 or ::1.
  - `wildcard_allowed`: Service is approved to bind to 0.0.0.0 or ::.
  - `specific_only`: Service must bind to an explicit non-wildcard IP address.
- **`ExpectedServicePolicy`**: Defines expectations for an administrative service:
  - `name`: Service identifier (e.g., "ssh", "http-prod").
  - `port`: Expected listening port.
  - `transport`: Expected transport protocol (`tcp` or `udp`).
  - `binding_policy`: Permitted `BindingPolicy`.
  - `expected_process`: Optional expected executable binary name (e.g., "sshd.exe", "nginx").
  - `required`: Boolean indicating whether the service must be present and listening.
- **`LocalExposurePolicy`**: Complete policy document with:
  - `policy_id`: Identifier string.
  - `allow_unknown_loopback`: Boolean permitting unlisted loopback listeners (default true).
  - `allow_unlisted_wildcards`: Boolean permitting unlisted wildcard listeners (default false).
  - `expected_services`: Slice of `ExpectedServicePolicy`.
  - Helper `fromExpectedPorts(allocator, ports_spec)`: Dynamically generates policy from comma-separated port numbers (e.g. `--ports 80,443`).
- **`LocalExposureFinding`**: Defensive finding structure:
  - `rule_id`: Stable identifier (e.g. `WS-AUDIT-EXPOSURE-WILDCARD-BINDING`).
  - `severity`: Structured `Severity` (`info`, `low`, `medium`, `high`, `critical`).
  - `severity_rationale`: Explicit justification for the assigned severity.
  - `evidence`: Specific observed socket string.
  - `supporting_observations`: PID, process name, local address, and port.
  - `context_evaluation`: Analysis of socket context against policy rules.
  - `remediation`: Concrete steps to restrict exposure or update baseline policy.
  - `false_positive_caveat`: Benign scenarios where the listener is safe.
  - `limitations`: Explicit statement of read-only observational bounds.
- **`LocalExposureAuditResult`**: Aggregates observed listeners, findings, compliant count, permission limitation flag, and provides multi-format renderers (`.toTerminal()`, `.toJson()`, `.toMarkdown()`).

### 2. Evaluated Rules Matrix
- **`WS-AUDIT-EXPOSURE-WILDCARD-BINDING`**:
  - Assigned when an expected service is configured with `loopback_only` or `specific_only` but is observed binding to wildcard `0.0.0.0` or `::`.
  - Severity: `medium`.
- **`WS-AUDIT-EXPOSURE-UNEXPECTED-LISTENER`**:
  - Assigned when an observed listener is not defined in `expected_services`.
  - Wildcard bindings receive `medium` severity (expands external host attack surface).
  - Interface-specific bindings receive `low` severity.
  - Loopback listeners are exempted when `allow_unknown_loopback` is enabled.
- **`WS-AUDIT-EXPOSURE-PROCESS-MISMATCH`**:
  - Assigned when an expected service is bound by an unexpected binary/process name.
  - Severity: `low`.
- **`WS-AUDIT-EXPOSURE-MISSING-SERVICE`**:
  - Assigned when an expected service marked `required = true` is not actively listening.
  - Severity: `low`.
- **`WS-AUDIT-EXPOSURE-PERMISSION-LIMITED`**:
  - Assigned when the underlying platform inspector reports permission boundaries, restricted process inspection, or partial table access.
  - Explicitly documents that WireScope cannot guarantee zero exposure without elevated privileges.
  - Severity: `info`.

### 3. Read-Only Invariant Enforcement
- The auditor interfaces with the operating system through `ListenerInspector` (wrapping `platform.inspectListeners`).
- No OS system calls for firewall modification, interface configuration, routing adjustment, or process signaling are referenced or permitted.

## Consequences

### Positive
- System administrators and security engineers can establish deterministic expected-state listener policies and detect configuration drift or unintended external exposure.
- Standardized, structured findings across CLI terminal, JSON machine pipelines, and human-readable Markdown reports.
- Comprehensive false-positive caveats and non-exploitative phrasing prevent alarmist or invalid vulnerability assertions.
- Permission limitations are prominently reported, preventing dangerous false negatives.

### Verification
- Controlled unit test fixtures in `src/audit/exposure_audit.zig` testing:
  - Clean baseline conforming to expected policy (0 findings).
  - Unexpected wildcard listener detection with supporting observations and caveat.
  - Visible permission limitation reporting when access is constrained.
  - Policy port specification parser (`--ports`).
  - Terminal, JSON, and Markdown rendering output.
- CLI integration tests in `src/cli/root.zig` exercising terminal, JSON, and Markdown invocations.
