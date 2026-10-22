# Architecture Decision Record (ADR) 0020: Bounded Host Discovery and Reachability States

## Status
Accepted

## Context
Phase 8.2 of Milestone 8 requires implementing bounded host discovery within explicitly authorized scopes, adhering to strict defensive engineering principles:
1. Support small, explicitly scoped IPv4 ranges first. Defer IPv6 discovery until its scope and testing strategies are formally designed.
2. Enforce conservative resource limits: concurrency bounds, rate limiting delays between target dispatches, and per-target timeouts.
3. Record empirical discovery method and observable evidence for each result.
4. Uphold the fundamental defensive security invariant: a lack of response must remain strictly *inconclusive* when firewall filtering, packet loss, or silent drops could explain the absence of reply. A host can never be reported as definitively offline from non-response alone.
5. Prevent any possibility of Internet-wide or unbounded scanning.
6. Provide hermetic controlled test fixtures covering all states (reachable, inconclusive, failed, cancelled) without public network dependencies.

## Decision

### 1. Reachability State Classification (`HostReachabilityState`)
Host reachability outcomes are classified into four distinct states:
- **`reachable`**: The target host actively returned a network-layer response. This includes:
  - Connection established (`tcp_syn_ack`): Port is open and completed handshake.
  - Connection refused (`tcp_rst`): Port is closed, but the target operating system's IP stack actively returned an RST packet. This constitutes definitive proof of host reachability.
- **`inconclusive`**: Probed discovery ports timed out without any response. In line with Master Specification Section 5.3 and 6.7, this is treated strictly as inconclusive because packet drops or firewall filtering cannot be distinguished from host absence.
- **`failed`**: An operational, routing, or permission error occurred (e.g. `network_unreachable`, `permission_denied`).
- **`cancelled`**: The operation was interrupted by user cancellation token or global deadline.

### 2. Empirical Evidence Recording (`DiscoveryEvidence`)
Each host observation records:
- **`method`**: `tcp_probe` (standard unprivileged TCP discovery).
- **`response_port`**: The port that responded (e.g. 80, 443).
- **`response_type`**: Protocol-level response classification (`tcp_syn_ack (open)`, `tcp_rst (connection refused)`, `timeout (no response)`, etc.).
- **`rtt_ms`**: Monotonically measured round-trip time in milliseconds.
- **`notes`**: Actionable context explaining the evidence (e.g., *"Host active: TCP RST received; network stack actively responding"*, or *"Inconclusive: No response received; silent packet drop or firewall filtering may explain absence of reply"*).

### 3. Resource Bounds and Rate Limiting (`DiscoveryConfig`)
Discovery applies defensive controls:
- **`concurrency`**: Conservative limit (default: 4, capped at 64 via `--concurrency`).
- **`rate_limit_delay_ms`**: Inter-target delay (default: 5 ms, configurable via `--rate-limit`) to avoid burst network flooding.
- **`timeout_ms`**: Per-target deadline (default: 2000 ms, configurable via `-t, --timeout`).
- **`max_hosts`**: Enforces strict host count cap (default: 256, configurable via `--max-hosts`).
- **Cancellation**: Monitored between and during connection attempts via `CancellationToken`.

### 4. Scope Confinement and Invariants
- Discovery only probes addresses present in `AssessmentPlan.scope.targets` that are not excluded by `AssessmentPlan.scope.exclusions`.
- Broad CIDRs (< /24) are blocked pre-execution with `error.ExcessiveCidrRange`.
- Remote non-loopback targets require explicit authorization acknowledgement (`--confirm-authorized`).
- IPv6 targets are marked `inconclusive` with notes documenting that IPv6 discovery is deferred until formal roadmap design.

### 5. CLI and Library Integration
- `wirescope discover <target|cidr> [options]` executes live bounded host discovery when `--preview` is omitted, or plan preview when `--preview` or `--dry-run` is specified.
- Outputs human-readable terminal summaries (`toTerminal`) and structured machine-readable JSON (`toJson`).

## Consequences

### Positive
- Reliable, unprivileged, cross-platform host discovery on Windows, Linux, and macOS without requiring raw sockets or elevated administrative rights.
- Accurately conveys network reality: never falsely claims a host is offline when packets might merely be filtered.
- Prevents network degradation through conservative rate limiting and concurrency limits.

### Negative
- Hosts with all discovery ports silently dropping packets without RST are reported as inconclusive rather than unreachable.
- IPv6 scanning is deferred until subsequent milestones.
