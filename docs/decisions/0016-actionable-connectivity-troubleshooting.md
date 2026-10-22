# Architecture Decision Record (ADR) 0016: Actionable Connectivity Troubleshooting

## Status
Accepted

## Context
Phase 6.3 of Milestone 6 requires building a diagnostic interpretation layer for DNS failures, TCP refusal, timeout, route/interface symptoms, and measurement anomalies:
1. Separate observed facts from possible explanations.
2. Label possible causes explicitly as hypotheses where evidence is insufficient, avoiding unsupported claims of root cause.
3. Recommend concrete, actionable next steps for diagnosis and remediation.
4. Support both single probe outcomes and repeated measurement anomalies (e.g. jitter, partial loss).
5. Provide concise terminal output and structured JSON details without suppressing underlying measurements or changing existing CLI layout.

## Decision

### 1. Separation of Observed Facts, Hypotheses, and Actions (`src/probes/tcp_troubleshooting.zig`)
We introduced `TcpTroubleshooting`:
- **`summary`**: High-level, objective status description.
- **`observed_facts`**: Verifiable empirical observations from socket/network behavior (e.g. "Remote host responded with TCP RST", "SYN packet transmitted but no response received before deadline").
- **`hypotheses`**: Plausible technical explanations clearly labeled as hypotheses (e.g. "No service is listening on port", "Firewall dropping packets", "Equal-Cost Multi-Path routing across divergent paths").
- **`recommended_actions`**: Objective next diagnostic or remediation steps (e.g. inspect local listeners, check firewall rules, ping default gateway).
- **`context_notes`**: Technical context explaining network behavior (e.g. "RST indicates an active rejection, confirming the host is reachable and running").

### 2. Result Type Mapping

| Outcome / Result Type | Observed Fact | Hypotheses (Possible Causes) | Recommended Actions |
| :--- | :--- | :--- | :--- |
| **`success`** | 3-way handshake established with SYN-ACK | Port is open; daemon is accepting connections | Proceed with TLS/HTTP probes; run `-c 5` to test stability |
| **`refusal` (RST)** | Target or proxy actively sent TCP RST | Daemon not listening; bound to localhost only; host firewall REJECT | Check service status; inspect listeners; verify bindings |
| **`timeout`** | SYN sent, no reply before deadline | Firewall/NAT drop; host offline; asymmetric routing drop | Check routes; inspect gateway; check firewall/security groups |
| **`network_unreachable`** | OS returned ENETUNREACH / EHOSTUNREACH | Interface down; missing default route; upstream router unreachable | Check interface link state; verify routing table and gateway |
| **`permission_denied`** | OS socket call returned EACCES | Local endpoint protection/antivirus; sandbox restriction | Check host outbound firewall rules; verify privileges |
| **`malformed_input`** | Pre-network syntax validation failed | Port out of range [1, 65535]; RFC 1035 invalid hostname | Correct host:port syntax; verify numeric port range |
| **`high_jitter` (Batch)** | Successive variation > 50% mean connect time | Intermediate hop congestion; ECMP route changes; Wi-Fi variance | Run larger sample batch; isolate gateway vs WAN jitter |
| **`partial_loss` (Batch)** | Some connects succeeded, some failed | Transit link packet loss; rate limiting (SYN flood policer) | Increase interval (`-i 1000`); inspect server listen backlog |

### 3. Integration with Output Contracts
- **Terminal**: `TcpProbeResult.toTerminal()` and `TcpBatchProbeResult.toTerminal()` append a clean "Troubleshooting Guidance" block below the technical metrics.
- **JSON**: `TcpProbeResult.toJson()` and `TcpBatchProbeResult.toJson()` include a structured `"troubleshooting"` object with arrays for `observed_facts`, `hypotheses`, and `recommended_actions`.

## Consequences

### Positive
- Strict adherence to defensive cybersecurity principles: no false accusations or unproven root-cause claims.
- Operators immediately receive clear diagnostic leads and hypotheses grounded in actual network evidence.
- Preserves full underlying evidence (raw latency, individual sample outcomes, status codes).
- Hermetic test coverage across all outcome categories and batch anomaly types.

### Limitations
- Troubleshooting guidance provides probabilistic hypotheses based on network symptoms; conclusive root cause determination requires inspecting destination host configuration directly.
