# Architecture Decision Record (ADR) 0013: DNS Troubleshooting and Resolver Comparison

## Status
Accepted

## Context
Phase 5.2 of Milestone 5 requires mapping observed DNS outcomes to actionable troubleshooting guidance and providing optional side-by-side comparison across explicitly configured resolvers.
Specific principles and criteria:
1. Advice must be tied directly to observed resolution outcomes (success, NXDOMAIN, timeout, no answer, malformed input, transport failure).
2. Uncertain root causes must be explicitly described as possibilities rather than unsupported facts.
3. Resolver comparisons must identify the resolvers actually queried and preserve individual latency and error evidence.
4. Different answers across resolvers must be treated as an observation requiring architectural context (e.g. split-horizon, CDN anycast, caching/TTL variations, policy filtering), NOT evidence of DNS poisoning or hijacking.
5. External DNS checks must remain strictly optional; default execution queries only the local system resolver.

## Decision

### 1. Structured Troubleshooting Guidance (`src/probes/dns_troubleshooting.zig`)
- **`DnsTroubleshooting`**: Encapsulates `summary`, `possible_causes` (list of strings), `recommended_actions` (list of actionable steps), and optional `context_notes`.
- **`generateTroubleshooting(category, count)`**: Generates context-aware diagnostic guidance:
  - `success`: Confirms resolution; highlights dual-stack reachability or round-robin edge distribution when multiple IPs are present.
  - `nxdomain`: Posits possibilities (typos, expired registration, private host queried on public resolver without search domains, zone propagation delay) and recommends FQDN verification, WHOIS audit, or VPN/internal DNS usage.
  - `timeout`: Posits possibilities (unresponsive upstream resolver, local network/gateway failure, UDP 53 firewall filtering, path congestion) and suggests checking routes, verifying port 53 egress, or testing alternate resolvers.
  - `no_answer`: Highlights that the domain exists (NOERROR) but lacks records for the queried family (A vs AAAA).
  - `malformed_input`: Highlights specific RFC 1035 syntax violations caught pre-network.
  - `resolver_transport_error`: Outlines host network stack, OS DNS client daemon, or socket exhaustion issues.

### 2. Evidence-Driven Disagreement Analysis (`explainDisagreement`)
- Prohibits false or unsubstantiated security conclusions.
- When answering resolvers return differing IP sets, WireScope issues an objective architectural analysis highlighting:
  1. Split-horizon (split-view) DNS (internal RFC 1918 vs external public IPs).
  2. Anycast CDN routing (geo-distributed edge proxies).
  3. Caching and TTL variations across recursive resolvers.
  4. Resolver policy filtering (sinkholing to `0.0.0.0` or `127.0.0.1` by security or ad-blocking resolvers).

### 3. Optional Resolver Comparison Engine (`src/probes/dns.zig`)
- **`compareResolvers`**: Queries each configured resolver individually, recording:
  - Exact resolver label/address.
  - Granular outcome category.
  - Monotonic elapsed latency in nanoseconds.
  - Lexicographically sorted answers.
  - Structured error details if query failed.
- **`ResolverComparisonResult`**: Compares answer sets across successful resolvers:
  - Sets `answers_match: bool`.
  - Attaches `disagreement_analysis` only when answer disagreement is observed.
  - Formats clean comparison tables in terminal and deterministic JSON.

### 4. Direct Custom UDP Resolver (`CustomUdpResolver`)
- Implements RFC 1035 UDP wire query to explicit target nameservers (e.g. `1.1.1.1:53`, `8.8.8.8:53`) with socket timeouts.
- Uses Windows `ws2_32.dll` APIs and POSIX sockets directly with zero external library dependencies.
- Completely optional: external resolvers are queried only when `--compare <resolvers>` is explicitly provided by the user.

## Consequences
- Operators obtain actionable diagnostic guidance immediately when DNS issues occur.
- Multi-resolver differences are presented with neutral, professional context without raising alarmist, unsupported security allegations.
- Zero mandatory external network dependencies during tests or default CLI usage.
