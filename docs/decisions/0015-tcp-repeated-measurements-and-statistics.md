# Architecture Decision Record (ADR) 0015: TCP Repeated Measurements and Statistical Summaries

## Status
Accepted

## Context
Phase 6.2 of Milestone 6 requires adding bounded repeated measurements and statistical summaries for network connectivity probes:
1. Allow a bounded sample count and interval (no unbounded ping loops or network flooding).
2. Report sample counts: total requested/attempted, successful connects, failed attempts, and packet/probe loss percentage.
3. Calculate round-trip statistics exclusively from comparable successful measurements: minimum, maximum, mean, median, sample standard deviation, and percentiles.
4. Document the jitter formula and calculate it from chronological successful measurements.
5. Report percentiles only when mathematically meaningful for the observed sample size; never fabricate percentiles on sparse sample sets.
6. Report failed samples separately with categorized failure causes (refusals, timeouts, unreachables, cancellations).
7. Do not merge DNS, TCP, TLS, and HTTP timing into one ambiguous number.
8. Use a monotonic clock for all durations; do not hide outliers or environmental variability.

## Decision

### 1. Bounded Sample Count and Interval Control
- **Bounds**:
  - Sample Count ($N$): Bounded to `1..100` (`ParseError.InvalidCount`). Prevents runaway loops, resource exhaustion, or denial-of-service behavior. Default: 1 (single probe) or 4 (`diagnose latency`).
  - Interval ($T$): Bounded to `0..60000` ms (`ParseError.InvalidInterval`). Default: 1000 ms.
- **Pacing & Responsive Cancellation**:
  - Inter-sample delay sleeps in responsive 20ms slices, repeatedly evaluating `CancellationToken.isCancelled()`.
  - Immediate termination occurs upon cancellation, preserving completed samples and marking `is_partial = true`.

### 2. Statistical Definitions & Formulas (`src/core/stats.zig`)

#### Exclusivity of Successful Measurements
- Failed samples (e.g. timeouts, RST refusals, network unreachables) do NOT possess a completed TCP 3-way handshake duration.
- Mixing arbitrary timeout bounds (e.g. 3000ms cutoffs) into latency calculations would fabricate non-existent transport delay distributions.
- Therefore, latency metrics (min, max, mean, median, standard deviation, jitter, percentiles) are calculated **exclusively from successful samples**.
- Failed samples are tracked separately in `failed_samples`, `loss_percent`, and `FailureBreakdown`.

#### Jitter Formula (RFC 3550 / RFC 4689 Mean Successive Absolute Difference)
- Let $(x_1, x_2, \dots, x_k)$ denote the chronological sequence of successful connection latencies ($k \ge 2$):
  $$J = \frac{1}{k - 1} \sum_{i=1}^{k - 1} |x_{i+1} - x_i|$$
- If $k < 2$, jitter is `null` (`n/a`), as at least two comparable successful measurements are required.

#### Sample Standard Deviation
- For $k \ge 2$ successful samples:
  $$s = \sqrt{ \frac{1}{k - 1} \sum_{i=1}^k (x_i - \bar{x})^2 }$$
- If $k < 2$, standard deviation is `null`.

#### Percentile Rules (Nearest-Rank Method)
- Evaluated on sorted successful samples:
  $$\text{rank} = \left\lceil \frac{P}{100} \times k \right\rceil, \quad \text{index} = \min(\text{rank} - 1, k - 1)$$
- Sample size thresholds for mathematical significance:
  - **p50 (Median)**: $k \ge 1$ (standard median: exact middle element for odd $k$, mean of two central elements for even $k$).
  - **p75**: Meaningful only when $k \ge 4$ (at least 1 observation per quartile).
  - **p90**: Meaningful only when $k \ge 10$ (at least 1 observation per decile).
  - **p95**: Meaningful only when $k \ge 20$ (at least 1 observation in top 5%).
  - **p99**: Meaningful only when $k \ge 100$ (at least 1 observation in top 1%).
- If $k$ is below the threshold, the percentile is explicitly omitted / `null`, never interpolated or fabricated.

### 3. Preserving Outliers and Environmental Variability
- Raw sample sequence history is fully preserved in `samples: []TcpSampleRecord`.
- Neither min/max nor standard deviation are artificially trimmed or filtered.
- Spikes and environmental jitter remain fully visible in terminal sample logs and JSON output.

### 4. Stage Timing Separation
- Monotonic timestamps (`std.time.nanoTimestamp()`) isolate DNS resolution duration (`dns_time_ns`) from TCP connect duration (`connect_time_ns`).
- Latency statistics aggregate solely `connect_time_ns`.
- Outputs explicitly state: "TCP connect time reflects 3-way SYN/SYN-ACK handshake duration, not ICMP echo ping latency."

## Consequences

### Positive
- Strict statistical validity: no artificial timeout values polluting latency distributions.
- Mathematical rigor: percentiles are only reported when the sample size genuinely supports them.
- RFC-compliant jitter metrics standard across performance tooling.
- Backward compatibility: single-sample invocation (`wirescope tcp <target> <port>`) preserves exact output format and behavior from Phase 6.1.
- Zero network required for automated testing via `MockTcpConnector` sequence simulation.

### Limitations
- Maximum 100 samples per execution by design. Operators requiring indefinite monitoring must execute automated batch assessments with persistence (Milestone 11).
