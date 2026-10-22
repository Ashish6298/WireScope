# Architecture Decision Record (ADR) 0022: Asset and Exposure Inventory

## Status
Accepted

## Context
Phase 8.4 of Milestone 8 requires building an asset and exposure inventory system that normalizes discovery observations and enables deterministic differential analysis across assessment runs:
1. Normalize host, address, port, service, and timestamp observations into an asset inventory (`AssetInventory`).
2. Deduplicate carefully while preserving source observations and unredacted empirical evidence.
3. Compare assessment runs to classify differences into deterministic categories: `new_asset`, `new_service`, `removed_service`, `changed_service`, `unchanged_service`, and `inconclusive_state`.
4. Uphold the critical false-removal guard: an incomplete or inconclusive run (e.g., packet drop, timeout, unreachable route) must NEVER cause an unobserved service to appear definitively removed.
5. Provide deterministic diff ordering (sorted by target IP, then port, then category).
6. Enable rebuilding inventories from saved observation structures, emitting both structured CLI terminal reports and JSON exports.

## Decision

### 1. Unified Asset and Service Normalization Model
Defined in `src/recon/inventory.zig`:
- **`AssetService`**: Represents a normalized service instance on a specific host:
  - `port`: Port number (1–65535).
  - `protocol`: Transport protocol (`"tcp"`).
  - `service_name`: Identified application service name (e.g., `"http"`, `"ssh"`).
  - `version`: Software version string if observed via empirical evidence.
  - `banner`: Raw received protocol banner.
  - `confidence`: Confidence level (`none`, `low`, `medium`, `high`, `confirmed`).
  - `method`: Identification method (`http_head`, `banner_grab`, etc.).
  - `first_seen_timestamp` & `last_seen_timestamp`: Monotonic observation timestamps.
  - `original_evidence`: Full empirical evidence preserved from original probes.
- **`AssetHost`**: Normalized host record:
  - `id`: Normalized string identifier (`asset_{ip}`).
  - `ip_address`: Canonical IP string.
  - `hostname`: Optional resolved hostname.
  - `reachability_state`: Observed reachability (`reachable`, `inconclusive`, etc.).
  - `services`: Dynamic slice of normalized `AssetService` entries.
  - `original_evidence`: Full reachability evidence preserved from host discovery.

### 2. Ingestion and Deterministic Deduplication
- `ingestHostDiscovery()`: Ingests `HostDiscoveryResult`, creating new host records or updating timestamps and reachability for existing hosts.
- `ingestServiceScan()`: Ingests `ServiceScanResult`. Upserts hosts and merges services on matching ports. If service attributes (e.g., software version) change, updates the record and preserves observation history.
- `rebuildFromObservations()`: Deterministically constructs an `AssetInventory` from arbitrary series of discovery and scan outputs.

### 3. False-Removal Invariant
When comparing baseline inventory $A$ to current inventory $B$:
- If a service observed on host $H$ in $A$ is absent in $B$:
  - If $H$ was probed in $B$ and verified reachable with the specific port returning an active TCP RST (`PortState.closed`): reported as `removed_service`.
  - If $H$ was not probed in $B$, timed out, or resulted in an inconclusive/filtered state: reported strictly as `inconclusive_state`! It is NEVER reported as `removed_service`.
  - The entry's `reason` explicitly documents: `"Host reachability inconclusive or unprobed; service cannot be claimed removed"`.

### 4. Deterministic Diff Ordering and Categorization
- `DiffCategory`: `new_asset`, `new_service`, `removed_service`, `changed_service`, `unchanged_service`, `inconclusive_state`.
- `InventoryDiff.sort()` sorts entries deterministically:
  1. Target IP address (lexicographical ascending).
  2. Port number (ascending, with host-level entries first).
  3. Diff category tag (ascending).

### 5. CLI Integration
- `--inventory`: Displays the current assessment inventory in human-readable or JSON format.
- Emits standardized legal disclaimer warning operators of authorization responsibilities.

## Consequences

### Positive
- Prevents false-positive service removal alarms caused by transient network loss or firewall timeouts.
- Guarantees 100% repeatable, deterministic diff outputs for automated CI/CD and security monitoring pipelines.
- Preserves full empirical evidence alongside normalized abstractions.

### Negative
- Preserving raw probe evidence in inventory structures requires explicit memory management (`deinit`) when handling large fleet inventories.
