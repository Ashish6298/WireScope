# Security Policy

WireScope is an evidence-driven, local-first network diagnostics and defensive cybersecurity assessment engine. We take the security, integrity, and safety of this tool and its users seriously.

---

## 1. Supported Versions

Security updates and patches are provided for the following versions:

| Version | Supported | Notes |
|---|---|---|
| `0.1.0-rc1` / `main` | **Yes** | Current active release candidate |
| `< 0.1.0` (Milestones 0–13) | No | Development development checkpoints |

---

## 2. Reporting a Vulnerability

If you discover a security vulnerability, scope-escape bug, parser crash, memory leak, or unsafe condition in WireScope, please report it responsibly:

- **Email:** `security@wirescope.dev` (or open a confidential GitHub Security Advisory).
- **PGP Key:** Available upon request or via published project security keys.
- **Do NOT open a public GitHub issue** for undisclosed vulnerabilities or zero-day exploits.

### What to Include in Your Report
To help us triage and reproduce the issue rapidly, please include:
1. Description of the vulnerability or unexpected behavior.
2. Exact steps to reproduce, including CLI flags, configuration profiles, target definitions, or input payloads.
3. Target platform details (OS name, version, architecture, compiler version).
4. Proof of Concept (PoC) script, test payload, or minimal reproduction.
5. Observed behavior versus expected safe behavior.
6. Potential impact assessment.

---

## 3. Response Commitments & Turnaround

- **Initial Response:** Within 48 hours of report receipt.
- **Triage & Validation:** Within 5 business days, confirming vulnerability reproducibility and severity classification.
- **Remediation & Patching:** Targeted patch released within 14–30 business days depending on severity.
- **Coordinated Disclosure:** We adhere to a 90-day coordinated disclosure policy, or sooner upon mutual agreement once a fix is verified.

---

## 4. In-Scope Security Boundaries

WireScope is designed with strict defensive invariants. Issues in the following areas are considered in-scope for security reports:

- **Scope Escape:** Any mechanism allowing network probes, DNS requests, or HTTP requests to target IP addresses or hosts outside approved assessment scope (e.g. DNS rebinding bypasses, unapproved HTTP redirects, CIDR expansion flaws).
- **Sandbox Traversal:** Any file operation escaping designated storage directories (`%LOCALAPPDATA%\wirescope`, `~/.local/share/wirescope`, or lab directories).
- **Denial of Service / Memory Exhaustion:** Unbounded memory allocation, socket descriptor exhaustion, or runaway probe threads triggered by untrusted network responses or malformed input payloads.
- **Credential Leakage:** Sensitive tokens (Authorization Bearer/Basic headers, passwords in URLs, API keys) appearing in unredacted report outputs when redaction is enabled.
- **Memory Corruption / Panics:** Buffer overflows, use-after-free, unaligned reads, or crashes in parser logic.

---

## 5. Out-of-Scope Scenarios

The following are considered intended behavior or documented residual limitations:

- Loss of process attribution when running WireScope without elevated/Administrator privileges (documented as `WS-AUDIT-EXPOSURE-PERMISSION-LIMITED`).
- Intermediate firewall or middlebox interference (e.g. forged TCP RSTs or silent drops).
- Local filesystem access by other processes running under the same user account without external encryption.
- Local SHA-256 manifest alteration by an adversary with write access to both report and manifest without external cryptographic PKI signing.

---

## 6. Safe Harbor

WireScope supports safe, responsible security research:
- If you make a good-faith effort to avoid privacy violations, data destruction, and service degradation, we will not pursue legal action against you for your research activities related to this project.
