# Security Policy & Architecture

OmniExecutor Agent executes shell commands, modifies workspace files, drives headless/headed browsers, and optionally controls Windows desktop UI elements. Because autonomous execution carries real host risk, security controls are enforced **deterministically outside the LLM prompt loop**.

---

## Defense-in-Depth Architecture

| Security Layer | Module | Enforcement Mechanism |
| :--- | :--- | :--- |
| **Constitutional Seal Guard** | `src/am_ua/governance/seal_guard.py` | Verifies SHA-256 digests over protected files (`constitution/` and `eval/`) before execution and blocks runtime writes outside allowed project/safe-temp boundaries |
| **Static & SAST Scanner (`shield`)** | `src/am_ua/security/agent_shield.py` | Evaluates 15 rules (`SHIELD-SEC-*`, `SHIELD-MCP-*`, `SHIELD-HOOK-*`, `SHIELD-PERM-*`, `SHIELD-SAST-*`) with `A`–`F` risk grading |
| **Pre-Write & Post-Edit AST Hooks** | `src/am_ua/execution/hook_engine.py` | `pre_write_secret_guard` blocks hardcoded API tokens before disk write; `post_python_syntax_check` parses modified `.py` ASTs to catch syntax/undefined-name bugs |
| **Runtime Environment Scrubbing** | `src/am_ua/execution/agent_loop.py` | Strips environment variables matching `(KEY\|TOKEN\|SECRET\|PASSWORD\|PASSWD\|CREDENTIAL\|AUTH)` from workspace `run` subprocesses |
| **Destructive Command Denylist** | `src/am_ua/execution/agent_loop.py` | Blocks destructive storage, shutdown, registry deletion, remote git push, and dynamic shell evaluation commands inside the workspace runner |
| **SSRF Guard & External Tainting** | `src/am_ua/execution/agent_loop.py`, `contracts/contracts.py` | `web_fetch` blocks loopback targets (`localhost` / `127.0.0.1`) and tags external content as `UNTRUSTED_EXTERNAL` |
| **AG-UI & Trace Redaction** | `src/am_ua/cognition/agui_protocol.py` | Redacts sensitive credential keys (`[REDACTED_SECRET]`), rejects non-finite floats, and binds SSE streams strictly to `127.0.0.1` loopback |
| **Adaptive Skill AST Gate & Seal** | `src/am_ua/execution/adaptive_skills.py` | Validates forged Python skill ASTs prior to registration and verifies the file SHA-256 digest before every `run_skill` execution |
| **Sub-Agent Recursion & Concurrency Caps** | `src/am_ua/execution/subagent_bus.py` | Enforces max spawn depth (`2`), max mission agents (`16`), adaptive worker caps (`2–8`), and an exclusive process-wide GUI input lock |
| **Windows DPAPI Secret Vault** | `src/am_ua/security/` | Supports hardware/user-bound DPAPI secret protection on Windows hosts |

---

## Verifying Repository Integrity Locally

Run these checks at any time to confirm that the workspace, constitution manifest, and static security posture remain clean:

```powershell
# Confirm SHA-256 constitutional seal and single-state-owner integrity
.\omni-executor.cmd doctor

# Scan manifests, docs, hooks, and configs across the workspace
.\omni-executor.cmd shield .
```

To run Python SAST checks across a workspace or module directory as well:

```python
from am_ua.security.agent_shield import AgentShieldAuditor

report = AgentShieldAuditor().scan_directory("path/to/workspace", include_source_sast=True)
print(report.grade, len(report.findings))
```

---

## Supported Scope

- Security guarantees apply to the **latest commit on the `master` branch** (`omni-executor` v4.1+).
- Prompt-injection resilience relies on architectural isolation (workspace confinement, deterministic hooks, executable verification oracles, and external taint metadata) rather than trusting LLM prompt instructions alone.

---

## Reporting a Vulnerability

If you discover a sandbox escape, workspace boundary bypass, credential leakage vector, or seal-guard flaw:

1. **Do not open a public GitHub issue** with exploit payloads or live secrets.
2. Document the minimal reproduction steps, affected module path, impact scope, and suggested mitigation.
3. Contact the repository maintainer directly via GitHub (`@juan3861` / private security advisory when enabled on the repository).

We aim to acknowledge credible security reports promptly and ship verified patches with regression tests under `tests/`.
