"""AgentShield static security auditor (src/am_ua/security/agent_shield.py).

Inspired by ECC AgentShield; audits workspace agent configs, MCP manifests,
hooks, and source/env files for leaked secrets, unsafe MCP servers,
hook-injection vectors, and overly permissive tool policies.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


@dataclass(frozen=True)
class ShieldFinding:
    rule_id: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    category: str  # secret | mcp | hook_injection | permission
    file: str
    line: int
    message: str
    remediation: str


@dataclass
class ShieldScanReport:
    target_root: str
    files_scanned: int
    risk_score: int
    grade: str
    passed: bool
    findings: List[ShieldFinding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_root": self.target_root,
            "files_scanned": self.files_scanned,
            "risk_score": self.risk_score,
            "grade": self.grade,
            "passed": self.passed,
            "finding_count": len(self.findings),
            "findings": [asdict(f) for f in self.findings],
        }


_SEVERITY_WEIGHT = {"CRITICAL": 30, "HIGH": 15, "MEDIUM": 5, "LOW": 1}

_SECRET_PATTERNS: Tuple[Tuple[str, str, re.Pattern[str]], ...] = (
    ("SHIELD-SEC-001", "CRITICAL", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("SHIELD-SEC-002", "CRITICAL", re.compile(r"\bgsk_[A-Za-z0-9]{20,}\b")),
    ("SHIELD-SEC-003", "CRITICAL", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b")),
    ("SHIELD-SEC-004", "CRITICAL", re.compile(r"\bAIza[0-9A-Za-z\-_]{25,}\b")),
    ("SHIELD-SEC-005", "HIGH", re.compile(r"(?i)\b(?:api_key|secret_key|auth_token|password)\s*[:=]\s*['\"][A-Za-z0-9_\-./+=]{12,}['\"]")),
)

_INJECTION_PATTERNS: Tuple[Tuple[str, str, str, re.Pattern[str]], ...] = (
    (
        "SHIELD-HOOK-001",
        "CRITICAL",
        "Pipe-to-shell remote execution in config/hook",
        re.compile(r"(?i)(?:curl|wget|irm)\s+[^\n|]+\|\s*(?:bash|sh|pwsh|powershell|iex)"),
    ),
    (
        "SHIELD-HOOK-002",
        "HIGH",
        "Dynamic shell/eval execution in hook or manifest",
        re.compile(r"(?i)(?:Invoke-Expression|\biex\s*\(|--no-verify\b)"),
    ),
)

_PERM_PATTERNS: Tuple[Tuple[str, str, str, re.Pattern[str]], ...] = (
    (
        "SHIELD-PERM-001",
        "HIGH",
        "Dangerous permission bypass flag detected",
        re.compile(r"(?i)\"(?:allow_all|bypass_seal|skip_verification|dangerouslySkipPermissions)\"\s*:\s*true"),
    ),
)

_SAST_CODE_PATTERNS: Tuple[Tuple[str, str, str, re.Pattern[str]], ...] = (
    ("SHIELD-SAST-001", "HIGH", "Unsafe deserialization via pickle.loads (CWE-502)", re.compile(r"\bpickle\.loads?\s*\(")),
    ("SHIELD-SAST-002", "HIGH", "YAML deserialization without SafeLoader (CWE-502)", re.compile(r"\byaml\.load\s*\([^)]*\)")),
    ("SHIELD-SAST-003", "MEDIUM", "TLS verification disabled via verify=False (CWE-295)", re.compile(r"\bverify\s*=\s*False\b")),
    ("SHIELD-SAST-004", "HIGH", "Subprocess invocation with shell=True (CWE-78)", re.compile(r"\bsubprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True")),
    ("SHIELD-SAST-005", "HIGH", "Dynamic code execution via eval()/exec() (CWE-95)", re.compile(r"(?<!\.)\b(?:eval|exec)\s*\(")),
)

_SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "node_modules", ".venv", "venv", "third_party", "vendor", "data"}
_SCAN_EXTS = {".json", ".yaml", ".yml", ".toml", ".env", ".cmd", ".ps1", ".sh", ".md"}
_CODE_EXTS = {".py", ".js", ".ts"}


class AgentShieldAuditor:
    """Static security auditor for AI agent harnesses, MCP configs, and hooks."""

    def scan_text(self, text: str, *, rel_path: str = "<memory>") -> List[ShieldFinding]:
        findings: List[ShieldFinding] = []
        lines = text.splitlines()
        for idx, line in enumerate(lines, 1):
            for rule_id, sev, rx in _SECRET_PATTERNS:
                if rx.search(line):
                    findings.append(
                        ShieldFinding(
                            rule_id=rule_id,
                            severity=sev,
                            category="secret",
                            file=rel_path,
                            line=idx,
                            message="Potential hardcoded secret or API token detected",
                            remediation="Move credentials to environment variables or DPAPI secret store.",
                        )
                    )
            for rule_id, sev, msg, rx in _INJECTION_PATTERNS:
                if rx.search(line):
                    findings.append(
                        ShieldFinding(
                            rule_id=rule_id,
                            severity=sev,
                            category="hook_injection",
                            file=rel_path,
                            line=idx,
                            message=msg,
                            remediation="Avoid remote pipe-to-shell or dynamic eval in hooks/configs.",
                        )
                    )
            for rule_id, sev, msg, rx in _PERM_PATTERNS:
                if rx.search(line):
                    findings.append(
                        ShieldFinding(
                            rule_id=rule_id,
                            severity=sev,
                            category="permission",
                            file=rel_path,
                            line=idx,
                            message=msg,
                            remediation="Enforce least-privilege tool allowlists and keep seals enabled.",
                        )
                    )
            if Path(rel_path).suffix.lower() in _CODE_EXTS:
                for rule_id, sev, msg, rx in _SAST_CODE_PATTERNS:
                    if rx.search(line):
                        if rule_id == "SHIELD-SAST-002" and "SafeLoader" in line:
                            continue
                        findings.append(
                            ShieldFinding(
                                rule_id=rule_id,
                                severity=sev,
                                category="sast",
                                file=rel_path,
                                line=idx,
                                message=msg,
                                remediation="Replace unsafe sink with parameterized/safe API or SafeLoader.",
                            )
                        )
        if rel_path.lower().endswith(".json"):
            findings.extend(self._audit_mcp_json(text, rel_path=rel_path))
        return findings

    @staticmethod
    def _audit_mcp_json(text: str, *, rel_path: str) -> List[ShieldFinding]:
        out: List[ShieldFinding] = []
        try:
            data = json.loads(text)
        except Exception:
            return out
        if not isinstance(data, dict):
            return out
        servers = data.get("mcpServers") or data.get("mcp_servers")
        if not isinstance(servers, dict):
            return out
        for name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            cmd = str(cfg.get("command", "")).strip().lower()
            args = [str(a) for a in (cfg.get("args") or [])]
            url = str(cfg.get("url", "")).strip()
            if cmd in ("npx", "npx.cmd") and args:
                pkg_args = [a for a in args if not a.startswith("-")]
                if pkg_args and "@" not in pkg_args[0].lstrip("@"):
                    out.append(
                        ShieldFinding(
                            rule_id="SHIELD-MCP-001",
                            severity="MEDIUM",
                            category="mcp",
                            file=rel_path,
                            line=1,
                            message=f"MCP server '{name}' uses unpinned npx package '{pkg_args[0]}'",
                            remediation="Pin an explicit package version (e.g. pkg@1.2.3) to prevent supply-chain drift.",
                        )
                    )
            if url.lower().startswith("http://") and not any(h in url.lower() for h in ("localhost", "127.0.0.1")):
                out.append(
                    ShieldFinding(
                        rule_id="SHIELD-MCP-002",
                        severity="HIGH",
                        category="mcp",
                        file=rel_path,
                        line=1,
                        message=f"MCP server '{name}' uses unencrypted remote HTTP URL: {url}",
                        remediation="Use HTTPS/TLS for remote MCP transports.",
                    )
                )
        return out

    def scan_directory(self, root: Path | str, *, max_files: int = 400, include_source_sast: bool = False) -> ShieldScanReport:
        base = Path(root).resolve()
        findings: List[ShieldFinding] = []
        scanned = 0
        allowed_exts = _SCAN_EXTS | (_CODE_EXTS if include_source_sast else set())
        for p in base.rglob("*"):
            if scanned >= max_files:
                break
            if any(part in _SKIP_DIRS for part in p.parts):
                continue
            if not p.is_file():
                continue
            if p.suffix.lower() not in allowed_exts and not p.name.startswith(".env"):
                continue
            try:
                if p.stat().st_size > 256_000:
                    continue
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            scanned += 1
            rel = str(p.relative_to(base)).replace("\\", "/")
            findings.extend(self.scan_text(text, rel_path=rel))

        score = min(100, sum(_SEVERITY_WEIGHT.get(f.severity, 1) for f in findings))
        grade = "A" if score == 0 else ("B" if score <= 15 else ("C" if score <= 35 else ("D" if score <= 60 else "F")))
        passed = not any(f.severity in ("CRITICAL", "HIGH") for f in findings)
        return ShieldScanReport(
            target_root=str(base),
            files_scanned=scanned,
            risk_score=score,
            grade=grade,
            passed=passed,
            findings=findings,
        )

    @staticmethod
    def prove_policy_containment(
        baseline_policy: Dict[str, Any],
        candidate_policy: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Formally prove that `candidate_policy` does not weaken `baseline_policy` invariants."""
        violations: List[str] = []

        def _norm_set(policy: Dict[str, Any], key: str) -> set[str]:
            val = policy.get(key) or []
            return {str(x).strip() for x in val if str(x).strip()}

        for list_key in (
            "self_modification_forbidden_prefixes",
            "untouchable_external_paths",
            "forbidden_cli_flags",
        ):
            base_items = _norm_set(baseline_policy, list_key)
            cand_items = _norm_set(candidate_policy, list_key)
            missing = sorted(base_items - cand_items)
            if missing:
                violations.append(f"{list_key} removed protected entries: {missing}")

        # Safety booleans that must remain False when baseline is False
        for must_stay_false in ("allow_remote_git_push", "allow_blind_rpa"):
            base_val = bool(baseline_policy.get(must_stay_false, False))
            cand_val = bool(candidate_policy.get(must_stay_false, False))
            if not base_val and cand_val:
                violations.append(f"{must_stay_false} weakened from False to True")

        # Safety booleans that must remain True when baseline is True
        for must_stay_true in ("actor_cannot_be_own_judge",):
            base_val = bool(baseline_policy.get(must_stay_true, True))
            cand_val = bool(candidate_policy.get(must_stay_true, True))
            if base_val and not cand_val:
                violations.append(f"{must_stay_true} weakened from True to False")

        return {
            "contained": len(violations) == 0,
            "violations": violations,
            "checked_invariants": 6,
        }
