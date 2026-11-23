"""Code Execution & Transactional Editing Muscle (P4.3 + Sonnet S1 & S2).

Unites:
  1. `CodexSandboxMuscle`: Connects to precompiled Rust `codex.exe mcp-server`,
     `codex-code-mode-host.exe` (V8 Code Mode), and `codex-command-runner.exe`
     (Win32 Restricted Token Sandbox) under `ConstitutionSealGuard`.
  2. `StaticVerificationGate` (Sonnet Upgrade S1): Deterministic SAST + Secret-Leak +
     AST Syntax/Compile gate executed before finalizing any `SafeEditPlan`.
  3. `SafeEditTransactionalJournal`: Atomic SHA-256 preflight + backup + journal +
     rollback over `MSEA SafeEditPlan`, automatically rolling back edits that fail
     `StaticVerificationGate`.
  4. `WorktreeIsolationManager` (Sonnet Upgrade S2): Ephemeral `git worktree` isolation
     in `F:\\AetherMind_Temp\\worktrees` for parallel subagent coding lanes.
  5. `E2BRemoteSandboxAdapter`: Explicit cloud microVM execution contract with honest
     capability/credential reporting (never faking remote runs).
"""

from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from am_ua.governance.seal_guard import ConstitutionSealGuard
from am_ua.perception.polyglot_repomap import MCPStdioClient


def _resolve_node_exe() -> str:
    canonical = r"C:\Program Files\nodejs\node.exe"
    if os.path.isfile(canonical):
        return canonical
    found = shutil.which("node")
    if found:
        return found
    raise FileNotFoundError("Node.js runtime not found for SafeEditTransactionalJournal")


class StaticVerificationError(RuntimeError):
    """Raised when edited code fails SAST, secret-leak, or syntax verification."""


@dataclass
class StaticFinding:
    rule_id: str
    severity: str  # "CRITICAL" | "HIGH" | "MEDIUM"
    file_path: str
    line: int
    message: str


class StaticVerificationGate:
    """Deterministic SAST, Secret-Leak, and Syntax/Compile Verifier (Sonnet S1)."""

    SECRET_PATTERNS = [
        ("SECRET_OPENAI_KEY", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{24,}\b")),
        ("SECRET_AWS_AKIA", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        ("SECRET_GITHUB_PAT", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
        (
            "SECRET_PRIVATE_KEY_PEM",
            re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        ),
    ]

    SQLI_FSTRING_RE = re.compile(
        r"""f["']\s*(?:SELECT|DELETE\s+FROM|UPDATE\s+\w+\s+SET|DROP\s+TABLE)\b[^"']*\{""",
        re.IGNORECASE,
    )

    def __init__(self, *, node_exe: Optional[str] = None) -> None:
        self.node_exe = node_exe or _resolve_node_exe()

    def _scan_secrets_and_sqli(self, rel_path: str, content: str) -> List[StaticFinding]:
        findings: List[StaticFinding] = []
        for lineno, line in enumerate(content.splitlines(), start=1):
            for rule_id, pat in self.SECRET_PATTERNS:
                if pat.search(line):
                    findings.append(
                        StaticFinding(
                            rule_id=rule_id,
                            severity="CRITICAL",
                            file_path=rel_path,
                            line=lineno,
                            message=f"Hardcoded credential/secret pattern detected ({rule_id})",
                        )
                    )
            if self.SQLI_FSTRING_RE.search(line):
                findings.append(
                    StaticFinding(
                        rule_id="SAST_SQL_INJECTION_FSTRING",
                        severity="HIGH",
                        file_path=rel_path,
                        line=lineno,
                        message="Unparameterized f-string SQL query detected",
                    )
                )
        return findings

    def _audit_python_ast(self, rel_path: str, content: str) -> List[StaticFinding]:
        findings: List[StaticFinding] = []
        try:
            tree = ast.parse(content, filename=rel_path)
        except SyntaxError as exc:
            findings.append(
                StaticFinding(
                    rule_id="SYNTAX_ERROR_PYTHON",
                    severity="CRITICAL",
                    file_path=rel_path,
                    line=exc.lineno or 1,
                    message=f"Python SyntaxError: {exc.msg}",
                )
            )
            return findings

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # 1. Detect raw eval/exec on dynamic (non-constant) input
                if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                    if node.args and not isinstance(node.args[0], ast.Constant):
                        findings.append(
                            StaticFinding(
                                rule_id="SAST_DYNAMIC_CODE_EVAL",
                                severity="HIGH",
                                file_path=rel_path,
                                line=node.lineno,
                                message=f"Dynamic `{node.func.id}()` on non-literal expression",
                            )
                        )
                # 2. Detect subprocess.*(..., shell=True) with dynamic command
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    if node.func.value.id == "subprocess" and node.func.attr in (
                        "run",
                        "Popen",
                        "call",
                        "check_output",
                        "check_call",
                    ):
                        shell_true = any(
                            kw.arg == "shell"
                            and isinstance(kw.value, ast.Constant)
                            and kw.value.value is True
                            for kw in node.keywords
                        )
                        if shell_true and node.args and not isinstance(node.args[0], ast.Constant):
                            findings.append(
                                StaticFinding(
                                    rule_id="SAST_SUBPROCESS_SHELL_INJECTION",
                                    severity="CRITICAL",
                                    file_path=rel_path,
                                    line=node.lineno,
                                    message="subprocess call with `shell=True` and dynamic command",
                                )
                            )
                    if node.func.value.id == "pickle" and node.func.attr in ("loads", "load"):
                        findings.append(
                            StaticFinding(
                                rule_id="SAST_UNSAFE_DESERIALIZATION_PICKLE",
                                severity="HIGH",
                                file_path=rel_path,
                                line=node.lineno,
                                message="Unsafe `pickle.load(s)` deserialization",
                            )
                        )
        return findings

    def _audit_js_syntax(self, abs_path: Path, rel_path: str) -> List[StaticFinding]:
        proc = subprocess.run(
            [self.node_exe, "--check", str(abs_path)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=False,
        )
        if proc.returncode != 0:
            return [
                StaticFinding(
                    rule_id="SYNTAX_ERROR_JS",
                    severity="CRITICAL",
                    file_path=rel_path,
                    line=1,
                    message=(proc.stderr or "JS syntax check failed").strip()[:240],
                )
            ]
        return []

    def verify_files(self, root: Path | str, rel_paths: List[str]) -> Dict[str, Any]:
        """Audit a list of edited files inside `root`; return structured SAST/Syntax verdict."""
        base = Path(root).resolve()
        all_findings: List[StaticFinding] = []
        for rel in rel_paths:
            fpath = (base / rel).resolve()
            if not fpath.is_file():
                continue
            content = fpath.read_text(encoding="utf-8", errors="replace")
            all_findings.extend(self._scan_secrets_and_sqli(rel, content))
            ext = fpath.suffix.lower()
            if ext == ".py":
                all_findings.extend(self._audit_python_ast(rel, content))
            elif ext in (".js", ".mjs", ".cjs"):
                all_findings.extend(self._audit_js_syntax(fpath, rel))
            elif ext == ".json":
                try:
                    json.loads(content)
                except json.JSONDecodeError as exc:
                    all_findings.append(
                        StaticFinding(
                            rule_id="SYNTAX_ERROR_JSON",
                            severity="CRITICAL",
                            file_path=rel,
                            line=exc.lineno,
                            message=f"Invalid JSON: {exc.msg}",
                        )
                    )
        blocking = [f for f in all_findings if f.severity in ("CRITICAL", "HIGH")]
        return {
            "ok": len(blocking) == 0,
            "checked_files": list(rel_paths),
            "blocking_count": len(blocking),
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "file": f.file_path,
                    "line": f.line,
                    "message": f.message,
                }
                for f in all_findings
            ],
        }


class SafeEditTransactionalJournal:
    """Transactional file editor combining MSEA SafeEditPlan + SAST StaticVerificationGate."""

    def __init__(
        self,
        workspace_root: Path | str,
        *,
        seal_guard: Optional[ConstitutionSealGuard] = None,
        static_gate: Optional[StaticVerificationGate] = None,
    ) -> None:
        self.workspace_root = Path(workspace_root).resolve()
        self.seal_guard = seal_guard
        self.static_gate = static_gate or StaticVerificationGate()
        self.bridge_script = Path(__file__).resolve().parent / "safe_edit_bridge.mjs"
        self.node_exe = _resolve_node_exe()

    def _call_bridge(self, action: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        from am_ua.contracts.contracts import resolve_omni_temp_dir

        _tmp = str(resolve_omni_temp_dir())
        env = os.environ.copy()
        env["TMP"] = _tmp
        env["TEMP"] = _tmp
        proc = subprocess.run(
            [self.node_exe, str(self.bridge_script)],
            input=json.dumps({"action": action, "payload": payload}),
            text=True,
            encoding="utf-8",
            capture_output=True,
            env=env,
            timeout=30,
            check=False,
        )
        raw = (proc.stdout or "").strip()
        if not raw:
            raise RuntimeError(f"safe_edit_bridge empty output (rc={proc.returncode}): {proc.stderr}")
        parsed = json.loads(raw.splitlines()[-1])
        if proc.returncode != 0 or not parsed.get("ok"):
            raise RuntimeError(
                f"SafeEdit '{action}' failed [{parsed.get('code')}]: {parsed.get('error')}"
            )
        return dict(parsed["result"])

    def apply_verified_plan(
        self,
        operations: List[Dict[str, Any]],
        *,
        plan_id: Optional[str] = None,
        enforce_sast: bool = True,
        actor: str = "agent",
    ) -> Dict[str, Any]:
        """Apply atomic edits, verify via SAST/Syntax gate, and auto-rollback on violation."""
        pid = plan_id or f"plan-{int(time.time() * 1000)}-{uuid.uuid4().hex[:8]}"
        rel_targets: List[str] = []
        for op in operations:
            rel_p = str(op["path"])
            rel_targets.append(rel_p)
            if self.seal_guard is not None:
                self.seal_guard.assert_write_allowed(self.workspace_root / rel_p, actor=actor)

        receipt = self._call_bridge(
            "apply",
            {
                "plan": {
                    "planId": pid,
                    "root": str(self.workspace_root),
                    "operations": operations,
                }
            },
        )
        if enforce_sast:
            verdict = self.static_gate.verify_files(self.workspace_root, rel_targets)
            if not verdict["ok"]:
                rb = self.rollback(receipt["receiptPath"])
                raise StaticVerificationError(
                    f"SAST/Syntax gate rejected plan '{pid}' ({verdict['findings']}); "
                    f"auto-rolled back via {rb['rollbackPath']}"
                )
            receipt["sast_verdict"] = verdict
        return receipt

    def rollback(self, receipt_path: Path | str) -> Dict[str, Any]:
        return self._call_bridge("rollback", {"receiptPath": str(receipt_path)})

    def recover(self, journal_path: Path | str) -> Dict[str, Any]:
        return self._call_bridge("recover", {"journalPath": str(journal_path)})


@dataclass
class IsolatedWorktreeHandle:
    mission_id: str
    lane_id: str
    repo_root: Path
    worktree_path: Path
    branch_name: str
    created_at: float = field(default_factory=time.time)


class WorktreeIsolationManager:
    """Provisions ephemeral `git worktree` sandboxes for parallel subagent lanes (Sonnet S2)."""

    def __init__(self, worktree_base: Optional[Path | str] = None) -> None:
        from am_ua.contracts.contracts import resolve_omni_temp_dir

        self.worktree_base = (
            Path(worktree_base) if worktree_base else resolve_omni_temp_dir("worktrees")
        ).resolve()
        self.worktree_base.mkdir(parents=True, exist_ok=True)
        self.git_exe = shutil.which("git") or "git"

    def _git(self, cwd: Path, args: List[str]) -> subprocess.CompletedProcess[str]:
        from am_ua.contracts.contracts import resolve_omni_temp_dir

        _tmp = str(resolve_omni_temp_dir())
        env = os.environ.copy()
        env["TMP"] = _tmp
        env["TEMP"] = _tmp
        return subprocess.run(
            [self.git_exe, *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            timeout=30,
            check=True,
        )

    def create_lane_worktree(
        self, repo_root: Path | str, *, mission_id: str, lane_id: str
    ) -> IsolatedWorktreeHandle:
        repo = Path(repo_root).resolve()
        safe_mission = re.sub(r"[^A-Za-z0-9_-]", "_", mission_id)[:40]
        safe_lane = re.sub(r"[^A-Za-z0-9_-]", "_", lane_id)[:40]
        wt_dir = self.worktree_base / safe_mission / f"{safe_lane}_{uuid.uuid4().hex[:6]}"
        wt_dir.parent.mkdir(parents=True, exist_ok=True)
        branch = f"am-ua/{safe_mission}/{safe_lane}-{uuid.uuid4().hex[:6]}"
        self._git(repo, ["worktree", "add", "-b", branch, str(wt_dir), "HEAD"])
        return IsolatedWorktreeHandle(
            mission_id=mission_id,
            lane_id=lane_id,
            repo_root=repo,
            worktree_path=wt_dir,
            branch_name=branch,
        )

    def collect_diff(self, handle: IsolatedWorktreeHandle) -> str:
        res = self._git(handle.worktree_path, ["diff", "HEAD"])
        return res.stdout

    def release_worktree(self, handle: IsolatedWorktreeHandle) -> None:
        try:
            self._git(handle.repo_root, ["worktree", "remove", "--force", str(handle.worktree_path)])
        finally:
            try:
                self._git(handle.repo_root, ["branch", "-D", handle.branch_name])
            except Exception:
                pass


class CodexSandboxMuscle:
    """Bridges precompiled Rust `codex-rs` Win32 binaries (`mcp-server`, V8 host, sandbox)."""

    DEFAULT_VENDOR_ROOT = Path(
        r"F:\npm-global\node_modules\@openai\codex\node_modules\@openai\codex-win32-x64\vendor\x86_64-pc-windows-msvc"
    )

    def __init__(
        self,
        vendor_root: Optional[Path | str] = None,
        *,
        seal_guard: Optional[ConstitutionSealGuard] = None,
    ) -> None:
        self.vendor_root = Path(vendor_root or self.DEFAULT_VENDOR_ROOT)
        self.codex_exe = self.vendor_root / "bin" / "codex.exe"
        self.code_mode_host_exe = self.vendor_root / "bin" / "codex-code-mode-host.exe"
        self.command_runner_exe = (
            self.vendor_root / "codex-resources" / "codex-command-runner.exe"
        )
        self.sandbox_setup_exe = (
            self.vendor_root / "codex-resources" / "codex-windows-sandbox-setup.exe"
        )
        self.rg_exe = self.vendor_root / "codex-path" / "rg.exe"
        self.seal_guard = seal_guard or ConstitutionSealGuard()

    def inventory(self) -> Dict[str, Any]:
        bins = {
            "codex_exe": self.codex_exe,
            "code_mode_host_exe": self.code_mode_host_exe,
            "command_runner_exe": self.command_runner_exe,
            "sandbox_setup_exe": self.sandbox_setup_exe,
            "rg_exe": self.rg_exe,
        }
        return {
            name: {"path": str(p), "available": p.is_file(), "bytes": p.stat().st_size if p.is_file() else 0}
            for name, p in bins.items()
        }

    def probe_mcp_server(self, *, timeout_s: float = 30.0) -> Dict[str, Any]:
        """Perform live JSON-RPC 2.0 `initialize` handshake against `codex.exe app-server --stdio`."""
        if not self.codex_exe.is_file():
            return {"ok": False, "reason": f"Missing codex.exe at {self.codex_exe}"}
        client = MCPStdioClient(
            [str(self.codex_exe), "app-server", "--listen", "stdio://"],
            startup_timeout_s=timeout_s,
        )
        try:
            init_info = client.start()
            return {
                "ok": True,
                "user_agent": init_info.get("userAgent", ""),
                "platform_os": init_info.get("platformOs", ""),
                "raw": init_info,
            }
        finally:
            client.close()

    def run_in_sandbox(
        self,
        command_args: List[str],
        *,
        cwd: Optional[Path | str] = None,
        disable_network: bool = False,
        timeout_s: float = 30.0,
    ) -> Dict[str, Any]:
        """Execute command inside Codex Win32 Restricted Token Sandbox (`codex.exe sandbox`)."""
        self.seal_guard.assert_command_safe(" ".join(command_args))
        cmd = [str(self.codex_exe), "sandbox"]
        cmd.extend(command_args)
        from am_ua.contracts.contracts import resolve_omni_temp_dir

        _tmp = str(resolve_omni_temp_dir())
        env = os.environ.copy()
        env["TMP"] = _tmp
        env["TEMP"] = _tmp
        if disable_network:
            env["HTTP_PROXY"] = "http://127.0.0.1:1"
            env["HTTPS_PROXY"] = "http://127.0.0.1:1"
            env["ALL_PROXY"] = "http://127.0.0.1:1"
        resolved_cwd = str(Path(cwd).resolve()) if cwd else None
        proc = subprocess.run(
            cmd,
            cwd=resolved_cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            timeout=timeout_s,
            check=False,
        )
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }


class E2BRemoteSandboxAdapter:
    """Explicit Cloud MicroVM Sandbox Adapter (E2B) with honest credential gating."""

    def __init__(self, api_key: Optional[str] = None) -> None:
        self.api_key = api_key if api_key is not None else os.environ.get("E2B_API_KEY", "")

    def is_configured(self) -> bool:
        return bool(self.api_key and self.api_key.strip())

    def describe_capabilities(self) -> Dict[str, Any]:
        return {
            "adapter": "e2b_cloud_microvm",
            "configured": self.is_configured(),
            "fallback": "local_codex_win32_sandbox",
            "supports": ["python", "node", "bash", "isolated_filesystem"],
        }
