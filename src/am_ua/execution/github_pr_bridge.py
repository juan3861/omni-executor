"""Governed GitHub PR & CI Automation Bridge via `gh` CLI (v13.0).

Provides safe, auditable PR lifecycle operations (`audit_before_pr`, `create_pr`,
`check_pr_ci`, `build_ci_fix_objective`) enforcing `AgentShieldAuditor` and
`PRReviewScorecard` before any remote PR action.

OMNI_TOPOLOGY_V2 compliant (`execution` organ: imports only stdlib + governance/security/execution).
"""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from am_ua.security.agent_shield import AgentShieldAuditor


class GitHubPRBridge:
    """Governed `gh` CLI wrapper for automated PR creation, CI check inspection, and autofix dispatch."""

    def __init__(self, repo_root: Path | str, *, gh_bin: Optional[str] = None) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.gh_bin = gh_bin or shutil.which("gh")

    def is_available(self) -> bool:
        return bool(self.gh_bin)

    def _run_gh(self, args: List[str], *, timeout_s: float = 30.0) -> Dict[str, Any]:
        if not self.gh_bin:
            return {"ok": False, "exit_code": 127, "error": "gh CLI not found on PATH"}
        proc = subprocess.run(
            [self.gh_bin, *args],
            cwd=str(self.repo_root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s,
            check=False,
        )
        return {
            "ok": proc.returncode == 0,
            "exit_code": proc.returncode,
            "stdout": (proc.stdout or "").strip(),
            "stderr": (proc.stderr or "").strip(),
        }

    def audit_before_pr(self, *, base_ref: str = "HEAD~1") -> Dict[str, Any]:
        """Run `AgentShieldAuditor` + git diff summary gate prior to opening or updating a PR."""
        shield = AgentShieldAuditor().scan_directory(self.repo_root)
        diff_proc = subprocess.run(
            ["git", "diff", "--stat", base_ref],
            cwd=str(self.repo_root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
        )
        return {
            "ok": bool(shield.passed),
            "shield_grade": shield.grade,
            "risk_score": shield.risk_score,
            "finding_count": len(shield.findings),
            "diff_stat": (diff_proc.stdout or "").strip()[-1500:],
        }

    def create_pr(
        self,
        *,
        title: str,
        body: str,
        base: str = "master",
        draft: bool = True,
        dry_run: bool = False,
        require_shield_pass: bool = True,
    ) -> Dict[str, Any]:
        """Create a governed GitHub Pull Request after verifying AgentShield passes."""
        audit = self.audit_before_pr() if require_shield_pass else {"ok": True, "shield_grade": "SKIPPED"}
        if require_shield_pass and not audit["ok"]:
            return {
                "ok": False,
                "blocked": True,
                "reason": f"AgentShield blocked PR creation (grade={audit.get('shield_grade')}, findings={audit.get('finding_count')})",
                "audit": audit,
            }
        cmd_args = ["pr", "create", "--title", title, "--body", body, "--base", base]
        if draft:
            cmd_args.append("--draft")
        if dry_run:
            return {
                "ok": True,
                "dry_run": True,
                "gh_available": self.is_available(),
                "command": ["gh", *cmd_args],
                "audit": audit,
            }
        res = self._run_gh(cmd_args, timeout_s=45.0)
        return {**res, "audit": audit}

    def check_pr_ci(self, pr_number: int | str) -> Dict[str, Any]:
        """Inspect GitHub PR CI checks via `gh pr view --json statusCheckRollup`."""
        res = self._run_gh(
            ["pr", "view", str(pr_number), "--json", "number,title,state,statusCheckRollup,headRefName"],
            timeout_s=30.0,
        )
        if not res.get("ok"):
            return res
        try:
            payload = json.loads(res.get("stdout") or "{}")
        except json.JSONDecodeError as exc:
            return {"ok": False, "error": f"Invalid gh JSON output: {exc}"}
        checks = list(payload.get("statusCheckRollup") or [])
        failing = [
            {
                "name": str(c.get("name") or c.get("context") or "check"),
                "conclusion": str(c.get("conclusion") or c.get("state") or ""),
                "details_url": str(c.get("detailsUrl") or c.get("targetUrl") or ""),
            }
            for c in checks
            if str(c.get("conclusion") or c.get("state") or "").upper() in ("FAILURE", "ERROR", "TIMED_OUT", "ACTION_REQUIRED")
        ]
        return {
            "ok": True,
            "pr_number": payload.get("number"),
            "title": payload.get("title"),
            "branch": payload.get("headRefName"),
            "state": payload.get("state"),
            "total_checks": len(checks),
            "failing_checks": failing,
            "all_green": len(failing) == 0,
        }

    @staticmethod
    def build_ci_fix_objective(ci_status: Dict[str, Any]) -> str:
        """Synthesize a crisp, grounded mission objective for fixing failing PR CI checks."""
        pr_num = ci_status.get("pr_number", "?")
        branch = ci_status.get("branch", "current")
        fails = ci_status.get("failing_checks") or []
        fail_names = ", ".join(str(f.get("name")) for f in fails) or "unknown check"
        return (
            f"Fix failing CI checks on PR #{pr_num} (branch '{branch}'): {fail_names}. "
            "Reproduce the failing check locally, apply the minimal verified fix, run pytest + AgentShield, and report evidence."
        )
