"""Interactive Streaming Terminal TUI for OmniExecutor (`omni chat` — v9.0 Fase 4)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from am_ua.execution.deterministic_offloader import DeterministicTaskOffloader
from am_ua.execution.parametric_playbooks import DEFAULT_PLAYBOOK_ENGINE
from am_ua.governance.homeostasis import HomeostasisGovernor
from am_ua.security.agent_shield import AgentShieldAuditor


class OmniTUI:
    """Zero-dependency interactive terminal console with slash commands & diff approval."""

    SLASH_COMMANDS = ("/cost", "/budget", "/playbook", "/rails", "/shield", "/compact", "/undo", "/help", "/exit")

    def __init__(
        self,
        workspace: Path | str,
        *,
        governor: Optional[HomeostasisGovernor] = None,
        auto_approve: bool = False,
        mission_fn: Optional[Callable[[str], Dict[str, Any]]] = None,
    ) -> None:
        self.ws = Path(workspace).resolve()
        self.governor = governor or HomeostasisGovernor()
        self.auto_approve = auto_approve
        self.mission_fn = mission_fn
        self.history: List[Dict[str, str]] = []

    def confirm_diff(self, file_path: str, diff_preview: str, *, input_fn: Callable[[str], str] = input) -> str:
        """Render diff preview and prompt `[y/n/a/e]` unless `--yolo` (`auto_approve`) is enabled."""
        if self.auto_approve:
            return "y"
        print(f"\n--- Diff Preview: {file_path} ---\n{diff_preview[:1500]}")
        ans = input_fn("Apply patch? [y]es / [n]o / [a]ll (--yolo) / [e]dit: ").strip().lower() or "n"
        if ans == "a":
            self.auto_approve = True
            return "y"
        return ans

    def handle_line(self, line: str) -> Dict[str, Any]:
        """Handle a slash command or user mission prompt deterministically."""
        cmd = (line or "").strip()
        if not cmd:
            return {"ok": True, "action": "noop"}

        if cmd in ("/exit", "/quit"):
            return {"ok": True, "action": "exit"}

        if cmd == "/help":
            return {"ok": True, "action": "help", "commands": list(self.SLASH_COMMANDS)}

        if cmd == "/cost":
            return {
                "ok": True,
                "action": "cost",
                "budget_mode": self.governor.budget_mode,
                "max_cost_usd": self.governor.max_cost_usd,
                "cost_usd_spent": round(self.governor.cost_usd_spent, 6),
                "tokens_spent": self.governor._tokens_spent,
            }

        if cmd.startswith("/budget"):
            parts = cmd.split(maxsplit=1)
            arg = parts[1].strip().lower() if len(parts) > 1 else "off"
            if arg in ("off", "free", "on_demand"):
                res = self.governor.set_budget_mode("on_demand", None)
            else:
                res = self.governor.set_budget_mode("fixed", float(arg))
            return {"ok": True, "action": "budget", **res}

        if cmd.startswith("/playbook"):
            parts = cmd.split(maxsplit=1)
            domain = parts[1].strip() if len(parts) > 1 else None
            return {
                "ok": True,
                "action": "playbook_list",
                "playbooks": DEFAULT_PLAYBOOK_ENGINE.list_playbooks(domain=domain),
            }

        if cmd == "/rails":
            caps = DeterministicTaskOffloader.probe_capabilities()
            return {"ok": True, "action": "rails", "count": len(caps.get("rails", [])), "capabilities": caps}

        if cmd == "/shield":
            rep = AgentShieldAuditor().scan_directory(self.ws)
            return {"ok": True, "action": "shield", **rep.to_dict()}

        if cmd == "/compact":
            kept = self.history[-4:] if len(self.history) > 4 else list(self.history)
            dropped = len(self.history) - len(kept)
            self.history = kept
            return {"ok": True, "action": "compact", "dropped_turns": dropped, "remaining_turns": len(self.history)}

        if cmd == "/undo":
            return {"ok": True, "action": "undo", "note": "Use WorkspaceTools.restore_checkpoint to revert last snapshot."}

        self.history.append({"role": "user", "content": cmd})
        if self.mission_fn is not None:
            res = self.mission_fn(cmd)
            self.history.append({"role": "assistant", "content": str(res.get("final_summary") or res.get("status") or "done")})
            return {"ok": bool(res.get("ok", True)), "action": "mission", "result": res}
        return {"ok": True, "action": "prompt_queued", "prompt": cmd}

    def run_repl(self, *, input_fn: Callable[[str], str] = input) -> int:
        print(f"OmniExecutor TUI ({self.ws}) — type /help or /exit")
        while True:
            try:
                line = input_fn("omni> ")
            except (EOFError, KeyboardInterrupt):
                break
            out = self.handle_line(line)
            if out.get("action") == "exit":
                break
            if out.get("action") != "noop":
                print(json.dumps(out, indent=2, ensure_ascii=False, default=str))
        return 0
