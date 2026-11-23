"""Workspace-confined tool surface for AgentLoop (extracted in v8.0 for modularity).

Part of the Execution Organ (OMNI_TOPOLOGY_V2 compliant).
All paths are resolved against the workspace boundary and checked against
symlinks and `ConstitutionSealGuard`.
"""

from __future__ import annotations

import ast
import gzip
import hashlib
import ipaddress
import json
import math
import os
import re
import socket
import subprocess
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from am_ua.cognition.llm_client import LLMClient
from am_ua.execution.adaptive_skills import AdaptiveSkillForge
from am_ua.execution.hook_engine import DeterministicHookEngine
from am_ua.execution.loop_prompts_and_scopes import (
    DANGEROUS_CMD_RE,
    SKIP_DIRS,
    clip,
    scrubbed_env,
)
from am_ua.execution.mcp_federation import MCPFederationHub
from am_ua.execution.pc_automation import PCAutomationEngine
from am_ua.execution.subagent_bus import SubAgentSessionBus
from am_ua.governance.seal_guard import ConstitutionSealGuard, ConstitutionalViolationError


class WorkspaceTools:
    """Tools confined to one workspace directory. Paths that escape the workspace are rejected."""

    def __init__(
        self,
        workspace: Path,
        seal_guard: ConstitutionSealGuard,
        *,
        cmd_timeout_s: float = 120.0,
        pc_engine: Optional[PCAutomationEngine] = None,
        skill_forge: Optional[AdaptiveSkillForge] = None,
        llm_client: Optional[LLMClient] = None,
        subagent_bus: Optional[SubAgentSessionBus] = None,
        mcp_hub: Optional[MCPFederationHub] = None,
        browser_factory: Optional[Callable[[bool], Any]] = None,
        hook_engine: Optional[DeterministicHookEngine] = None,
        repo_mapper_factory: Optional[Callable[[Path], Any]] = None,
        knowledge_factory: Optional[Callable[[Path], Any]] = None,
    ) -> None:
        self.ws = workspace.resolve()
        self.seal_guard = seal_guard
        self.cmd_timeout_s = cmd_timeout_s
        self._pc_engine = pc_engine or PCAutomationEngine()
        self._skill_forge = skill_forge or AdaptiveSkillForge()
        self._llm = llm_client
        self._subagent_bus = subagent_bus
        self._mcp_hub = mcp_hub
        self._browser_factory = browser_factory
        self._repo_mapper_factory = repo_mapper_factory
        self._knowledge_factory = knowledge_factory
        self._browser: Any = None
        self._checkpoints: Dict[str, Dict[str, bytes]] = {}
        self._task_list: List[Dict[str, str]] = []
        self._io_lock = threading.RLock()
        # Workspace itself must be a constitutionally writable location (project root or safe temp root).
        self.seal_guard.assert_write_allowed(self.ws / ".am_probe", actor="agent_loop")

    def resolve(self, rel: str) -> Path:
        raw_req = Path(rel)
        raw_p = (self.ws / raw_req) if not raw_req.is_absolute() else raw_req
        if not raw_req.is_absolute():
            cur = self.ws
            for part in raw_req.parts:
                if part in ("", "."):
                    continue
                cur = cur / part
                if cur.is_symlink():
                    raise ConstitutionalViolationError(f"Symlink escapes workspace boundary check: {rel}")
        if raw_p.is_symlink():
            raise ConstitutionalViolationError(f"Symlink escapes workspace boundary check: {rel}")
        p = raw_p.resolve()
        if p != self.ws and self.ws not in p.parents:
            raise ConstitutionalViolationError(f"Path escapes workspace: {rel}")
        return p

    # ---- tools (all return JSON-serializable dicts)
    def list_dir(self, args: Dict[str, Any]) -> Dict[str, Any]:
        base = self.resolve(str(args.get("path", ".")))
        depth = min(int(args.get("depth", 2)), 4)
        out: List[str] = []
        for root, dirs, files in os.walk(base):
            rel_root = Path(root).relative_to(base)
            if len(rel_root.parts) >= depth:
                dirs[:] = []
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
            for f in sorted(files):
                out.append(str((rel_root / f).as_posix()))
                if len(out) >= 400:
                    return {"entries": out, "truncated": True}
        return {"entries": out, "truncated": False}

    def read_file(self, args: Dict[str, Any]) -> Dict[str, Any]:
        p = self.resolve(str(args["file"]))
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(1, int(args.get("start_line", 1)))
        end = min(len(lines), int(args.get("end_line", start + 399)))
        numbered = "\n".join(f"{i}: {lines[i - 1]}" for i in range(start, end + 1))
        return {"file": args["file"], "total_lines": len(lines), "content": clip(numbered)}

    def search(self, args: Dict[str, Any]) -> Dict[str, Any]:
        pat_str = str(args["pattern"])
        base = self.resolve(str(args.get("path", ".")))
        if args.get("prefer_native", True):
            from am_ua.execution.native_backends import NativeBackendRouter

            native_res = NativeBackendRouter.ripgrep_search(self.ws, pat_str, target=base, max_hits=200)
            if native_res is not None:
                return native_res

        pattern = re.compile(pat_str)
        hits: List[str] = []
        for root, dirs, files in os.walk(base):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for f in files:
                fp = Path(root) / f
                if fp.stat().st_size > 1_000_000:
                    continue
                try:
                    for n, line in enumerate(fp.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                        if pattern.search(line):
                            hits.append(f"{fp.relative_to(self.ws).as_posix()}:{n}: {line.strip()[:200]}")
                            if len(hits) >= 200:
                                return {"hits": hits, "truncated": True, "backend": "python_regex"}
                except OSError:
                    continue
        return {"hits": hits, "truncated": False, "backend": "python_regex"}

    @staticmethod
    def _strip_fences(content: str) -> str:
        from am_ua.execution.workspace_fs import strip_code_fences

        return strip_code_fences(content)

    @staticmethod
    def _post_edit_diagnostics(p: Path) -> Dict[str, Any]:
        """Run immediate deterministic AST/JSON syntax verification right after file mutation."""
        ext = p.suffix.lower()
        if ext == ".py":
            import ast

            try:
                ast.parse(p.read_text(encoding="utf-8", errors="replace"), filename=str(p))
                return {"ok": True, "kind": "python_ast", "errors": []}
            except SyntaxError as exc:
                return {
                    "ok": False,
                    "kind": "python_ast",
                    "errors": [{"line": exc.lineno or 0, "col": exc.offset or 0, "msg": exc.msg}],
                }
        if ext == ".json":
            try:
                json.loads(p.read_text(encoding="utf-8", errors="replace"))
                return {"ok": True, "kind": "json", "errors": []}
            except json.JSONDecodeError as exc:
                return {
                    "ok": False,
                    "kind": "json",
                    "errors": [{"line": exc.lineno, "col": exc.colno, "msg": exc.msg}],
                }
        return {"ok": True, "kind": "none", "errors": []}

    def write_file(self, args: Dict[str, Any]) -> Dict[str, Any]:
        p = Path(str(args["path"]))  # already absolute + gate-checked by LastMileSecurityGate
        p.parent.mkdir(parents=True, exist_ok=True)
        content = self._strip_fences(str(args["content"]))
        p.write_text(content, encoding="utf-8", newline="\n")
        return {
            "written": p.relative_to(self.ws).as_posix(),
            "bytes": p.stat().st_size,
            "post_edit_diagnostics": self._post_edit_diagnostics(p),
        }

    def replace_in_file(self, args: Dict[str, Any]) -> Dict[str, Any]:
        from am_ua.execution.workspace_fs import apply_hunks_safely

        p = Path(str(args["path"]))
        text = p.read_text(encoding="utf-8")
        raw_hunks = args.get("hunks")
        if isinstance(raw_hunks, list) and raw_hunks:
            hunks: List[Tuple[str, str]] = []
            for h in raw_hunks:
                if not isinstance(h, dict):
                    raise ValueError("each entry in 'hunks' must be an object with 'old' and 'new'")
                h_old = str(h.get("old", h.get("old_str", "")))
                h_new = str(h.get("new", h.get("new_str", "")))
                hunks.append((h_old, h_new))
        else:
            if "old" not in args or "new" not in args:
                raise ValueError("replace_in_file requires ('old', 'new') or non-empty 'hunks'")
            hunks = [(str(args["old"]), str(args["new"]))]

        try:
            working, syn_err = apply_hunks_safely(text, hunks, is_python=(p.suffix == ".py"))
        except ValueError:
            if len(hunks) != 1:
                raise
            from am_ua.execution.apex_codeact_fuzzy import AiderFuzzySearchReplaceEngine

            fuzzy = AiderFuzzySearchReplaceEngine.apply_search_replace(
                self.ws,
                file_path=str(p.relative_to(self.ws).as_posix()),
                search_block=hunks[0][0],
                replace_block=hunks[0][1],
                apply=True,
            )
            if not fuzzy.get("ok"):
                raise ValueError(str(fuzzy.get("error") or "Fuzzy search/replace did not match"))
            res_f: Dict[str, Any] = {
                "replaced_in": p.relative_to(self.ws).as_posix(),
                "hunks_applied": 1,
                "match_level": fuzzy.get("match_level"),
                "fuzzy_healed": True,
            }
            return res_f
        p.write_text(working, encoding="utf-8", newline="\n")
        res: Dict[str, Any] = {
            "replaced_in": p.relative_to(self.ws).as_posix(),
            "hunks_applied": len(hunks),
            "post_edit_diagnostics": self._post_edit_diagnostics(p),
        }
        if syn_err:
            res["syntax_error"] = syn_err
        return res

    def cpg_impact(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Query Code Property Graph (AST+CFG+Dataflow/Taint) & SCIP index over the workspace."""
        from am_ua.perception.code_property_graph import CodePropertyGraphBuilder, SCIPIndexStore

        action = str(args.get("action", "summary")).strip().lower()
        symbol = str(args.get("symbol", "")).strip()
        if action == "scip_build":
            out_rel = args.get("out_path")
            out_p = self.resolve(str(out_rel)) if out_rel else None
            return SCIPIndexStore(self.ws).build_and_save(out_p, max_files=int(args.get("max_files", 500)))
        cpg = CodePropertyGraphBuilder(self.ws).build(max_files=int(args.get("max_files", 500)))
        if action == "summary":
            return {"ok": True, **cpg.to_summary()}
        if not symbol:
            return {"ok": False, "error": f"symbol is required for cpg_impact action={action!r}"}
        if action == "goto_definition":
            return {"ok": True, "symbol": symbol, "definitions": cpg.goto_definition(symbol)}
        if action == "find_references":
            return {"ok": True, "symbol": symbol, "references": cpg.find_references(symbol)}
        if action == "taint":
            direction = str(args.get("direction", "forward")).strip().lower()
            return {"ok": True, **cpg.trace_taint_slice(symbol, direction=direction)}
        return {"ok": True, **cpg.impact_analysis(symbol)}

    _TASK_STATUS_ALIASES = {
        "pending": "todo",
        "to_do": "todo",
        "open": "todo",
        "in-progress": "in_progress",
        "working": "in_progress",
        "active": "in_progress",
        "completed": "done",
        "complete": "done",
        "finished": "done",
    }

    def task_tracker(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Track structured mission subtasks (`view` / `plan`) with status alias normalization."""
        cmd = str(args.get("command", "view")).strip().lower()
        if cmd not in ("view", "plan"):
            raise ValueError(f"Unsupported task_tracker command: {cmd!r}")
        if cmd == "plan":
            raw_list = args.get("task_list")
            if not isinstance(raw_list, list):
                raise ValueError("'task_list' must be a list when command='plan'")
            normalized: List[Dict[str, str]] = []
            for item in raw_list:
                if not isinstance(item, dict) or not str(item.get("title", "")).strip():
                    raise ValueError("each task_list item must have a non-empty 'title'")
                raw_st = str(item.get("status", "todo")).strip().lower().replace("-", "_").replace(" ", "_")
                st = raw_st if raw_st in ("todo", "in_progress", "done") else self._TASK_STATUS_ALIASES.get(raw_st)
                if st is None:
                    raise ValueError(f"Invalid task status: {item.get('status')!r}")
                normalized.append({
                    "title": str(item["title"]).strip()[:200],
                    "notes": str(item.get("notes", "")).strip()[:500],
                    "status": st,
                })
            self._task_list = normalized
        return {
            "ok": True,
            "command": cmd,
            "count": len(self._task_list),
            "tasks": list(self._task_list),
        }

    def run(self, args: Dict[str, Any]) -> Dict[str, Any]:
        from am_ua.execution.openhands_organs import ShellSemanticPolicyRails

        cmd = str(args["command"]).strip()
        if DANGEROUS_CMD_RE.search(cmd):
            raise ConstitutionalViolationError(f"Command blocked by agent denylist: {cmd[:120]}")
        policy_verdict = ShellSemanticPolicyRails.analyze_command(cmd)
        if not policy_verdict.get("ok") and policy_verdict.get("risk") == "HIGH":
            raise ConstitutionalViolationError(
                f"Command blocked by ShellSemanticPolicyRails ({policy_verdict.get('matched_rail')}): {policy_verdict.get('reason')}"
            )
        timeout = min(float(args.get("timeout_s", self.cmd_timeout_s)), 600.0)
        sandbox_mode = str(args.get("sandbox") or ("hermetic" if args.get("hermetic") else "")).strip().lower()
        if sandbox_mode == "hermetic":
            from am_ua.execution.hermetic_sandbox_bridge import HermeticSandboxBridge

            return HermeticSandboxBridge().run_command(cmd, timeout_s=timeout)
        if sandbox_mode == "docker":
            import shutil

            docker_bin = shutil.which("docker")
            if not docker_bin:
                return {"exit_code": 127, "output": "docker binary not found on host", "elapsed_s": 0.0}
            t0_d = time.perf_counter()
            d_proc = subprocess.run(
                [docker_bin, "run", "--rm", "--network=none", "-v", f"{self.ws}:/ws", "-w", "/ws", "python:3.11-slim", "sh", "-lc", cmd],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
            )
            d_out = (d_proc.stdout or "") + (("\n[stderr]\n" + d_proc.stderr) if d_proc.stderr else "")
            return {"exit_code": d_proc.returncode, "output": clip(str(d_out)), "elapsed_s": round(time.perf_counter() - t0_d, 2), "sandbox": "docker"}
        # In PowerShell, invoking a quoted path requires the call operator '&'
        if os.name == "nt":
            if cmd.startswith(('"', "'")) and not cmd.startswith("&"):
                cmd = f"& {cmd}"
            argv = ["pwsh", "-NoProfile", "-NonInteractive", "-Command", cmd]
        else:
            argv = ["bash", "-lc", cmd]
        t0 = time.perf_counter()
        try:
            proc = subprocess.run(
                argv,
                cwd=str(self.ws), env=scrubbed_env(), capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=timeout,
            )
            code, out = proc.returncode, (proc.stdout or "") + (("\n[stderr]\n" + proc.stderr) if proc.stderr else "")
        except subprocess.TimeoutExpired as exc:
            code, out = 124, f"TIMEOUT after {timeout}s\n{(exc.stdout or '')}"
        return {"exit_code": code, "output": clip(str(out)), "elapsed_s": round(time.perf_counter() - t0, 2)}

    # ---- PC Automation & Adaptive Skill Tools
    def pc_observe(self, args: Dict[str, Any]) -> Dict[str, Any]:
        hwnd = args.get("hwnd")
        window_title = args.get("window_title") or args.get("title")
        include_ocr = bool(args.get("include_ocr", True))
        max_elements = min(int(args.get("max_elements", 60)), 120)
        return self._pc_engine.observe_desktop(
            hwnd=int(hwnd) if hwnd is not None else None,
            window_title=str(window_title) if window_title else None,
            include_ocr=include_ocr,
            max_elements=max_elements,
        )

    def pc_ground_vlm(self, args: Dict[str, Any]) -> Dict[str, Any]:
        target_desc = str(args.get("target") or args.get("description") or "")
        if not target_desc:
            return {"ok": False, "error": "target description is required"}
        window_title = args.get("window_title") or args.get("title")
        return self._pc_engine.ground_with_vlm(
            target_desc,
            self._llm,
            refresh=bool(args.get("refresh", True)),
            window_title=str(window_title) if window_title else None,
        )

    def pc_act(self, args: Dict[str, Any]) -> Dict[str, Any]:
        action_type = str(args.get("action_type", "click"))
        return self._pc_engine.execute_gui_action(
            action_type,
            tag_id=int(args["tag_id"]) if args.get("tag_id") is not None else None,
            target=str(args["target"]) if args.get("target") else None,
            x=int(args["x"]) if args.get("x") is not None else None,
            y=int(args["y"]) if args.get("y") is not None else None,
            norm_x=float(args["norm_x"]) if args.get("norm_x") is not None else None,
            norm_y=float(args["norm_y"]) if args.get("norm_y") is not None else None,
            text=str(args["text"]) if args.get("text") is not None else None,
            keys=args.get("keys"),
            scroll_clicks=int(args.get("scroll_clicks", 0)),
            button=str(args.get("button", "left")),
            dry_run=bool(args.get("dry_run", False)),
        )

    def pc_window(self, args: Dict[str, Any]) -> Dict[str, Any]:
        action = str(args.get("action", "list")).lower().strip()
        if action == "list":
            filt = str(args.get("filter", args.get("locator", "")))
            return {"ok": True, "windows": self._pc_engine.window_organ.list_windows(filt, limit=60)}
        if action == "active":
            return {"ok": True, "active_window": self._pc_engine.window_organ.get_active_window()}
        if action == "find":
            loc = str(args.get("locator", ""))
            return {"ok": True, "windows": self._pc_engine.window_organ.find_windows_by_locator(loc)}
        if action == "launch":
            cmd_val = args.get("app_cmd") or args.get("cmd")
            if not cmd_val:
                return {"ok": False, "error": "launch requires 'app_cmd'"}
            if DANGEROUS_CMD_RE.search(str(cmd_val)):
                raise ConstitutionalViolationError(f"Blocked dangerous launch cmd: {str(cmd_val)[:120]}")
            return self._pc_engine.window_organ.launch_isolated_app(
                cmd_val, cwd=self.ws, wait_for_window_s=float(args.get("wait_s", 2.0))
            )
        if action == "cleanup":
            return {"ok": True, **self._pc_engine.window_organ.cleanup_spawned_apps()}
        loc = str(args.get("locator", args.get("title", "")))
        rect_raw = args.get("rect")
        rect = tuple(int(v) for v in rect_raw[:4]) if isinstance(rect_raw, list) and len(rect_raw) >= 4 else None
        return self._pc_engine.window_organ.control_window(loc, action=action, rect=rect)  # type: ignore[arg-type]

    def pc_clipboard(self, args: Dict[str, Any]) -> Dict[str, Any]:
        action = str(args.get("action", "get")).lower().strip()
        if action == "set":
            txt = str(args.get("text", ""))
            ok = self._pc_engine.clipboard.set_text(txt)
            return {"ok": ok, "length": len(txt)}
        val = self._pc_engine.clipboard.get_text()
        return {"ok": True, "text": clip(val, 4000)}

    def pc_process(self, args: Dict[str, Any]) -> Dict[str, Any]:
        action = str(args.get("action", "list")).lower().strip()
        if action == "port_owner":
            return self._pc_engine.window_organ.find_port_owner(int(args.get("port", 80)))
        filt = str(args.get("filter", ""))
        return {"ok": True, "processes": self._pc_engine.window_organ.list_processes(filt, limit=40)}

    def skill_forge(self, args: Dict[str, Any]) -> Dict[str, Any]:
        return self._skill_forge.forge_skill(
            name=str(args["name"]),
            description=str(args.get("description", "")),
            code=str(args["code"]),
            tags=args.get("tags"),
            test_kwargs=args.get("test_kwargs"),
        )

    def skill_run(self, args: Dict[str, Any]) -> Dict[str, Any]:
        action = str(args.get("action", "run")).lower().strip()
        if action == "list":
            return {"ok": True, "skills": self._skill_forge.list_skills()}
        if action == "search":
            return {"ok": True, "skills": self._skill_forge.search_skills(str(args.get("query", "")))}
        return self._skill_forge.run_skill(str(args["name"]), args.get("kwargs"))

    def spawn_agent(self, args: Dict[str, Any]) -> Dict[str, Any]:
        if self._subagent_bus is None:
            return {"ok": False, "error": "SubAgentSessionBus is not configured"}
        obj = str(args.get("objective", "")).strip()
        if not obj:
            return {"ok": False, "error": "objective is required"}
        role = str(args.get("role", "general_engineer"))
        parent_id = str(args.get("parent_id", "root"))
        current_depth = int(args.get("current_depth", 0))
        ws = str(self.ws)

        def _worker(sid: str, objective_txt: str, ws_path: Path) -> Dict[str, Any]:
            return {"ok": True, "session_id": sid, "objective": objective_txt, "role": role, "workspace": str(ws_path)}

        return self._subagent_bus.spawn_session(
            obj,
            _worker,
            parent_id=parent_id,
            current_depth=current_depth,
            role=role,
            workspace=ws,
            run_async=not bool(args.get("wait", False)),
        )

    def send_agent(self, args: Dict[str, Any]) -> Dict[str, Any]:
        if self._subagent_bus is None:
            return {"ok": False, "error": "SubAgentSessionBus is not configured"}
        return self._subagent_bus.send_message(
            sender_id=str(args.get("sender_id", "primary")),
            recipient_id=str(args["recipient_id"]),
            content=str(args.get("content", "")),
        )

    def await_agents(self, args: Dict[str, Any]) -> Dict[str, Any]:
        if self._subagent_bus is None:
            return {"ok": False, "error": "SubAgentSessionBus is not configured"}
        sids = args.get("session_ids") or []
        if isinstance(sids, str):
            sids = [sids]
        return self._subagent_bus.await_sessions([str(x) for x in sids], timeout_s=float(args.get("timeout_s", 30.0)))

    def spawn_team(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Assemble and execute a multi-wave hierarchical team (CEO -> Architect -> Devs -> Supervisor -> Auditors)."""
        if self._subagent_bus is None:
            return {"ok": False, "error": "SubAgentSessionBus is not configured"}
        obj = str(args.get("objective", "")).strip()
        if not obj:
            return {"ok": False, "error": "missing required 'objective' for spawn_team"}
        file_count = int(args.get("workspace_file_count", 0))
        return self._subagent_bus.orchestrate_team(obj, workspace_file_count=file_count)

    def mcp_call(self, args: Dict[str, Any]) -> Dict[str, Any]:
        if self._mcp_hub is None:
            return {"ok": False, "error": "MCPFederationHub is not configured"}
        action = str(args.get("action", "call")).lower().strip()
        srv_name = str(args.get("server", "local"))
        if action == "list":
            return self._mcp_hub.list_server_tools(srv_name)
        return self._mcp_hub.call_server_tool(
            srv_name,
            str(args["tool"]),
            args.get("arguments") or {},
        )

    def _get_browser(self, *, headless: bool = True) -> Any:
        with self._io_lock:
            if self._browser is None:
                if self._browser_factory is None:
                    raise RuntimeError("browser_factory is not configured")
                self._browser = self._browser_factory(headless)
            return self._browser

    def browser_observe(self, args: Dict[str, Any]) -> Dict[str, Any]:
        headless = bool(args.get("headless", True))
        url = args.get("url")
        wait_ms = int(args.get("wait_ms", 200))
        force_reload = bool(args.get("force_reload", False))
        return self._get_browser(headless=headless).observe(
            url=str(url) if url else None,
            wait_ms=wait_ms,
            force_reload=force_reload,
        )

    def browser_act(self, args: Dict[str, Any]) -> Dict[str, Any]:
        action = str(args.get("action", "")).strip()
        if not action:
            return {"ok": False, "error": "missing required 'action'"}
        idx = args.get("idx")
        return self._get_browser(headless=bool(args.get("headless", True))).act(
            action,
            idx=int(idx) if idx is not None else None,
            target=str(args["target"]) if args.get("target") else None,
            text=str(args["text"]) if args.get("text") is not None else None,
            url=str(args["url"]) if args.get("url") else None,
        )

    def browser_extract(self, args: Dict[str, Any]) -> Dict[str, Any]:
        selector = str(args.get("selector", "body"))
        return self._get_browser(headless=bool(args.get("headless", True))).extract(selector=selector)

    def repo_map(self, args: Dict[str, Any]) -> Dict[str, Any]:
        if self._repo_mapper_factory is None:
            return {"ok": False, "error": "repo_mapper_factory is not configured"}
        max_chars = min(int(args.get("max_chars", 3000)), 12000)
        mapper = self._repo_mapper_factory(self.ws)
        ranked, text = mapper.build_ranked_map(max_chars=max_chars)
        return {
            "ok": True,
            "file_count": len(ranked),
            "ranked_files": [{"path": r.rel_path, "pagerank": r.pagerank, "symbols": len(r.symbols)} for r in ranked[:15]],
            "repomap": text,
        }

    def checkpoint(self, args: Dict[str, Any]) -> Dict[str, Any]:
        name = str(args.get("name", "default")).strip() or "default"
        snap: Dict[str, bytes] = {}
        for root, dirs, files in os.walk(self.ws):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for f in files:
                fp = Path(root) / f
                try:
                    if fp.stat().st_size <= 512_000:
                        rel = str(fp.relative_to(self.ws)).replace("\\", "/")
                        snap[rel] = fp.read_bytes()
                except OSError:
                    continue
        with self._io_lock:
            self._checkpoints[name] = snap
        return {"ok": True, "checkpoint": name, "files_captured": len(snap)}

    def knowledge_query(self, args: Dict[str, Any]) -> Dict[str, Any]:
        if self._knowledge_factory is None:
            return {"ok": False, "error": "knowledge_factory is not configured"}
        question = str(args.get("question", "")).strip()
        top_k = min(int(args.get("top_k", 5)), 15)
        idx = self._knowledge_factory(self.ws)
        return idx.query(question, top_k=top_k)

    @staticmethod
    def _validate_ssrf_url(url: str) -> Optional[str]:
        """Return an error string if `url` targets loopback/private/metadata IPs, else None."""
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme == "file":
            return None
        if parsed.scheme not in ("http", "https"):
            return "Only http://, https://, or file:// URLs are permitted"
        host = (parsed.hostname or "").strip().lower()
        if not host:
            return "Missing hostname in URL"
        if host in ("localhost", "metadata.google.internal", "metadata"):
            return f"Host '{host}' blocked (SSRF protection)"

        def _is_blocked_ip(ip_obj: ipaddress._BaseAddress) -> bool:
            if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
                ip_obj = ip_obj.ipv4_mapped
            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_reserved
                or ip_obj.is_unspecified
            ):
                return True
            if isinstance(ip_obj, ipaddress.IPv4Address):
                if ip_obj in ipaddress.IPv4Network("100.64.0.0/10"):
                    return True
                if ip_obj in ipaddress.IPv4Network("169.254.0.0/16"):
                    return True
            return False

        try:
            literal_ip = ipaddress.ip_address(host)
            if _is_blocked_ip(literal_ip):
                return f"IP '{host}' blocked (SSRF protection)"
            return None
        except ValueError:
            pass

        try:
            infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
        except OSError:
            return None

        for info in infos:
            sockaddr = info[4]
            if not sockaddr:
                continue
            addr_str = str(sockaddr[0]).split("%")[0]
            try:
                resolved_ip = ipaddress.ip_address(addr_str)
                if _is_blocked_ip(resolved_ip):
                    return f"Resolved IP '{addr_str}' for '{host}' blocked (SSRF protection)"
            except ValueError:
                continue
        return None

    def web_fetch(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Lightweight HTML/Text-to-Markdown fetcher (Crawl4AI/Agent-Reach style, R16 tainted)."""
        import html as _html
        import urllib.request

        url = str(args.get("url", "")).strip()
        ssrf_err = self._validate_ssrf_url(url)
        if ssrf_err:
            return {"ok": False, "url": url, "error": ssrf_err}
        max_chars = min(int(args.get("max_chars", 6000)), 20_000)
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "OmniExecutor-WebFetch/8.0",
                    "Accept-Encoding": "identity, gzip",
                },
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw_bytes = resp.read(256_000)
                enc = (resp.headers.get("Content-Encoding") or "").lower()
                if "gzip" in enc:
                    try:
                        raw_bytes = gzip.decompress(raw_bytes)
                    except OSError:
                        pass
                raw = raw_bytes.decode("utf-8", errors="replace")
            extracted: Optional[str] = None
            if not url.startswith("file://"):
                try:
                    import trafilatura  # type: ignore[import-not-found]

                    extracted = trafilatura.extract(raw, output_format="markdown")
                except Exception:
                    extracted = None
            if extracted:
                cleaned = extracted.strip()
            else:
                cleaned = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", raw)
                cleaned = re.sub(r"(?is)<h([1-4])[^>]*>(.*?)</h\1>", lambda m: f"\n{'#' * int(m.group(1))} {re.sub(r'<[^>]+>', '', m.group(2)).strip()}\n", cleaned)
                cleaned = re.sub(r"(?is)<[^>]+>", " ", cleaned)
                cleaned = _html.unescape(re.sub(r"[ \t]+", " ", re.sub(r"\n{3,}", "\n\n", cleaned))).strip()
            return {
                "ok": True,
                "url": url,
                "taint": "UNTRUSTED_EXTERNAL",
                "content": clip(cleaned, max_chars),
            }
        except Exception as exc:
            return {"ok": False, "url": url, "error": f"{type(exc).__name__}: {str(exc)[:300]}"}

    def spill_query(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Query or slice a spilled large tool output file on disk."""
        from am_ua.execution.output_compressor import ToolOutputCompressor

        spill_path = str(args.get("spill_path", "")).strip()
        if not spill_path:
            return {"ok": False, "error": "missing required 'spill_path'"}
        pattern = args.get("pattern")
        start_line = int(args.get("start_line", 1))
        max_lines = min(int(args.get("max_lines", 80)), 200)
        return ToolOutputCompressor().query_spill(
            spill_path,
            pattern=str(pattern) if pattern else None,
            start_line=start_line,
            max_lines=max_lines,
        )

    def deterministic_preflight(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Single-shot deterministic bundle: AST syntax sweep + AgentShield SAST + PageRank RepoMap."""
        from am_ua.execution.deterministic_offloader import DeterministicTaskOffloader

        max_chars = min(int(args.get("max_chars", 3500)), 12000)
        return DeterministicTaskOffloader.run_preflight_bundle(self.ws, max_chars=max_chars)

    def deterministic_exec(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute any programmable deterministic rail across the 220-rail matrix."""
        from am_ua.execution.deterministic_offloader import DeterministicTaskOffloader

        action = str(args.get("action") or args.get("rail") or "list_capabilities").strip()
        params = args.get("params") if isinstance(args.get("params"), dict) else {
            k: v for k, v in args.items() if k not in ("action", "rail")
        }
        return DeterministicTaskOffloader.execute_rail(
            action,
            self.ws,
            params=params,
            run_fn=self.run,
        )

    def _prepare_playbook_args(self, tool_name: str, bound_args: Dict[str, Any], _ws_tools: Any) -> Dict[str, Any]:
        out = dict(bound_args)
        if tool_name in ("write_file", "replace_in_file"):
            raw_p = str(out.get("path", out.get("file", "")))
            resolved = self.resolve(raw_p)
            self.seal_guard.assert_write_allowed(resolved, actor="agent_loop")
            out["path"] = str(resolved)
        return out

    def run_playbook(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """List or execute a deterministic parametric playbook (Code / Windows / Browser)."""
        from am_ua.execution.parametric_playbooks import DEFAULT_PLAYBOOK_ENGINE

        action = str(args.get("action") or "").strip().lower()
        playbook_name = str(args.get("playbook") or "").strip()
        if action == "list" or playbook_name in ("", "list"):
            domain = str(args.get("domain")).strip() if args.get("domain") else None
            return {
                "ok": True,
                "playbooks": DEFAULT_PLAYBOOK_ENGINE.list_playbooks(domain=domain),
            }

        raw_vars = args.get("variables")
        if not isinstance(raw_vars, dict):
            raw_vars = args.get("vars") if isinstance(args.get("vars"), dict) else {}
        return DEFAULT_PLAYBOOK_ENGINE.execute(
            playbook_name,
            dict(raw_vars),
            self,
            prepare_args_fn=self._prepare_playbook_args,
        )

    def code_sandbox(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Pure-Python restricted AST evaluator for deterministic math, JSON, and assertions (~1 ms)."""
        code = str(args.get("code", "")).strip()
        if not code:
            return {"ok": False, "error": "missing required 'code'"}
        if len(code) > 8000:
            return {"ok": False, "error": "code exceeds 8000 char sandbox limit"}

        allowed_builtins: Dict[str, Any] = {
            "abs": abs, "all": all, "any": any, "bool": bool, "dict": dict,
            "enumerate": enumerate, "float": float, "int": int, "len": len,
            "list": list, "max": max, "min": min, "pow": pow, "range": range,
            "round": round, "set": set, "sorted": sorted, "str": str,
            "sum": sum, "tuple": tuple, "zip": zip, "True": True, "False": False, "None": None,
        }
        allowed_modules: Dict[str, Any] = {"math": math, "json": json}

        try:
            tree = ast.parse(code, mode="exec")
        except SyntaxError as exc:
            return {"ok": False, "error": f"SyntaxError: {exc}"}

        forbidden_nodes = (ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal, ast.With, ast.AsyncWith, ast.Try, ast.Raise, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.While)
        for node in ast.walk(tree):
            if isinstance(node, forbidden_nodes):
                return {"ok": False, "error": f"Forbidden AST construct: {type(node).__name__}"}
            if isinstance(node, ast.Name) and node.id.startswith("__"):
                return {"ok": False, "error": f"Forbidden dunder name: {node.id}"}
            if isinstance(node, ast.Attribute) and node.attr.startswith("_"):
                return {"ok": False, "error": f"Forbidden private attribute: {node.attr}"}
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in ("open", "eval", "exec", "compile", "__import__", "getattr", "setattr", "delattr", "globals", "locals"):
                    return {"ok": False, "error": f"Forbidden call: {node.func.id}"}

        def _safe_range(*r_args: int) -> range:
            r = range(*r_args)
            if len(r) > 5000:
                raise ValueError("range exceeds 5000 step sandbox limit")
            return r

        env_globals: Dict[str, Any] = {
            "__builtins__": {**allowed_builtins, "range": _safe_range},
            **allowed_modules,
        }
        env_locals: Dict[str, Any] = {}
        try:
            last_expr = None
            if tree.body and isinstance(tree.body[-1], ast.Expr):
                last_expr = ast.Expression(body=tree.body.pop().value)
            if tree.body:
                exec(compile(tree, "<code_sandbox>", "exec"), env_globals, env_locals)
            val = eval(compile(last_expr, "<code_sandbox>", "eval"), env_globals, env_locals) if last_expr is not None else env_locals.get("result")
            return {"ok": True, "result": val, "locals": {k: v for k, v in env_locals.items() if not k.startswith("_")}}
        except Exception as exc:
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    def restore_checkpoint(self, args: Dict[str, Any]) -> Dict[str, Any]:
        name = str(args.get("name", "default")).strip() or "default"
        with self._io_lock:
            snap = self._checkpoints.get(name)
        if snap is None:
            return {"ok": False, "error": f"unknown checkpoint '{name}'"}
        restored: List[str] = []
        for rel, data in snap.items():
            fp = self.resolve(rel)
            self.seal_guard.assert_write_allowed(fp, actor="agent_loop")
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_bytes(data)
            restored.append(rel)
        return {"ok": True, "checkpoint": name, "restored_files": restored}

    def close(self) -> None:
        with self._io_lock:
            if self._browser is not None:
                try:
                    self._browser.close()
                except Exception:
                    pass
                self._browser = None

    # ---- snapshot for evidence diffs
    def snapshot(self) -> Dict[str, Tuple[str, Optional[str]]]:
        snap: Dict[str, Tuple[str, Optional[str]]] = {}
        for root, dirs, files in os.walk(self.ws):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for f in files:
                fp = Path(root) / f
                try:
                    data = fp.read_bytes() if fp.stat().st_size <= 512_000 else b""
                except OSError:
                    continue
                rel = fp.relative_to(self.ws).as_posix()
                try:
                    txt: Optional[str] = data.decode("utf-8")
                except UnicodeDecodeError:
                    txt = None
                snap[rel] = (hashlib.sha256(data).hexdigest(), txt)
                if len(snap) >= 5000:
                    return snap
        return snap
