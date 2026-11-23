"""Deterministic Parametric Playbook Engine (v8.2 — Fase 3).

Converts repetitive multi-step workflows across **Code**, **Windows OS/Desktop**, and **Browser**
into deterministic, pre-fixed, reusable playbooks with dynamic variable binding (`{{var}}` and
prior step chaining `{{prev.<key>}}`).

An LLM (or CLI/caller) only needs 1 shot to select a registered playbook and bind arbitrary runtime
variables (`file_path`, `old_symbol`, `new_symbol`, `url`, `selector`, `window_title`, `steps`, etc.),
executing the entire multi-step sequence deterministically at 0 extra LLM turns.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
import re
from typing import Any, Callable, Dict, List, Optional, Sequence


_VAR_RX = re.compile(r"\{\{\s*([a-zA-Z0-9_.\-]+)\s*\}\}")
_DANGEROUS_INTERP_RX = re.compile(r"[;&|`$><\r\n]")


@dataclass(frozen=True)
class PlaybookStep:
    """Single deterministic step inside a pre-fixed parameterized playbook."""

    step_id: str
    tool: str
    args_template: Dict[str, Any]
    save_as: str = ""
    on_fail: str = "abort"  # abort | continue


@dataclass
class PlaybookSpec:
    """Registered pre-fixed deterministic agent playbook with typed required variables."""

    name: str
    domain: str  # code | windows | browser | hybrid
    description: str
    required_vars: Tuple[str, ...]
    optional_vars: Dict[str, Any] = field(default_factory=dict)
    steps: List[PlaybookStep] = field(default_factory=list)
    estimated_tokens_saved: int = 8000


from typing import Tuple  # keep dataclass typing clean above/below


def _lookup_dotted(ctx: Dict[str, Any], key: str) -> Any:
    if key in ctx:
        return ctx[key]
    parts = key.split(".")
    cur: Any = ctx
    for p in parts:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            raise KeyError(key)
    return cur


def _bind_value(
    tmpl: Any,
    ctx: Dict[str, Any],
    *,
    shell_safe: bool = False,
) -> Any:
    if isinstance(tmpl, dict):
        return {k: _bind_value(v, ctx, shell_safe=shell_safe) for k, v in tmpl.items()}
    if isinstance(tmpl, list):
        return [_bind_value(item, ctx, shell_safe=shell_safe) for item in tmpl]
    if not isinstance(tmpl, str):
        return tmpl

    exact = _VAR_RX.fullmatch(tmpl.strip())
    if exact:
        val = _lookup_dotted(ctx, exact.group(1))
        return val

    def _sub(m: re.Match[str]) -> str:
        val = _lookup_dotted(ctx, m.group(1))
        s = str(val)
        if shell_safe and _DANGEROUS_INTERP_RX.search(s):
            raise ValueError(f"Unsafe shell metacharacter in interpolated variable '{m.group(1)}'")
        return s

    return _VAR_RX.sub(_sub, tmpl)


class ParametricPlaybookEngine:
    """Registry and executor for pre-fixed deterministic multi-step agents with dynamic slot filling."""

    def __init__(self, *, load_builtin: bool = True) -> None:
        self._specs: Dict[str, PlaybookSpec] = {}
        self._custom_runners: Dict[str, Callable[[Dict[str, Any], Any], Dict[str, Any]]] = {}
        if load_builtin:
            self._register_builtins()

    def register(
        self,
        name: str,
        *,
        domain: str,
        description: str,
        required_vars: Sequence[str],
        steps: List[PlaybookStep],
        optional_vars: Optional[Dict[str, Any]] = None,
        estimated_tokens_saved: int = 8000,
    ) -> None:
        self._specs[name] = PlaybookSpec(
            name=name,
            domain=domain,
            description=description,
            required_vars=tuple(required_vars),
            optional_vars=dict(optional_vars or {}),
            steps=list(steps),
            estimated_tokens_saved=int(estimated_tokens_saved),
        )

    def register_custom_runner(
        self,
        name: str,
        *,
        domain: str,
        description: str,
        required_vars: Sequence[str],
        runner_fn: Callable[[Dict[str, Any], Any], Dict[str, Any]],
        optional_vars: Optional[Dict[str, Any]] = None,
        estimated_tokens_saved: int = 9000,
    ) -> None:
        self.register(
            name,
            domain=domain,
            description=description,
            required_vars=required_vars,
            steps=[],
            optional_vars=optional_vars,
            estimated_tokens_saved=estimated_tokens_saved,
        )
        self._custom_runners[name] = runner_fn

    def list_playbooks(self, domain: Optional[str] = None) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for spec in sorted(self._specs.values(), key=lambda s: (s.domain, s.name)):
            if domain and spec.domain != domain:
                continue
            out.append(
                {
                    "name": spec.name,
                    "domain": spec.domain,
                    "description": spec.description,
                    "required_vars": list(spec.required_vars),
                    "optional_vars": dict(spec.optional_vars),
                    "step_count": len(spec.steps),
                    "estimated_tokens_saved": spec.estimated_tokens_saved,
                }
            )
        return out

    def bind_steps(self, playbook_name: str, variables: Dict[str, Any]) -> List[Dict[str, Any]]:
        if playbook_name not in self._specs:
            raise KeyError(f"Unknown deterministic playbook: {playbook_name!r}")
        spec = self._specs[playbook_name]
        missing = [v for v in spec.required_vars if v not in variables or variables[v] is None]
        if missing:
            raise ValueError(f"Playbook {playbook_name!r} missing required variables: {missing}")

        ctx: Dict[str, Any] = {**spec.optional_vars, **variables}
        bound: List[Dict[str, Any]] = []
        for st in spec.steps:
            shell_safe = st.tool == "run" and "command" in st.args_template and "{{verify_cmd}}" not in str(st.args_template.get("command", ""))
            args = _bind_value(st.args_template, ctx, shell_safe=shell_safe)
            bound.append(
                {
                    "step_id": st.step_id,
                    "tool": st.tool,
                    "args": args,
                    "save_as": st.save_as,
                    "on_fail": st.on_fail,
                }
            )
        return bound

    def execute(
        self,
        playbook_name: str,
        variables: Dict[str, Any],
        ws_tools: Any,
        *,
        prepare_args_fn: Optional[Callable[[str, Dict[str, Any], Any], Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        if playbook_name not in self._specs:
            return {
                "ok": False,
                "error": f"Unknown playbook {playbook_name!r}",
                "available_playbooks": [p["name"] for p in self.list_playbooks()],
            }
        spec = self._specs[playbook_name]
        missing = [v for v in spec.required_vars if v not in variables or variables[v] is None]
        if missing:
            return {"ok": False, "playbook": playbook_name, "error": f"Missing required variables: {missing}"}

        ctx: Dict[str, Any] = {**spec.optional_vars, **variables, "vars": dict(variables)}
        if playbook_name in self._custom_runners:
            res = dict(self._custom_runners[playbook_name](ctx, ws_tools))
            res.setdefault("playbook", playbook_name)
            res.setdefault("domain", spec.domain)
            res.setdefault("estimated_tokens_saved", spec.estimated_tokens_saved)
            return res

        trace: List[Dict[str, Any]] = []
        prev: Dict[str, Any] = {}
        overall_ok = True

        for st in spec.steps:
            step_ctx = {**ctx, "prev": prev}
            try:
                shell_safe = st.tool == "run" and "{{verify_cmd}}" not in str(st.args_template.get("command", ""))
                args = _bind_value(st.args_template, step_ctx, shell_safe=shell_safe)
                if prepare_args_fn is not None:
                    call_args = prepare_args_fn(st.tool, args, ws_tools)
                else:
                    call_args = dict(args)
                    if st.tool in ("write_file", "replace_in_file") and hasattr(ws_tools, "resolve"):
                        raw_p = str(call_args.get("file", call_args.get("path", "")))
                        call_args["path"] = str(ws_tools.resolve(raw_p))

                fn = getattr(ws_tools, st.tool, None)
                if fn is None:
                    raise AttributeError(f"WorkspaceTools has no method '{st.tool}'")
                obs = fn(call_args)
                step_ok = True
                if isinstance(obs, dict):
                    if obs.get("ok") is False:
                        step_ok = False
                    elif st.tool == "run" and obs.get("exit_code") not in (0, None):
                        step_ok = False
            except Exception as exc:
                obs = {"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:300]}"}
                step_ok = False

            trace.append(
                {
                    "step_id": st.step_id,
                    "tool": st.tool,
                    "ok": step_ok,
                    "observation": obs,
                }
            )
            if isinstance(obs, dict):
                prev = obs
                if st.save_as:
                    ctx[st.save_as] = obs
            else:
                prev = {"result": obs}
                if st.save_as:
                    ctx[st.save_as] = prev

            if not step_ok and st.on_fail == "abort":
                overall_ok = False
                break
            if not step_ok:
                overall_ok = False

        return {
            "ok": overall_ok,
            "playbook": playbook_name,
            "domain": spec.domain,
            "steps_executed": len(trace),
            "estimated_tokens_saved": spec.estimated_tokens_saved if overall_ok else 0,
            "final_observation": prev,
            "trace": trace,
        }

    # ------------------------------------------------------------------ Built-ins
    def _register_builtins(self) -> None:
        # 1. CODE DOMAIN: Safe AST/LibCST refactor + lint + pytest verify
        self.register(
            "code_refactor_rename_and_verify",
            domain="code",
            description="Deterministically rename a Python symbol across a file/repo, autofix lint, and run verification command.",
            required_vars=("file_path", "old_symbol", "new_symbol", "verify_cmd"),
            optional_vars={"target_glob": "."},
            steps=[
                PlaybookStep("backup", "checkpoint", {"name": "pre_playbook_refactor"}, save_as="ckpt"),
                PlaybookStep(
                    "codemod",
                    "deterministic_exec",
                    {
                        "action": "libcst_safe_codemod",
                        "params": {
                            "file_path": "{{file_path}}",
                            "symbol_old": "{{old_symbol}}",
                            "symbol_new": "{{new_symbol}}",
                        },
                    },
                    save_as="codemod_res",
                ),
                PlaybookStep(
                    "lint",
                    "deterministic_exec",
                    {"action": "code_autofix_and_lint", "params": {"target": "{{file_path}}", "apply_fix": True}},
                    save_as="lint_res",
                    on_fail="continue",
                ),
                PlaybookStep("verify", "run", {"command": "{{verify_cmd}}", "timeout_s": 120}, save_as="verify_res"),
            ],
            estimated_tokens_saved=12000,
        )

        # 2. CODE DOMAIN: Surgical search & replace + verify
        self.register(
            "code_patch_and_verify",
            domain="code",
            description="Apply an exact/fuzzy search-and-replace patch on a target file and verify with command.",
            required_vars=("path", "old", "new", "verify_cmd"),
            steps=[
                PlaybookStep("backup", "checkpoint", {"name": "pre_patch"}, save_as="ckpt"),
                PlaybookStep(
                    "patch",
                    "replace_in_file",
                    {"path": "{{path}}", "old": "{{old}}", "new": "{{new}}"},
                    save_as="patch_res",
                ),
                PlaybookStep("verify", "run", {"command": "{{verify_cmd}}", "timeout_s": 120}, save_as="verify_res"),
            ],
            estimated_tokens_saved=9000,
        )

        # 3. CODE DOMAIN: Pre-flight + Rail Execution + Verify
        self.register(
            "code_diagnose_and_rail",
            domain="code",
            description="Execute repository preflight + any named deterministic rail with arbitrary params.",
            required_vars=("rail",),
            optional_vars={"params": {}, "max_chars": 3000},
            steps=[
                PlaybookStep("preflight", "deterministic_preflight", {"max_chars": "{{max_chars}}"}, save_as="pre"),
                PlaybookStep(
                    "exec_rail",
                    "deterministic_exec",
                    {"rail": "{{rail}}", "params": "{{params}}"},
                    save_as="rail_res",
                ),
            ],
            estimated_tokens_saved=8000,
        )

        # 4. WINDOWS DOMAIN: Launch isolated app, observe/verify UIA+OCR, cleanup
        self.register(
            "win_launch_observe_and_close",
            domain="windows",
            description="Launch an isolated Windows application, observe its window via UIA/OCR, and clean up.",
            required_vars=("app_cmd",),
            optional_vars={"window_title": "", "wait_s": 2.0, "include_ocr": True},
            steps=[
                PlaybookStep(
                    "launch",
                    "pc_window",
                    {"action": "launch", "app_cmd": "{{app_cmd}}", "wait_s": "{{wait_s}}"},
                    save_as="launch_res",
                ),
                PlaybookStep(
                    "observe",
                    "pc_observe",
                    {"window_title": "{{window_title}}", "include_ocr": "{{include_ocr}}", "max_elements": 60},
                    save_as="obs_res",
                    on_fail="continue",
                ),
                PlaybookStep("cleanup", "pc_window", {"action": "cleanup"}, save_as="cleanup_res"),
            ],
            estimated_tokens_saved=10000,
        )

        # 5. WINDOWS DOMAIN: Closed-loop multi-step desktop UI automation with dynamic steps
        def _win_ui_sequence(ctx: Dict[str, Any], ws_tools: Any) -> Dict[str, Any]:
            win_title = str(ctx.get("window_title") or "")
            raw_steps = ctx.get("steps")
            if not isinstance(raw_steps, list) or not raw_steps:
                return {"ok": False, "error": "'steps' must be a non-empty list of desktop UI steps"}
            trace: List[Dict[str, Any]] = []
            if win_title:
                obs0 = ws_tools.pc_observe({"window_title": win_title, "include_ocr": True})
                trace.append({"step": "initial_observe", "ok": bool(obs0.get("ok", True)), "observation": obs0})
            ok_all = True
            for i, step in enumerate(raw_steps, 1):
                act_args = dict(step) if isinstance(step, dict) else {}
                res = ws_tools.pc_act(act_args)
                step_ok = bool(res.get("ok", True))
                if not step_ok:
                    ok_all = False
                trace.append({"step": f"act_{i}", "ok": step_ok, "observation": res})
                if not step_ok:
                    break
            return {"ok": ok_all, "steps_executed": len(trace), "trace": trace}

        self.register_custom_runner(
            "win_ui_sequence",
            domain="windows",
            description="Execute an arbitrary sequence of closed-loop Windows GUI actions (`steps`) on a target window.",
            required_vars=("steps",),
            optional_vars={"window_title": ""},
            runner_fn=_win_ui_sequence,
            estimated_tokens_saved=11000,
        )

        # 6. WINDOWS DOMAIN: Port & process triage + deterministic system inventory
        self.register(
            "win_port_and_process_triage",
            domain="windows",
            description="Inspect TCP port ownership and filter active OS processes deterministically.",
            required_vars=("port",),
            optional_vars={"filter": ""},
            steps=[
                PlaybookStep("port", "pc_process", {"action": "port_owner", "port": "{{port}}"}, save_as="port_res"),
                PlaybookStep("procs", "pc_process", {"action": "list", "filter": "{{filter}}"}, save_as="proc_res"),
            ],
            estimated_tokens_saved=4500,
        )

        # 7. BROWSER DOMAIN: Open URL, execute dynamic action sequence (fill/click/press), extract selector
        def _web_navigate_fill_extract(ctx: Dict[str, Any], ws_tools: Any) -> Dict[str, Any]:
            url = str(ctx["url"]).strip()
            headless = bool(ctx.get("headless", True))
            extract_sel = str(ctx.get("extract_selector") or "body")
            raw_steps = ctx.get("steps") or []
            trace: List[Dict[str, Any]] = []

            obs = ws_tools.browser_observe({"url": url, "headless": headless})
            trace.append({"step": "observe", "ok": bool(obs.get("ok", True)), "url": obs.get("url")})
            if obs.get("blocked_by_domain_guard") or obs.get("ok") is False:
                return {"ok": False, "error": obs.get("error", "browser_observe failed"), "trace": trace}

            for idx_s, s in enumerate(raw_steps, 1):
                if not isinstance(s, dict):
                    continue
                act_args = {**s, "headless": headless}
                res = ws_tools.browser_act(act_args)
                s_ok = bool(res.get("ok", True))
                trace.append({"step": f"act_{idx_s}", "ok": s_ok, "observation": res})
                if not s_ok:
                    return {"ok": False, "steps_executed": len(trace), "trace": trace, "error": res.get("error")}

            extracted = ws_tools.browser_extract({"selector": extract_sel, "headless": headless})
            trace.append({"step": "extract", "ok": bool(extracted.get("ok", True)), "observation": extracted})
            return {
                "ok": bool(extracted.get("ok", True)),
                "steps_executed": len(trace),
                "extracted": extracted,
                "trace": trace,
            }

        self.register_custom_runner(
            "web_navigate_fill_extract",
            domain="browser",
            description="Navigate to an arbitrary URL, execute dynamic indexed DOM steps (`click`/`fill`/`press`), and extract CSS selector content in 1 deterministic shot.",
            required_vars=("url",),
            optional_vars={"steps": [], "extract_selector": "body", "headless": True},
            runner_fn=_web_navigate_fill_extract,
            estimated_tokens_saved=14000,
        )

        # 8. BROWSER DOMAIN: Zero-browser fast SSRF-guarded fetch + HTML extraction
        self.register(
            "web_fast_fetch_extract",
            domain="browser",
            description="Fetch a public URL safely via SSRF-guarded HTTP/Markdown extractor without launching Chromium.",
            required_vars=("url",),
            optional_vars={"max_chars": 6000},
            steps=[
                PlaybookStep("fetch", "web_fetch", {"url": "{{url}}", "max_chars": "{{max_chars}}"}, save_as="fetch_res"),
            ],
            estimated_tokens_saved=5000,
        )

        # 9. BROWSER DOMAIN: Persistent session / cookies verification + extraction
        def _web_session_cookie_flow(ctx: Dict[str, Any], ws_tools: Any) -> Dict[str, Any]:
            url = str(ctx["url"]).strip()
            headless = bool(ctx.get("headless", True))
            extract_sel = str(ctx.get("extract_selector") or "body")
            state_path = str(ctx.get("state_file") or ".browser_session_meta.json")
            obs = ws_tools.browser_observe({"url": url, "headless": headless})
            if not obs.get("ok", True) or obs.get("blocked_by_domain_guard"):
                return {"ok": False, "error": obs.get("error", "observe failed"), "observation": obs}
            ext = ws_tools.browser_extract({"selector": extract_sel, "headless": headless})
            meta = {"url": obs.get("url"), "state_file": state_path, "element_count": obs.get("element_count", 0)}
            return {"ok": bool(ext.get("ok", True)), "session": meta, "extracted": ext, "steps_executed": 2}

        self.register_custom_runner(
            "web_session_cookie_flow",
            domain="browser",
            description="Observe a URL within a tracked session metadata flow and extract target DOM content deterministically.",
            required_vars=("url",),
            optional_vars={"state_file": ".browser_session_meta.json", "extract_selector": "body", "headless": True},
            runner_fn=_web_session_cookie_flow,
            estimated_tokens_saved=9000,
        )

        # 10. BROWSER DOMAIN: Deterministic paginated extraction loop (next selector + dedupe)
        def _web_paginated_extract(ctx: Dict[str, Any], ws_tools: Any) -> Dict[str, Any]:
            url = str(ctx["url"]).strip()
            headless = bool(ctx.get("headless", True))
            extract_sel = str(ctx.get("extract_selector") or "body")
            next_sel = str(ctx.get("next_selector") or "a.next")
            max_pages = min(20, max(1, int(ctx.get("max_pages", 3))))
            pages: List[Dict[str, Any]] = []
            seen_texts: set[str] = set()
            obs = ws_tools.browser_observe({"url": url, "headless": headless})
            if not obs.get("ok", True):
                return {"ok": False, "error": obs.get("error", "observe failed"), "pages": pages}
            for p_idx in range(1, max_pages + 1):
                ext = ws_tools.browser_extract({"selector": extract_sel, "headless": headless})
                txt = str(ext.get("text") or "")
                if txt and txt in seen_texts:
                    break
                seen_texts.add(txt)
                pages.append({"page": p_idx, "text": txt, "ok": bool(ext.get("ok", True))})
                if p_idx >= max_pages:
                    break
                nxt = ws_tools.browser_act({"action": "click", "target": next_sel, "headless": headless})
                if not nxt.get("ok", True):
                    break
            return {"ok": bool(pages), "pages_collected": len(pages), "pages": pages, "steps_executed": len(pages) * 2}

        self.register_custom_runner(
            "web_paginated_extract",
            domain="browser",
            description="Deterministically paginate across multi-page lists/tables using a next-button selector until duplicate or exhausted.",
            required_vars=("url",),
            optional_vars={"next_selector": "a.next", "extract_selector": "body", "max_pages": 3, "headless": True},
            runner_fn=_web_paginated_extract,
            estimated_tokens_saved=15000,
        )

        # 11. BROWSER DOMAIN: SSRF-guarded download + SHA-256 checksum validation
        def _web_download_verify_sha256(ctx: Dict[str, Any], ws_tools: Any) -> Dict[str, Any]:
            import hashlib

            url = str(ctx["url"]).strip()
            expected_sha = str(ctx.get("expected_sha256") or "").strip().lower()
            fetch_res = ws_tools.web_fetch({"url": url, "max_chars": int(ctx.get("max_chars", 50000))})
            if not fetch_res.get("ok"):
                return {"ok": False, "error": fetch_res.get("error", "fetch failed"), "fetch": fetch_res}
            payload = str(fetch_res.get("content") or "").encode("utf-8")
            digest = hashlib.sha256(payload).hexdigest()
            matched = (digest == expected_sha) if expected_sha else True
            return {"ok": matched, "sha256": digest, "bytes": len(payload), "expected_sha256": expected_sha or None, "steps_executed": 1}

        self.register_custom_runner(
            "web_download_and_verify_sha256",
            domain="browser",
            description="Fetch a public URL safely via SSRF guard and compute/verify its SHA-256 checksum deterministically.",
            required_vars=("url",),
            optional_vars={"expected_sha256": "", "max_chars": 50000},
            runner_fn=_web_download_verify_sha256,
            estimated_tokens_saved=6500,
        )

        # 12. BROWSER DOMAIN: SPA retry/wait observe -> act -> extract
        def _web_spa_wait_and_act(ctx: Dict[str, Any], ws_tools: Any) -> Dict[str, Any]:
            url = str(ctx["url"]).strip()
            headless = bool(ctx.get("headless", True))
            wait_ms = min(5000, max(50, int(ctx.get("wait_ms", 250))))
            obs = ws_tools.browser_observe({"url": url, "wait_ms": wait_ms, "headless": headless})
            if not obs.get("ok", True):
                return {"ok": False, "error": obs.get("error", "SPA observe failed")}
            steps = ctx.get("steps") or []
            trace: List[Dict[str, Any]] = []
            for i, st in enumerate(steps, 1):
                res = ws_tools.browser_act({**(st if isinstance(st, dict) else {}), "headless": headless})
                trace.append({"step": i, "ok": bool(res.get("ok", True)), "observation": res})
                if not res.get("ok", True):
                    return {"ok": False, "steps_executed": i + 1, "trace": trace, "error": res.get("error")}
            ext = ws_tools.browser_extract({"selector": str(ctx.get("extract_selector") or "body"), "headless": headless})
            return {"ok": bool(ext.get("ok", True)), "extracted": ext, "steps_executed": len(trace) + 2, "trace": trace}

        self.register_custom_runner(
            "web_spa_wait_and_act",
            domain="browser",
            description="Wait for client-rendered SPA stabilization, execute indexed DOM steps, and extract output.",
            required_vars=("url",),
            optional_vars={"wait_ms": 250, "steps": [], "extract_selector": "body", "headless": True},
            runner_fn=_web_spa_wait_and_act,
            estimated_tokens_saved=12000,
        )

        # 13. WINDOWS DOMAIN: Deterministic ZIP archive create/extract inside workspace
        def _win_batch_file_archive(ctx: Dict[str, Any], ws_tools: Any) -> Dict[str, Any]:
            import zipfile

            mode = str(ctx.get("mode", "create")).strip().lower()
            archive_rel = str(ctx["archive_path"])
            arc_p = ws_tools.resolve(archive_rel)
            if mode == "create":
                ws_tools.seal_guard.assert_write_allowed(arc_p, actor="agent_loop")
                arc_p.parent.mkdir(parents=True, exist_ok=True)
                src_files = ctx.get("files") or []
                added: List[str] = []
                with zipfile.ZipFile(arc_p, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                    for rel in src_files:
                        fp = ws_tools.resolve(str(rel))
                        if fp.is_file():
                            zf.write(fp, arcname=fp.relative_to(ws_tools.ws).as_posix())
                            added.append(fp.relative_to(ws_tools.ws).as_posix())
                return {"ok": True, "mode": "create", "archive": arc_p.relative_to(ws_tools.ws).as_posix(), "files": added, "steps_executed": 1}
            if mode == "extract":
                dest_dir = ws_tools.resolve(str(ctx.get("dest_dir") or "."))
                ws_tools.seal_guard.assert_write_allowed(dest_dir / ".zip_probe", actor="agent_loop")
                extracted: List[str] = []
                with zipfile.ZipFile(arc_p, "r") as zf:
                    for member in zf.namelist():
                        out_p = ws_tools.resolve(str(Path(dest_dir.relative_to(ws_tools.ws)) / member))
                        if member.endswith("/"):
                            out_p.mkdir(parents=True, exist_ok=True)
                        else:
                            out_p.parent.mkdir(parents=True, exist_ok=True)
                            out_p.write_bytes(zf.read(member))
                            extracted.append(out_p.relative_to(ws_tools.ws).as_posix())
                return {"ok": True, "mode": "extract", "extracted": extracted, "steps_executed": 1}
            return {"ok": False, "error": f"Unsupported archive mode: {mode!r}"}

        self.register_custom_runner(
            "win_batch_file_archive",
            domain="windows",
            description="Create or safely extract ZIP archives strictly inside the workspace boundary (zip-slip guarded).",
            required_vars=("archive_path",),
            optional_vars={"mode": "create", "files": [], "dest_dir": "."},
            runner_fn=_win_batch_file_archive,
            estimated_tokens_saved=7000,
        )

        # 14. WINDOWS DOMAIN: System health, env PATH & process snapshot
        self.register(
            "win_system_health_and_services",
            domain="windows",
            description="Run deterministic system process inventory + host CPU/homeostasis rail diagnostics.",
            required_vars=(),
            optional_vars={"filter": "python"},
            steps=[
                PlaybookStep("procs", "pc_process", {"action": "list", "filter": "{{filter}}"}, save_as="proc_res"),
                PlaybookStep("silicon", "deterministic_exec", {"rail": "cpu_silicon_probe"}, save_as="cpu_res", on_fail="continue"),
            ],
            estimated_tokens_saved=6000,
        )

        # 15. WINDOWS DOMAIN: Multi-app OCR observe -> Clipboard transfer -> Target act
        def _win_multiapp_ocr_transfer(ctx: Dict[str, Any], ws_tools: Any) -> Dict[str, Any]:
            src_win = str(ctx.get("source_window") or "")
            dst_win = str(ctx.get("target_window") or "")
            obs_src = ws_tools.pc_observe({"window_title": src_win, "include_ocr": True})
            payload = str(ctx.get("text") or obs_src.get("ocr_text") or obs_src.get("window_title") or src_win)
            clip_res = ws_tools.pc_clipboard({"action": "set", "text": payload})
            act_dst = ws_tools.pc_act({"action_type": "type", "target": dst_win, "text": payload}) if dst_win else {"ok": True}
            return {
                "ok": bool(clip_res.get("ok", True)) and bool(act_dst.get("ok", True)),
                "transferred_chars": len(payload),
                "source_obs": obs_src,
                "target_act": act_dst,
                "steps_executed": 3,
            }

        self.register_custom_runner(
            "win_multiapp_ocr_transfer",
            domain="windows",
            description="Extract text from a source Windows window via OCR/UIA, stage in OS clipboard, and type into target window.",
            required_vars=("source_window",),
            optional_vars={"target_window": "", "text": ""},
            runner_fn=_win_multiapp_ocr_transfer,
            estimated_tokens_saved=10500,
        )

        # 16. WINDOWS / CONTAINER DOMAIN: Network-isolated Docker execution
        self.register(
            "code_docker_isolated_run",
            domain="windows",
            description="Run a shell command inside a network-isolated Docker container (--network=none) over the workspace.",
            required_vars=("command",),
            optional_vars={"timeout_s": 120},
            steps=[
                PlaybookStep("docker_exec", "run", {"command": "{{command}}", "sandbox": "docker", "timeout_s": "{{timeout_s}}"}, save_as="docker_res"),
            ],
            estimated_tokens_saved=5500,
        )

        # 17. CODE DOMAIN: Transactional Patch + Pytest + Auto-Rollback on Failure
        def _code_git_worktree_patch_commit(ctx: Dict[str, Any], ws_tools: Any) -> Dict[str, Any]:
            ck = ws_tools.checkpoint({"name": "pre_tx_patch"})
            raw_path = str(ctx["path"])
            resolved = str(ws_tools.resolve(raw_path))
            ws_tools.seal_guard.assert_write_allowed(resolved, actor="agent_loop")
            patch_res = ws_tools.replace_in_file({"path": resolved, "old": str(ctx["old"]), "new": str(ctx["new"])})
            verify_res = ws_tools.run({"command": str(ctx["verify_cmd"]), "timeout_s": int(ctx.get("timeout_s", 120))})
            if verify_res.get("exit_code") != 0:
                rb = ws_tools.restore_checkpoint({"name": "pre_tx_patch"})
                return {"ok": False, "rolled_back": True, "rollback": rb, "verify": verify_res, "steps_executed": 4}
            return {"ok": True, "rolled_back": False, "checkpoint": ck, "patch": patch_res, "verify": verify_res, "steps_executed": 3}

        self.register_custom_runner(
            "code_git_worktree_patch_commit",
            domain="code",
            description="Checkpoint workspace, apply surgical patch, run verification suite, and auto-rollback if verification fails.",
            required_vars=("path", "old", "new", "verify_cmd"),
            optional_vars={"timeout_s": 120},
            runner_fn=_code_git_worktree_patch_commit,
            estimated_tokens_saved=13000,
        )

        # 18. CODE DOMAIN: Zero-token fault diagnosis + affected test check
        self.register(
            "code_error_diagnose_and_tdd_fix",
            domain="code",
            description="Run preflight AST/RepoMap + deterministic pytest failure parsing for zero-turn bug localization.",
            required_vars=("verify_cmd",),
            optional_vars={"max_chars": 3000},
            steps=[
                PlaybookStep("preflight", "deterministic_preflight", {"max_chars": "{{max_chars}}"}, save_as="pre"),
                PlaybookStep("verify", "run", {"command": "{{verify_cmd}}", "timeout_s": 120}, save_as="test_res", on_fail="continue"),
            ],
            estimated_tokens_saved=9500,
        )


DEFAULT_PLAYBOOK_ENGINE = ParametricPlaybookEngine(load_builtin=True)
