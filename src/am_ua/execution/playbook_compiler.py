"""Turn-0 Playbook Router, Trace-to-Playbook Compiler, Rail Classifier & Self-Healing Selector Store (v11.0).

Eliminates unnecessary LLM turns by:
  1. Classifying all 220 deterministic rails cleanly by operational domain (`code`, `windows`,
     `browser`, `security`, `data`, `formal`, `observability`, `orchestration`).
  2. Intercepting parameterized Code/Windows/Browser intents at Turn 0 (`0` LLM tokens)
     and executing the matching playbook or compiled skill BEFORE waking an LLM.
  3. Compiling winning multi-turn LLM traces (`TraceToPlaybookCompiler`) into parameterized,
     persistent JSON playbooks registered live in `DEFAULT_PLAYBOOK_ENGINE`.
  4. Providing `SelfHealingSelectorCache` so brittle web selectors auto-heal via semantic/ARIA
     anchor matching and update cached CSS selectors cleanly on disk.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple


def infer_rail_category(name: str, description: str = "") -> str:
    """Deterministically map any of the 220+ rails to a concrete operational domain."""
    n = (name or "").lower()
    d = (description or "").lower()
    text = f"{n} {d}"
    if any(k in text for k in ("win_", "windows", "winget", "clipboard", "registry", "schtasks", "port", "process", "fastmft", "cpu_", "l1_", "l2_", "memory_bandwidth", "ps_", "exe", "pe_", "desktop")):
        return "windows"
    if any(k in text for k in ("web_", "http", "browser", "dom_", "html", "url", "seo", "cookie", "fetch", "markdown_extract")):
        return "browser"
    if any(k in text for k in ("shield", "secret", "gitleaks", "jwt", "merkle", "sbom", "cve", "supply_chain", "hash", "hmac", "encrypt", "auth", "policy", "sandbox", "pii")):
        return "security"
    if any(k in text for k in ("z3", "tla", "hoare", "formal", "invariant", "theorem", "smt", "property_edge", "hypothesis", "raft", "paxos")):
        return "formal"
    if any(k in text for k in ("sql", "csv", "json", "yaml", "toml", "parquet", "dbt", "data_", "tabular", "schema", "bm25", "regex", "xml", "document")):
        return "data"
    if any(k in text for k in ("otel", "telemetry", "trace", "metric", "ledger", "log_", "profile", "bench", "slo", "coverage", "git_forensics")):
        return "observability"
    if any(k in text for k in ("fleet", "swarm", "dag", "workflow", "cordis", "claw", "worktree", "checkpoint", "replay")):
        return "orchestration"
    return "code"


class SelfHealingSelectorCache:
    """Stores anchored DOM/ARIA selectors and auto-heals broken CSS selectors deterministically."""

    def __init__(self, store_path: Optional[Path | str] = None) -> None:
        from am_ua.contracts.contracts import resolve_omni_temp_dir

        self.store_path = Path(
            store_path or (resolve_omni_temp_dir("selector_cache") / "healed_selectors.json")
        ).resolve()
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        self._data: Dict[str, Dict[str, Any]] = self._load()

    def _load(self) -> Dict[str, Dict[str, Any]]:
        if self.store_path.is_file():
            try:
                raw = json.loads(self.store_path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    return raw
            except Exception:
                pass
        return {}

    def _save(self) -> None:
        self.store_path.write_text(json.dumps(self._data, indent=2, ensure_ascii=False), encoding="utf-8")

    @staticmethod
    def _key(scope: str, intent: str) -> str:
        return hashlib.sha256(f"{scope}::{intent.strip().lower()}".encode("utf-8")).hexdigest()[:16]

    def record_anchor(self, scope: str, intent: str, *, selector: str, role: str = "", text: str = "", dom_sha256: str = "") -> str:
        k = self._key(scope, intent)
        self._data[k] = {
            "scope": scope,
            "intent": intent,
            "selector": selector,
            "role": role,
            "text": text,
            "dom_sha256": dom_sha256,
        }
        self._save()
        return k

    def resolve_or_heal(
        self,
        scope: str,
        intent: str,
        *,
        candidate_elements: Sequence[Dict[str, Any]],
        primary_selector: str = "",
        dom_sha256: str = "",
    ) -> Dict[str, Any]:
        """Return matching element idx/selector or heal from ARIA role + text/placeholder similarity."""
        k = self._key(scope, intent)
        anchor = self._data.get(k, {})
        wanted_sel = primary_selector or str(anchor.get("selector") or "")

        # 1. Exact selector match in live candidates
        if wanted_sel:
            for el in candidate_elements:
                el_sel = str(el.get("selector") or el.get("css") or "")
                el_id = str(el.get("id") or "")
                if el_sel == wanted_sel or (wanted_sel.startswith("#") and el_id == wanted_sel[1:]):
                    return {"ok": True, "healed": False, "element": el, "selector": wanted_sel}

        # 2. Semantic / ARIA self-healing fallback
        tokens = set(re.findall(r"[a-z0-9]{2,}", f"{intent} {anchor.get('text', '')} {anchor.get('role', '')}".lower()))
        best_score = 0.0
        best_el: Optional[Dict[str, Any]] = None
        for el in candidate_elements:
            blob = " ".join(
                str(el.get(f, "") or "") for f in ("text", "name", "role", "aria_label", "placeholder", "id", "tag")
            ).lower()
            el_tokens = set(re.findall(r"[a-z0-9]{2,}", blob))
            if not tokens or not el_tokens:
                continue
            overlap = len(tokens & el_tokens) / max(1, len(tokens))
            if anchor.get("role") and str(el.get("role") or "").lower() == str(anchor["role"]).lower():
                overlap += 0.35
            if overlap > best_score:
                best_score = overlap
                best_el = el

        if best_el is not None and best_score >= 0.3:
            healed_sel = str(
                best_el.get("selector")
                or (f"#{best_el['id']}" if best_el.get("id") else "")
                or best_el.get("name")
                or wanted_sel
            )
            self.record_anchor(
                scope,
                intent,
                selector=healed_sel,
                role=str(best_el.get("role") or ""),
                text=str(best_el.get("text") or best_el.get("name") or "")[:120],
                dom_sha256=dom_sha256,
            )
            return {
                "ok": True,
                "healed": True,
                "score": round(best_score, 3),
                "previous_selector": wanted_sel,
                "selector": healed_sel,
                "element": best_el,
            }
        return {"ok": False, "healed": False, "selector": wanted_sel, "reason": "No matching or healable element"}


class TraceToPlaybookCompiler:
    """Compiles successful multi-turn tool traces into reusable 0-token ParametricPlaybooks."""

    def __init__(self, store_path: Optional[Path | str] = None) -> None:
        from am_ua.contracts.contracts import resolve_omni_temp_dir

        self.store_path = Path(
            store_path or (resolve_omni_temp_dir("compiled_playbooks") / "compiled_playbooks.json")
        ).resolve()
        self.store_path.parent.mkdir(parents=True, exist_ok=True)

    def load_all(self) -> Dict[str, Dict[str, Any]]:
        if self.store_path.is_file():
            try:
                raw = json.loads(self.store_path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    return raw
            except Exception:
                pass
        return {}

    def compile_trace(
        self,
        *,
        name: str,
        objective: str,
        tool_calls: Sequence[Dict[str, Any]],
        domain: Optional[str] = None,
        verification: Optional[Dict[str, Any]] = None,
        persist: bool = True,
        register_live: bool = True,
    ) -> Dict[str, Any]:
        """Distill tool calls into parameterized `PlaybookStep`s and register on `DEFAULT_PLAYBOOK_ENGINE`."""
        from am_ua.execution.parametric_playbooks import DEFAULT_PLAYBOOK_ENGINE, PlaybookStep

        clean_calls = [
            tc for tc in tool_calls if tc.get("ok", True) and tc.get("tool") not in ("finish", "request_human")
        ]
        if not clean_calls:
            return {"ok": False, "error": "No executable successful tool calls to compile"}

        # Detect domain automatically if omitted
        inferred_domain = domain or "code"
        tool_names = " ".join(str(tc.get("tool", "")) for tc in clean_calls)
        if "browser_" in tool_names or "web_fetch" in tool_names:
            inferred_domain = "browser"
        elif "pc_" in tool_names:
            inferred_domain = "windows"

        steps_spec: List[Dict[str, Any]] = []
        param_defaults: Dict[str, Any] = {}
        for idx, tc in enumerate(clean_calls, 1):
            tname = str(tc["tool"])
            raw_args = dict(tc.get("args") or {})
            templated_args: Dict[str, Any] = {}
            for k, v in raw_args.items():
                if isinstance(v, str) and len(v) <= 240 and k in ("path", "file_path", "url", "command", "target", "old", "new", "pattern", "filter", "window_title"):
                    var_name = f"s{idx}_{k}"
                    param_defaults[var_name] = v
                    templated_args[k] = f"{{{{{var_name}}}}}"
                else:
                    templated_args[k] = v
            steps_spec.append({"id": f"step_{idx}", "tool": tname, "args": templated_args, "save_as": f"out_{idx}"})

        pb_record = {
            "name": name,
            "domain": inferred_domain,
            "description": f"Compiled deterministic playbook from: {objective[:140]}",
            "keywords": sorted(set(re.findall(r"[a-z0-9_]{3,}", objective.lower())))[:12],
            "optional_vars": param_defaults,
            "steps": steps_spec,
            "verified_postcondition": bool((verification or {}).get("passed", True)),
            "estimated_tokens_saved": max(2500, len(steps_spec) * 3500),
        }

        if persist:
            existing = self.load_all()
            existing[name] = pb_record
            self.store_path.write_text(json.dumps(existing, indent=2, ensure_ascii=False), encoding="utf-8")

        if register_live:
            pb_steps = [
                PlaybookStep(step_id=s["id"], tool=s["tool"], args_template=s["args"], save_as=s["save_as"])
                for s in steps_spec
            ]
            DEFAULT_PLAYBOOK_ENGINE.register(
                name,
                domain=inferred_domain,
                description=pb_record["description"],
                required_vars=(),
                optional_vars=param_defaults,
                steps=pb_steps,
                estimated_tokens_saved=int(pb_record["estimated_tokens_saved"]),
            )
        return {"ok": True, "playbook": pb_record, "steps_compiled": len(steps_spec)}


class TurnZeroPlaybookRouter:
    """Turn-0 Pre-LLM Classifier matching Code/Windows/Browser intents to 0-token playbooks."""

    @staticmethod
    def match_intent(
        objective: str,
        *,
        verify_cmd: Optional[str] = None,
        compiler: Optional[TraceToPlaybookCompiler] = None,
    ) -> Optional[Dict[str, Any]]:
        text = (objective or "").strip()
        if not text:
            return None
        low = text.lower()

        # 1. Code domain: rename symbol (`rename SYMBOL to NEW_SYMBOL in FILE`)
        m_ren = re.search(
            r"(?:rename|renomear)\s+(?:symbol\s+|func(?:ao|tion)?\s+)?`?([A-Za-z_][A-Za-z0-9_]*)`?\s+(?:to|para)\s+`?([A-Za-z_][A-Za-z0-9_]*)`?\s+(?:in|em)\s+`?([A-Za-z0-9_./\\-]+\.py)`?",
            text,
            re.IGNORECASE,
        )
        if m_ren:
            vars_map: Dict[str, Any] = {
                "old_symbol": m_ren.group(1),
                "new_symbol": m_ren.group(2),
                "file_path": m_ren.group(3),
            }
            if verify_cmd:
                vars_map["verify_cmd"] = verify_cmd
            return {"playbook": "code_refactor_rename_and_verify", "variables": vars_map, "confidence": 0.96}

        # 2. Browser domain: fast fetch URL (`fetch <url>` / `extract text from https://...`)
        m_url = re.search(r"((?:https?|file)://[^\s'\"<>]+)", text, re.IGNORECASE)
        if m_url and any(w in low for w in ("fetch", "extract", "read page", "extrair", "baixar pagina", "download")) and not any(w in low for w in ("click", "login", "fill", "type")):
            url = m_url.group(1).rstrip(".,;)")
            if "sha256" in low or "checksum" in low or "download" in low:
                return {"playbook": "web_download_and_verify_sha256", "variables": {"url": url}, "confidence": 0.94}
            return {"playbook": "web_fast_fetch_extract", "variables": {"url": url}, "confidence": 0.93}

        # 3. Windows domain: port owner (`port <num>` / `who is using port <num>`) or system health
        m_port = re.search(r"\b(?:port|porta)\s+(\d{2,5})\b", low)
        if m_port and any(w in low for w in ("owner", "triage", "process", "check", "who", "quem", "dono")):
            return {
                "playbook": "win_port_and_process_triage",
                "variables": {"port": int(m_port.group(1)), "filter": ""},
                "confidence": 0.92,
            }
        if any(p in low for p in ("system health snapshot", "windows system health", "saude do sistema windows", "process inventory")):
            return {"playbook": "win_system_health_and_services", "variables": {"filter": "python"}, "confidence": 0.91}

        # 4. Compiled persistent playbooks (learned from prior LLM trajectories)
        if compiler is not None:
            obj_tokens = set(re.findall(r"[a-z0-9_]{3,}", low))
            best_score = 0.0
            best_pb: Optional[Dict[str, Any]] = None
            for name, rec in compiler.load_all().items():
                kw = set(rec.get("keywords") or [])
                if not kw:
                    continue
                overlap = len(obj_tokens & kw) / max(1, len(kw))
                if overlap >= 0.75 and overlap > best_score and rec.get("verified_postcondition", True):
                    best_score = overlap
                    best_pb = {"playbook": name, "variables": dict(rec.get("optional_vars") or {}), "confidence": round(overlap, 3)}
            if best_pb is not None:
                return best_pb
        return None
