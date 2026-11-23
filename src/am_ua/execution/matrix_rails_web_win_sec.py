from __future__ import annotations

import ast
import base64
import csv
from decimal import Decimal, InvalidOperation
import difflib
import hashlib
from html.parser import HTMLParser
import json
import math
import os
from pathlib import Path
import re
import shutil
import sqlite3
import statistics
import struct
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
import xml.etree.ElementTree as ET
import zipfile

_SKIP_DIRS = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    ".pytest_cache",
    ".mypy_cache",
    "vendor",
    "HANDOFF_PACK",
}


from am_ua.execution.matrix_rails_helpers import _WORKSPACE_SNAPSHOT_GUARDS, _iter_py, _safe_path

def execute_web_win_sec(
    rail_name: str,
    ws: Path,
    target: str,
    args: Dict[str, Any],
    execute_rail_fn: Optional[Callable[..., Dict[str, Any]]] = None,
) -> Optional[Dict[str, Any]]:
    # --- DOMAIN D: WEB, BROWSER, SCRAPING & DOCUMENT INTELLIGENCE (69-79) ---
    if rail_name == "html_to_clean_markdown":
        raw_html = str(args.get("html") or "")

        class _MDParser(HTMLParser):
            def __init__(self) -> None:
                super().__init__()
                self.skip = False
                self.out: List[str] = []

            def handle_starttag(self, tag: str, attrs: Any) -> None:
                t = tag.lower()
                if t in ("script", "style", "noscript"):
                    self.skip = True
                elif t in ("h1", "h2", "h3"):
                    self.out.append("\n" + "#" * int(t[1]) + " ")
                elif t == "li":
                    self.out.append("\n- ")
                elif t in ("p", "div", "br"):
                    self.out.append("\n")

            def handle_endtag(self, tag: str) -> None:
                if tag.lower() in ("script", "style", "noscript"):
                    self.skip = False

            def handle_data(self, data: str) -> None:
                if not self.skip and data.strip():
                    self.out.append(data.strip() + " ")

        p = _MDParser()
        p.feed(raw_html)
        md = re.sub(r"\n{3,}", "\n\n", "".join(p.out)).strip()
        return {"ok": True, "rail": rail_name, "markdown": md}

    if rail_name == "html_table_to_json":
        raw_html = str(args.get("html") or "")
        rows_raw = re.findall(r"(?is)<tr[^>]*>(.*?)</tr>", raw_html)
        matrix: List[List[str]] = []
        for r in rows_raw:
            cells = [re.sub(r"<[^>]+>", "", c).strip() for c in re.findall(r"(?is)<t[dh][^>]*>(.*?)</t[dh]>", r)]
            if cells:
                matrix.append(cells)
        return {"ok": True, "rail": rail_name, "row_count": len(matrix), "rows": matrix}

    if rail_name == "html_meta_opengraph_extractor":
        raw_html = str(args.get("html") or "")
        title_m = re.search(r"(?is)<title[^>]*>(.*?)</title>", raw_html)
        metas: Dict[str, str] = {}
        for m in re.finditer(r'(?is)<meta\s+[^>]*?(?:name|property)=["\']([^"\']+)["\'][^>]*?content=["\']([^"\']*)["\']', raw_html):
            metas[m.group(1)] = m.group(2)
        return {"ok": True, "rail": rail_name, "title": (title_m.group(1).strip() if title_m else ""), "meta": metas}

    if rail_name == "sitemap_robots_parser":
        txt = str(args.get("content") or "")
        disallow = [ln.split(":", 1)[1].strip() for ln in txt.splitlines() if ln.lower().startswith("disallow:")]
        locs = re.findall(r"<loc>(.*?)</loc>", txt)
        return {"ok": True, "rail": rail_name, "disallow_rules": disallow, "sitemap_urls": locs}

    if rail_name == "url_normalizer_and_deparam":
        raw_url = str(args.get("url") or "https://example.com/page?utm_source=ads&id=42&fbclid=abc")
        u = urlparse(raw_url)
        drop_prefixes = ("utm_", "fbclid", "gclid", "mc_cid", "msclkid")
        clean_q = [(k, v) for k, v in parse_qsl(u.query) if not any(k.lower().startswith(p) for p in drop_prefixes)]
        norm = urlunparse((u.scheme.lower(), u.netloc.lower(), u.path or "/", "", urlencode(sorted(clean_q)), ""))
        return {"ok": True, "rail": rail_name, "original": raw_url, "normalized": norm}

    if rail_name == "css_selector_locator_gen":
        raw_html = str(args.get("html") or "")
        selectors: List[Dict[str, str]] = []
        for m in re.finditer(r"(?is)<(button|input|a|select)\b([^>]*)>", raw_html):
            tag, attrs = m.group(1).lower(), m.group(2)
            id_m = re.search(r'\bid=["\']([^"\']+)["\']', attrs)
            tid_m = re.search(r'\bdata-testid=["\']([^"\']+)["\']', attrs)
            name_m = re.search(r'\bname=["\']([^"\']+)["\']', attrs)
            if tid_m:
                selectors.append({"tag": tag, "selector": f'[data-testid="{tid_m.group(1)}"]'})
            elif id_m:
                selectors.append({"tag": tag, "selector": f"#{id_m.group(1)}"})
            elif name_m:
                selectors.append({"tag": tag, "selector": f'{tag}[name="{name_m.group(1)}"]'})
        return {"ok": True, "rail": rail_name, "selectors": selectors}

    if rail_name == "accessibility_aria_tree_dump":
        raw_html = str(args.get("html") or "")
        nodes: List[Dict[str, str]] = []
        for m in re.finditer(r"(?is)<(button|a|input|h[1-6]|nav|main)\b([^>]*)>(.*?)</\1>", raw_html):
            role_m = re.search(r'\brole=["\']([^"\']+)["\']', m.group(2))
            label_m = re.search(r'\baria-label=["\']([^"\']+)["\']', m.group(2))
            text = re.sub(r"<[^>]+>", "", m.group(3)).strip()
            nodes.append({"tag": m.group(1).lower(), "role": (role_m.group(1) if role_m else m.group(1).lower()), "label": (label_m.group(1) if label_m else text[:80])})
        return {"ok": True, "rail": rail_name, "aria_node_count": len(nodes), "nodes": nodes}

    if rail_name == "har_network_analyzer":
        har = args.get("har") or {}
        entries = ((har.get("log") or {}).get("entries") or []) if isinstance(har, dict) else []
        errors = [e for e in entries if int(((e.get("response") or {}).get("status") or 200)) >= 400]
        return {"ok": True, "rail": rail_name, "total_requests": len(entries), "error_requests": len(errors)}

    if rail_name == "pdf_type_classifier":
        raw = args.get("pdf_bytes") or b"%PDF-1.4\n/Type /Page /Font /Text"
        if isinstance(raw, str):
            raw = raw.encode("latin-1", errors="replace")
        pages = max(1, raw.count(b"/Type /Page") - raw.count(b"/Type /Pages"))
        has_text = b"/Font" in raw or b"BT" in raw
        return {"ok": True, "rail": rail_name, "page_count": pages, "classification": ("text_native" if has_text else "scanned_image")}

    if rail_name == "markdown_toc_and_links_audit":
        md = str(args.get("markdown") or "")
        if not md and args.get("file_path"):
            md = _safe_path(ws, str(args["file_path"])).read_text(encoding="utf-8", errors="replace")
        headings = [{"level": len(m.group(1)), "title": m.group(2).strip()} for m in re.finditer(r"(?m)^(#{1,6})\s+(.+)$", md)]
        links = re.findall(r"\[[^\]]+\]\(([^)]+)\)", md)
        return {"ok": True, "rail": rail_name, "headings": headings, "link_count": len(links), "links": links[:50]}

    if rail_name == "rss_atom_feed_parser":
        xml_txt = str(args.get("xml") or "<rss><channel><item><title>News</title><link>https://example.com</link></item></channel></rss>")
        root = ET.fromstring(xml_txt)
        items = [{"title": (it.findtext("title") or "").strip(), "link": (it.findtext("link") or "").strip()} for it in root.findall(".//item")]
        return {"ok": True, "rail": rail_name, "item_count": len(items), "items": items}

    # --- DOMAIN E: WINDOWS OS, DESKTOP, PROCESSES & HARDWARE (80-90) ---
    if rail_name in (
        "win_service_inspector",
        "win_scheduled_tasks_audit",
        "win_startup_programs_audit",
        "win_event_log_triage",
        "win_network_connections",
        "win_dns_and_hosts_audit",
        "win_winget_package_audit",
        "win_clipboard_inspect",
        "win_temp_hygiene_analyzer",
        "win_power_and_battery_probe",
        "win_dll_pe_header_inspect",
    ):
        if rail_name == "win_temp_hygiene_analyzer":
            tdir = Path(tempfile.gettempdir())
            cnt = 0
            total_b = 0
            for p in list(tdir.glob("*"))[:200]:
                try:
                    if p.is_file():
                        cnt += 1
                        total_b += p.stat().st_size
                except OSError:
                    continue
            return {"ok": True, "rail": rail_name, "temp_dir": str(tdir), "sampled_files": cnt, "sampled_bytes": total_b}

        if rail_name == "win_power_and_battery_probe":
            return {"ok": True, "rail": rail_name, "cpu_count": os.cpu_count() or 1, "platform": sys.platform}

        if rail_name == "win_dll_pe_header_inspect":
            pe_bytes = args.get("pe_bytes")
            if pe_bytes is None and args.get("file_path"):
                pe_bytes = _safe_path(ws, str(args["file_path"])).read_bytes()[:1024]
            if not pe_bytes:
                pe_bytes = Path(sys.executable).read_bytes()[:1024]
            is_mz = pe_bytes[:2] == b"MZ"
            machine = "unknown"
            if is_mz and len(pe_bytes) >= 64:
                pe_off = struct.unpack("<I", pe_bytes[60:64])[0]
                if pe_off + 6 <= len(pe_bytes) and pe_bytes[pe_off : pe_off + 4] == b"PE\x00\x00":
                    m_code = struct.unpack("<H", pe_bytes[pe_off + 4 : pe_off + 6])[0]
                    machine = {0x8664: "x86_64", 0x014C: "x86", 0xAA64: "ARM64"}.get(m_code, hex(m_code))
            return {"ok": is_mz, "rail": rail_name, "valid_mz_header": is_mz, "architecture": machine}

        if rail_name == "win_dns_and_hosts_audit":
            hosts_p = Path(r"C:\Windows\System32\drivers\etc\hosts") if os.name == "nt" else Path("/etc/hosts")
            entries = []
            if hosts_p.is_file():
                entries = [ln.strip() for ln in hosts_p.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip() and not ln.strip().startswith("#")]
            return {"ok": True, "rail": rail_name, "hosts_path": str(hosts_p), "custom_entry_count": len(entries), "entries": entries[:25]}

        from am_ua.execution.apex_v62_extracts import execute_real_win_os_rail

        return execute_real_win_os_rail(rail_name, ws, args=args)

    # --- DOMAIN F: SECURITY, CRYPTOGRAPHY, MATH & SANDBOXING (91-100) ---
    if rail_name == "jwt_token_inspector":
        tok = str(args.get("token") or "")
        parts = tok.split(".")
        if len(parts) < 2:
            return {"ok": False, "rail": rail_name, "error": "Invalid JWT format"}
        pad_h = parts[0] + "=" * (-len(parts[0]) % 4)
        pad_p = parts[1] + "=" * (-len(parts[1]) % 4)
        hdr = json.loads(base64.urlsafe_b64decode(pad_h).decode("utf-8"))
        pay = json.loads(base64.urlsafe_b64decode(pad_p).decode("utf-8"))
        return {"ok": True, "rail": rail_name, "header": hdr, "payload": pay}

    if rail_name == "tls_certificate_inspector":
        import ssl
        return {"ok": True, "rail": rail_name, "openssl_version": ssl.OPENSSL_VERSION}

    if rail_name == "secret_entropy_scanner":
        text = str(args.get("text") or "")
        high_entropy: List[Dict[str, Any]] = []
        for tok in re.findall(r"[A-Za-z0-9_/+=-]{20,}", text):
            freq = {ch: tok.count(ch) / len(tok) for ch in set(tok)}
            ent = -sum(p * math.log2(p) for p in freq.values())
            if ent >= 4.2:
                high_entropy.append({"token_prefix": tok[:6] + "***", "length": len(tok), "entropy": round(ent, 3)})
        return {"ok": len(high_entropy) == 0, "rail": rail_name, "high_entropy_tokens": high_entropy}

    if rail_name == "pii_redaction_rail":
        text = str(args.get("text") or "")
        redacted = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[REDACTED_EMAIL]", text)
        redacted = re.sub(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b", "[REDACTED_CPF]", redacted)
        redacted = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]", redacted)
        return {"ok": True, "rail": rail_name, "redacted_text": redacted, "changed": redacted != text}

    if rail_name == "cron_expression_evaluator":
        expr = str(args.get("cron") or "*/5 * * * *").strip()
        fields = expr.split()
        valid = len(fields) == 5
        return {"ok": valid, "rail": rail_name, "cron": expr, "fields": fields if valid else []}

    if rail_name == "math_symbolic_evaluator":
        nums = [float(x) for x in (args.get("values") or [10, 20, 30, 40, 50])]
        return {
            "ok": True,
            "rail": rail_name,
            "count": len(nums),
            "sum": sum(nums),
            "mean": round(statistics.mean(nums), 6),
            "median": round(statistics.median(nums), 6),
            "stdev": round(statistics.pstdev(nums), 6),
        }

    if rail_name == "financial_irr_npv_calculator":
        rate = Decimal(str(args.get("discount_rate") or "0.10"))
        cashflows = [Decimal(str(c)) for c in (args.get("cashflows") or ["-1000", "400", "400", "500"])]
        npv = sum((cf / ((Decimal("1") + rate) ** idx) for idx, cf in enumerate(cashflows)), Decimal("0"))
        return {"ok": True, "rail": rail_name, "discount_rate": str(rate), "npv": str(round(npv, 4))}

    if rail_name == "rbac_policy_simulator":
        role = str(args.get("role") or "viewer")
        action = str(args.get("action") or "read")
        matrix = args.get("policy") or {"admin": ["read", "write", "delete"], "editor": ["read", "write"], "viewer": ["read"]}
        allowed = action in (matrix.get(role) or [])
        return {"ok": True, "rail": rail_name, "role": role, "action": action, "allowed": allowed}

    if rail_name == "sandbox_escape_auditor":
        snippet = str(args.get("code") or "")
        vectors = [v for v in ("../", "/etc/passwd", "ctypes.windll", "docker.sock", "nsenter", "chroot") if v in snippet]
        return {"ok": len(vectors) == 0, "rail": rail_name, "escape_vectors_found": vectors}

    if rail_name == "deterministic_batch_pipeline":
        steps = list(args.get("steps") or [])
        results: List[Dict[str, Any]] = []
        for st in steps:
            r_name = str(st.get("rail") or "")
            r_params = dict(st.get("params") or {})
            if execute_rail_fn is not None and r_name and r_name != "deterministic_batch_pipeline":
                results.append(execute_rail_fn(r_name, ws, params=r_params))
        return {"ok": all(r.get("ok", False) for r in results), "rail": rail_name, "steps_executed": len(results), "results": results}

    # --- DOMAIN G: OPENHANDS V1 SDK MAXIMUM EXTRACTION ORGANS (101-105) ---
    if rail_name == "stuck_loop_detector":
        from am_ua.execution.openhands_organs import OpenHandsStuckDetector

        res = OpenHandsStuckDetector().analyze(list(args.get("events") or []))
        return {"rail": rail_name, **res.to_dict()}

    if rail_name == "shell_policy_rails_audit":
        from am_ua.execution.openhands_organs import ShellSemanticPolicyRails

        res = ShellSemanticPolicyRails.analyze_command(str(args.get("command") or ""))
        return {"rail": rail_name, **res}

    if rail_name == "v4a_multifile_patch":
        from am_ua.execution.openhands_organs import V4AMultiFilePatchEngine

        res = V4AMultiFilePatchEngine.apply_patch(
            ws,
            str(args.get("patch_text") or ""),
            dry_run=bool(args.get("dry_run", False)),
        )
        return {"rail": rail_name, **res}

    if rail_name == "trajectory_critic_eval":
        from am_ua.execution.openhands_organs import TrajectoryCritic

        res = TrajectoryCritic().evaluate(
            list(args.get("events") or []),
            git_patch=args.get("git_patch"),
            require_patch=bool(args.get("require_patch", True)),
            verify_passed=args.get("verify_passed"),
        )
        return {"rail": rail_name, **res.to_dict()}

    if rail_name == "tom_intent_consultant":
        from am_ua.execution.openhands_organs import ToMIntentConsultant

        res = ToMIntentConsultant.consult(
            str(args.get("user_message") or ""),
            prior_preferences=args.get("prior_preferences"),
        )
        return {"rail": rail_name, **res}

    if rail_name == "sleeptime_compute_indexer":
        from am_ua.execution.openhands_organs import SleeptimeComputeEngine

        res = SleeptimeComputeEngine.index_trajectories(
            ws,
            list(args.get("trajectories") or []),
            out_rel_path=str(args.get("out_rel_path") or ".omni_sleeptime_profile.json"),
        )
        return {"rail": rail_name, **res}

    if rail_name == "ask_oracle_dilemma":
        from am_ua.execution.openhands_organs import AskOracleConsultant

        res = AskOracleConsultant.consult_oracle(
            str(args.get("question") or ""),
            context=args.get("context"),
            approaches_tried=args.get("approaches_tried"),
        )
        return {"rail": rail_name, **res}

    if rail_name == "planning_file_editor_rail":
        from am_ua.execution.openhands_organs import PlanningFileEditorGate

        gate = PlanningFileEditorGate(ws)
        res = gate.edit_plan_file(str(args.get("plan_path") or "PLAN.md"), str(args.get("content") or "# Plan\n"))
        return {"rail": rail_name, **res}

    if rail_name == "stateful_python_kernel_rail":
        from am_ua.execution.openhands_organs import StatefulPythonSessionKernel

        kernel = StatefulPythonSessionKernel(ws)
        for cell in list(args.get("cells") or [str(args.get("code") or "x = 40 + 2")]):
            last = kernel.run_cell(str(cell))
        return {"rail": rail_name, **last}

    if rail_name == "inbound_debounce_triage":
        from am_ua.execution.openhands_organs import InboundDebounceTriageEngine

        if args.get("plan_markdown"):
            res = InboundDebounceTriageEngine.audit_plan_review(str(args["plan_markdown"]))
        else:
            res = InboundDebounceTriageEngine.coalesce_burst_messages(
                list(args.get("messages") or []),
                debounce_window_s=float(args.get("debounce_window_s", 2.5)),
            )
        return {"rail": rail_name, **res}

    # --- DOMAIN H: SUB-MILLISECOND TOKEN & LATENCY SAVERS (111-120) ---
    if rail_name == "ast_skeleton_compress":
        from am_ua.execution.token_latency_savers import ast_skeleton_compress

        src = str(args.get("source_code") or "")
        if not src and args.get("file_path"):
            src = _safe_path(ws, str(args["file_path"])).read_text(encoding="utf-8", errors="replace")
        return {"rail": rail_name, **ast_skeleton_compress(src)}

    if rail_name == "comby_template_rewrite":
        from am_ua.execution.token_latency_savers import comby_template_rewrite

        return {
            "rail": rail_name,
            **comby_template_rewrite(
                str(args.get("source_text") or ""),
                str(args.get("match_template") or ""),
                str(args.get("rewrite_template") or ""),
            ),
        }

    if rail_name == "prompt_token_pruner":
        from am_ua.execution.token_latency_savers import prompt_token_pruner

        return {"rail": rail_name, **prompt_token_pruner(str(args.get("text") or ""))}

    if rail_name == "grammar_json_repair":
        from am_ua.execution.token_latency_savers import grammar_json_repair

        return {"rail": rail_name, **grammar_json_repair(str(args.get("malformed_text") or ""))}

    if rail_name == "delta_debug_minimizer":
        from am_ua.execution.token_latency_savers import delta_debug_minimizer

        return {
            "rail": rail_name,
            **delta_debug_minimizer(
                list(args.get("items") or []),
                fail_trigger_substring=str(args.get("fail_trigger_substring") or "ERROR"),
            ),
        }

    if rail_name == "dom_semantic_distiller":
        from am_ua.execution.token_latency_savers import dom_semantic_distiller

        return {"rail": rail_name, **dom_semantic_distiller(str(args.get("html") or ""))}

    if rail_name == "pyupgrade_modernizer":
        from am_ua.execution.token_latency_savers import pyupgrade_modernizer

        return {"rail": rail_name, **pyupgrade_modernizer(str(args.get("source_code") or ""))}

    if rail_name == "gitleaks_precommit_gate":
        from am_ua.execution.token_latency_savers import gitleaks_precommit_gate

        return {"rail": rail_name, **gitleaks_precommit_gate(str(args.get("text") or ""))}

    if rail_name == "semantic_cache_lookup":
        from am_ua.execution.token_latency_savers import SimHashSemanticCache

        cache = SimHashSemanticCache(max_hamming_distance=int(args.get("max_hamming_distance", 4)))
        for entry in list(args.get("seed_entries") or []):
            cache.put(str(entry.get("prompt") or ""), entry.get("response"))
        return {"rail": rail_name, **cache.lookup(str(args.get("prompt") or ""))}

    if rail_name == "pytest_affected_test_selector":
        from am_ua.execution.token_latency_savers import pytest_affected_test_selector

        return {
            "rail": rail_name,
            **pytest_affected_test_selector(ws, list(args.get("modified_files") or [])),
        }

    return None
