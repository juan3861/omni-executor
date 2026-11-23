from __future__ import annotations

import ast
import csv
from dataclasses import dataclass
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional


from am_ua.execution.offloader_shared import (
    BUILTIN_DETERMINISTIC_RAILS,
    _SKIP_DIRS,
    _iter_py_files,
    _resolve_in_workspace,
)

def off_fastmft_radar(
    cls,
    workspace: Path,
    *,
    mode: str = "projects",
    target: str = ".",
    top: int = 20,
    dry_run: bool = True,
) -> Dict[str, Any]:
    """Symbiotic fastmft / AetherScan v1.3.0 rail: projects, Casimir advise + UCIP, and safe parasite cleanup."""
    from am_ua.governance.homeostasis import casimir_bistable_diagnostics

    ws = Path(workspace).resolve()
    tgt = _resolve_in_workspace(ws, target)
    if not tgt.exists():
        return {"ok": False, "error": f"Target does not exist: {target}"}

    mode_norm = (mode or "projects").strip().lower()
    if mode_norm not in ("projects", "advise", "clean_parasites"):
        return {"ok": False, "error": f"Unsupported fastmft_radar mode: {mode_norm} (use projects|advise|clean_parasites)"}

    safe_clean_names = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".turbo"}
    all_parasite_names = safe_clean_names | {"node_modules", "target", ".venv", "venv", "dist", "build", ".next"}
    project_markers = {
        ".git": "git",
        "pyproject.toml": "python",
        "requirements.txt": "python",
        "package.json": "node",
        "cargo.toml": "rust",
        "go.mod": "go",
        "cmakelists.txt": "cpp",
        "pom.xml": "java",
    }

    t0 = time.perf_counter()

    def _scan_parasites_local(root: Path, allowed_names: set[str]) -> List[Dict[str, Any]]:
        found: List[Dict[str, Any]] = []
        for dirpath, dirnames, _ in os.walk(root):
            matched = [d for d in dirnames if d in allowed_names]
            for d in matched:
                p_dir = Path(dirpath) / d
                p_bytes = 0
                p_files = 0
                for sr, _, sf in os.walk(p_dir):
                    for fn in sf:
                        try:
                            p_bytes += (Path(sr) / fn).stat().st_size
                            p_files += 1
                        except OSError:
                            continue
                found.append({
                    "name": d,
                    "rel_path": p_dir.relative_to(ws).as_posix(),
                    "bytes": p_bytes,
                    "files": p_files,
                })
            dirnames[:] = [d for d in dirnames if d not in allowed_names and d != ".git"]
        found.sort(key=lambda x: x["bytes"], reverse=True)
        return found

    if mode_norm == "clean_parasites":
        parasites = _scan_parasites_local(tgt, safe_clean_names)
        removed: List[str] = []
        reclaimed_bytes = 0
        if not dry_run:
            for item in parasites:
                p_full = _resolve_in_workspace(ws, item["rel_path"])
                if p_full.is_dir():
                    shutil.rmtree(p_full, ignore_errors=True)
                    if not p_full.exists():
                        removed.append(item["rel_path"])
                        reclaimed_bytes += int(item["bytes"])
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        return {
            "ok": True,
            "backend": "fastmft_parasite_cleaner",
            "mode": "clean_parasites",
            "dry_run": bool(dry_run),
            "elapsed_ms": elapsed_ms,
            "parasite_count": len(parasites),
            "total_parasite_bytes": sum(int(p["bytes"]) for p in parasites),
            "removed_count": len(removed),
            "reclaimed_bytes": reclaimed_bytes,
            "removed": removed[:50],
            "parasites": parasites[:50],
        }

    fm_bin = cls._find_fastmft()

    if mode_norm == "advise":
        if fm_bin and os.name == "nt":
            temp_base = Path(r"F:\AetherMind_Temp\fastmft_rail")
            if temp_base.parent.exists():
                temp_base.mkdir(parents=True, exist_ok=True)
                out_dir = Path(tempfile.mkdtemp(prefix="advise_", dir=str(temp_base)))
            else:
                out_dir = Path(tempfile.mkdtemp(prefix="fastmft_advise_"))
            try:
                env = os.environ.copy()
                if temp_base.parent.exists():
                    env["TMP"] = str(temp_base.parent)
                    env["TEMP"] = str(temp_base.parent)
                proc = subprocess.run(
                    [fm_bin, "advise", str(tgt), "--top", str(max(1, int(top))), "--out", str(out_dir)],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    env=env,
                    timeout=60,
                    check=False,
                )
                rep_file = out_dir / "advise_report.json"
                ucip_file = out_dir / "ucip_map.txt"
                if proc.returncode == 0 and rep_file.is_file():
                    rep_data = json.loads(rep_file.read_text(encoding="utf-8", errors="replace"))
                    ucip_txt = ucip_file.read_text(encoding="utf-8", errors="replace") if ucip_file.is_file() else str(rep_data.get("ucip_compact_protocol", ""))
                    return {
                        "ok": True,
                        "backend": "fastmft_v1.3.0",
                        "mode": "advise",
                        "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 2),
                        "casimir": rep_data.get("casimir_bistable_model", {}),
                        "relocation_candidates": (rep_data.get("relocation_candidates") or [])[:top],
                        "projects": (rep_data.get("discovered_projects") or [])[:top],
                        "ucip_compact": ucip_txt.strip(),
                    }
            finally:
                shutil.rmtree(out_dir, ignore_errors=True)

        # Portable deterministic fallback (Linux / CI / host without fastmft binary)
        du = shutil.disk_usage(tgt)
        parasites = _scan_parasites_local(tgt, all_parasite_names)
        reclaimable = sum(int(p["bytes"]) for p in parasites)
        cas = casimir_bistable_diagnostics(du.free, du.total, reclaimable_bytes=reclaimable)
        projects: List[Dict[str, Any]] = []
        for dirpath, dirnames, filenames in os.walk(tgt):
            dirnames[:] = [d for d in dirnames if d not in all_parasite_names]
            markers = []
            for name in list(dirnames) + list(filenames):
                tag = project_markers.get(name.lower())
                if tag and tag not in markers:
                    markers.append(tag)
            if markers:
                projects.append({"path": Path(dirpath).as_posix(), "markers": markers})
            dirnames[:] = [d for d in dirnames if d != ".git"]
        elapsed_s = round(time.perf_counter() - t0, 3)
        vol_label = tgt.drive or "/"
        ucip_line = (
            f"§UCIP:1.2|VOL:{vol_label}|SCAN:{elapsed_s:.3f}s|"
            f"TOT:{du.total // (1024**3)}GB|FREE:{du.free // (1024**3)}GB|"
            f"GAP_D:{cas['normalized_gap_d']:.4f}|FC:{cas['casimir_force_fc']:.1f}|"
            f"U:{cas['bistable_potential_u']:.3f}|STATE:{cas['regime_state']}|"
            f"POST_FREE:{cas['post_move_free_bytes'] // (1024**3)}GB"
        )
        return {
            "ok": True,
            "backend": "python_fastmft_fallback",
            "mode": "advise",
            "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 2),
            "casimir": cas,
            "relocation_candidates": [],
            "projects": projects[:top],
            "ucip_compact": ucip_line,
        }

    # Default mode == "projects"
    parasites = _scan_parasites_local(tgt, all_parasite_names)
    total_p_bytes = sum(int(p["bytes"]) for p in parasites)
    raw_stdout = ""
    backend = "python_fastmft_fallback"
    if fm_bin and os.name == "nt":
        proc = subprocess.run(
            [fm_bin, "projects", str(tgt), "--parasites", "--top", str(max(1, int(top)))],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            check=False,
        )
        if proc.returncode == 0:
            backend = "fastmft_v1.3.0"
            raw_stdout = (proc.stdout or "")[:3000]

    projects_list: List[Dict[str, Any]] = []
    for dirpath, dirnames, filenames in os.walk(tgt):
        markers = []
        for name in list(dirnames) + list(filenames):
            tag = project_markers.get(name.lower())
            if tag and tag not in markers:
                markers.append(tag)
        if markers:
            projects_list.append({
                "path": Path(dirpath).relative_to(ws).as_posix() or ".",
                "markers": markers,
            })
        dirnames[:] = [d for d in dirnames if d not in all_parasite_names and d != ".git"]

    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    p_sig = ",".join(f"{p['rel_path']}:{p['bytes']//1024}K" for p in parasites[:8]) or "none"
    ucip_proj = f"§UCIP:PROJECTS|ROOT:{tgt.name}|BACKEND:{backend}|MS:{elapsed_ms}|PROJS:{len(projects_list)}|PARASITES_KB:{total_p_bytes//1024}|TOP:{p_sig}"
    return {
        "ok": True,
        "backend": backend,
        "mode": "projects",
        "elapsed_ms": elapsed_ms,
        "projects_found": len(projects_list),
        "projects": projects_list[:top],
        "parasite_count": len(parasites),
        "total_parasite_bytes": total_p_bytes,
        "parasites": parasites[:top],
        "ucip_compact": ucip_proj,
        "native_report_excerpt": raw_stdout,
    }

def off_windows_system_rail(
    cls,
    workspace: Path,
    *,
    sub_action: str = "probe",
    target: str = "",
    port: Optional[int] = None,
) -> Dict[str, Any]:
    """Pre-built 0-token Windows Desktop & OS rail (UIA/windows/processes/ports/storage/Casimir)."""
    from am_ua.governance.homeostasis import casimir_bistable_diagnostics

    act = (sub_action or "probe").strip().lower()
    du = shutil.disk_usage(workspace)
    cas = casimir_bistable_diagnostics(du.free, du.total)
    if act == "storage_health":
        return {"ok": True, "backend": "windows_system_rail", "sub_action": act, "casimir": cas}

    if os.name == "nt":
        try:
            from am_ua.execution.pc_automation import PCAutomationEngine

            pc = PCAutomationEngine()
            if act == "windows":
                return {"ok": True, "backend": "win32_uia", "sub_action": act, "windows": pc.list_windows(filter_text=target)[:40]}
            if act == "processes":
                return {"ok": True, "backend": "win32_proc", "sub_action": act, "processes": pc.window_organ.list_processes(name_filter=target)[:40]}
            if act == "port_owner" and port is not None:
                return {"ok": True, "backend": "win32_net", "sub_action": act, "port_info": pc.window_organ.find_port_owner(int(port))}
            probe = pc.probe_capabilities()
            return {"ok": True, "backend": "win32_pc_automation", "sub_action": "probe", "capabilities": probe, "casimir": cas}
        except Exception as exc:
            return {"ok": True, "backend": "portable_os_probe", "sub_action": act, "note": str(exc)[:200], "casimir": cas}

    return {
        "ok": True,
        "backend": "portable_os_probe",
        "sub_action": act,
        "platform": sys.platform,
        "casimir": cas,
    }

def off_browser_playbook_rail(
    cls,
    workspace: Path,
    *,
    sub_action: str = "extract_links_forms",
    file_path: Optional[str] = None,
    html: Optional[str] = None,
    url: Optional[str] = None,
    allowed_domains: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Pre-built 0-token Browser & Web extraction/guard rail (links, inputs, forms, tables, domain check)."""
    from html.parser import HTMLParser

    act = (sub_action or "extract_links_forms").strip().lower()
    if act == "domain_check" and url:
        import ipaddress
        from urllib.parse import urlparse

        host = (urlparse(str(url)).hostname or "").strip().lower()
        if not host:
            return {"ok": False, "backend": "deterministic_domain_guard", "url": url, "allowed": False, "reason": "missing hostname"}
        try:
            ip = ipaddress.ip_address(host.strip("[]"))
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return {"ok": False, "backend": "deterministic_domain_guard", "url": url, "allowed": False, "reason": "private/loopback IP blocked"}
        except ValueError:
            pass
        allow_list = [d.strip().lower() for d in (allowed_domains or []) if d and d.strip()]
        if allow_list and not any(host == d or host.endswith("." + d.lstrip("*.")) for d in allow_list):
            return {"ok": False, "backend": "deterministic_domain_guard", "url": url, "allowed": False, "reason": f"host '{host}' not in allowed_domains"}
        return {"ok": True, "backend": "deterministic_domain_guard", "url": url, "allowed": True, "reason": "allowed"}

    raw_html = str(html or "")
    if not raw_html and file_path:
        p = _resolve_in_workspace(Path(workspace).resolve(), str(file_path))
        if not p.is_file():
            return {"ok": False, "error": f"HTML file not found: {file_path}"}
        raw_html = p.read_text(encoding="utf-8", errors="replace")

    class _DOMExtractor(HTMLParser):
        def __init__(self) -> None:
            super().__init__()
            self.links: List[Dict[str, str]] = []
            self.inputs: List[Dict[str, str]] = []
            self.buttons: List[Dict[str, str]] = []
            self._cur_btn: Optional[Dict[str, str]] = None

        def handle_starttag(self, tag: str, attrs: List[tuple[str, Optional[str]]]) -> None:
            ad = {k.lower(): (v or "") for k, v in attrs}
            t = tag.lower()
            if t == "a" and ad.get("href"):
                self.links.append({"href": ad["href"], "id": ad.get("id", "")})
            elif t in ("input", "select", "textarea"):
                self.inputs.append({"tag": t, "id": ad.get("id", ""), "name": ad.get("name", ""), "type": ad.get("type", "text")})
            elif t == "button":
                self._cur_btn = {"id": ad.get("id", ""), "type": ad.get("type", "button"), "text": ""}

        def handle_data(self, data: str) -> None:
            if self._cur_btn is not None:
                self._cur_btn["text"] += data.strip()

        def handle_endtag(self, tag: str) -> None:
            if tag.lower() == "button" and self._cur_btn is not None:
                self.buttons.append(self._cur_btn)
                self._cur_btn = None

    parser = _DOMExtractor()
    parser.feed(raw_html)
    return {
        "ok": True,
        "backend": "deterministic_dom_extractor",
        "sub_action": act,
        "link_count": len(parser.links),
        "input_count": len(parser.inputs),
        "button_count": len(parser.buttons),
        "links": parser.links[:50],
        "inputs": parser.inputs[:50],
        "buttons": parser.buttons[:50],
    }

def off_patch_validate_and_apply(
    cls,
    workspace: Path,
    *,
    file_path: str,
    old_text: str,
    new_text: str,
    apply: bool = False,
) -> Dict[str, Any]:
    """Deterministically validate a code replacement in memory (including AST check) and optionally apply it."""
    ws = Path(workspace).resolve()
    if not file_path:
        return {"ok": False, "error": "file_path is required"}
    target = _resolve_in_workspace(ws, file_path)
    if not target.is_file():
        return {"ok": False, "error": f"File not found: {file_path}"}
    src = target.read_text(encoding="utf-8", errors="replace")
    occurrences = src.count(old_text)
    if not old_text or occurrences != 1:
        return {
            "ok": False,
            "valid_patch": False,
            "applied": False,
            "occurrences": occurrences,
            "error": f"Expected old_text to match exactly once, matched {occurrences} times",
        }
    patched = src.replace(old_text, new_text, 1)
    if target.suffix.lower() == ".py":
        try:
            ast.parse(patched, filename=str(target))
        except SyntaxError as exc:
            return {
                "ok": False,
                "valid_patch": False,
                "applied": False,
                "syntax_error": f"Line {exc.lineno}: {exc.msg}",
            }
    if apply:
        target.write_text(patched, encoding="utf-8", newline="\n")
    return {
        "ok": True,
        "backend": "atomic_ast_patch_verifier",
        "valid_patch": True,
        "applied": bool(apply),
        "file": target.relative_to(ws).as_posix(),
    }

def off_ledger_audit(
    cls,
    *,
    entries: Optional[List[Dict[str, Any]]] = None,
    file_path: Optional[str] = None,
    workspace: Optional[Path] = None,
) -> Dict[str, Any]:
    """Rillet/Basis-style deterministic double-entry accounting ledger verifier using exact Decimal math."""
    from decimal import Decimal, InvalidOperation

    rows: List[Dict[str, Any]] = []
    if entries is not None:
        rows = list(entries)
    elif file_path and workspace is not None:
        p = _resolve_in_workspace(Path(workspace).resolve(), str(file_path))
        if not p.is_file():
            return {"ok": False, "error": f"Ledger file not found: {file_path}"}
        if p.suffix.lower() == ".json":
            loaded = json.loads(p.read_text(encoding="utf-8", errors="replace"))
            rows = loaded if isinstance(loaded, list) else list(loaded.get("entries", []))
        else:
            with p.open("r", encoding="utf-8", errors="replace", newline="") as fh:
                rows = list(csv.DictReader(fh))
    else:
        return {"ok": False, "error": "Provide 'entries' list or 'file_path' (.json/.csv) for ledger_audit"}

    total_debits = Decimal("0")
    total_credits = Decimal("0")
    by_tx: Dict[str, Dict[str, Decimal]] = {}
    account_balances: Dict[str, Decimal] = {}
    parse_errors: List[str] = []

    for idx, row in enumerate(rows):
        tx_id = str(row.get("tx_id") or row.get("journal_id") or f"tx_{idx}")
        acct = str(row.get("account") or "UNSPECIFIED")
        try:
            debit = Decimal(str(row.get("debit") or "0"))
            credit = Decimal(str(row.get("credit") or "0"))
        except (InvalidOperation, ValueError) as exc:
            parse_errors.append(f"Row {idx} ({tx_id}): invalid decimal ({exc})")
            continue
        if debit < 0 or credit < 0:
            parse_errors.append(f"Row {idx} ({tx_id}): negative debit/credit not allowed")
            continue
        total_debits += debit
        total_credits += credit
        bucket = by_tx.setdefault(tx_id, {"debit": Decimal("0"), "credit": Decimal("0")})
        bucket["debit"] += debit
        bucket["credit"] += credit
        account_balances[acct] = account_balances.get(acct, Decimal("0")) + (debit - credit)

    unbalanced_txs = [
        {
            "tx_id": tid,
            "debit": str(b["debit"]),
            "credit": str(b["credit"]),
            "delta": str(b["debit"] - b["credit"]),
        }
        for tid, b in sorted(by_tx.items())
        if b["debit"] != b["credit"]
    ]
    net_delta = total_debits - total_credits
    balanced = (net_delta == Decimal("0")) and not unbalanced_txs and not parse_errors
    return {
        "ok": balanced,
        "backend": "decimal_double_entry_ledger",
        "entries_checked": len(rows),
        "transactions_checked": len(by_tx),
        "total_debits": str(total_debits),
        "total_credits": str(total_credits),
        "net_delta": str(net_delta),
        "balanced": balanced,
        "unbalanced_transactions": unbalanced_txs[:50],
        "parse_errors": parse_errors[:50],
        "account_balances": {k: str(v) for k, v in sorted(account_balances.items())},
    }
