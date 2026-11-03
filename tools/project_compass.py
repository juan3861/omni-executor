#!/usr/bin/env python3
"""Project Compass — Anti-Amnesia & Anti-Drift Continuation Engine.

Guarantees that ANY agent (Antigravity, Gemini CLI, Codex, Claude Code, Hermes,
Cursor) or human engineer entering `F:\\AetherMind_Universal_Agent` immediately
knows:
  1. What the Grand Narrative ("Why") and Immutable Constraints are,
  2. Exactly which Phases/Subphases are VERIFIED with real SHA-256 & test proofs,
  3. Whether any file drifted or was edited mid-crash since the last checkpoint,
  4. The EXACT next subphase to execute, its required files, symbols, and tests.

Fail-closed rule: A subphase CANNOT be marked VERIFIED unless:
  - All upstream `depends_on` subphases are VERIFIED,
  - All `required_files` exist, have size > 0, and contain zero stub markers,
  - All `required_symbols` exist in the required files,
  - Its `test_command` executes with exit code 0 under `TMP/TEMP = F:\\AetherMind_Temp`,
  - `ConstitutionSealGuard.verify_seal` passes (if manifest exists).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from am_ua.governance.homeostasis import HomeostasisGovernor
from am_ua.governance.seal_guard import ConstitutionSealGuard, compute_content_sha256

CANONICAL_PYTHON = r"C:\Users\juanp\AppData\Local\Programs\Python\Python311\python.exe"
if not os.path.isfile(CANONICAL_PYTHON):
    CANONICAL_PYTHON = sys.executable

FORBIDDEN_STUB_PATTERNS = (
    re.compile(r"TODO_STUB"),
    re.compile(r"MOCK_ONLY_PLACEHOLDER"),
    re.compile(r'raise\s+NotImplementedError\(\s*["\']stub', re.IGNORECASE),
)


class SubphaseVerificationError(RuntimeError):
    """Raised when a subphase fails any of the 5 verification gates."""


class ProjectCompass:
    """Cryptographic DAG state machine preventing agent drift and amnesia."""

    def __init__(self, root: Path = ROOT) -> None:
        self.root = root.resolve()
        self.master_path = self.root / "project" / "MASTER_PHASES.json"
        self.live_state_path = self.root / "project" / "LIVE_STATE.json"
        self.narrative_path = self.root / "AETHERMIND_NARRATIVE_STATE.md"
        self.panel_path = self.root / "PAINEL_HUMANO.md"
        self.db_path = self.root / "data" / "compass_ledger.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.master = json.loads(self.master_path.read_text(encoding="utf-8"))
        self.subphases_ordered: List[Dict[str, Any]] = []
        self.subphase_map: Dict[str, Dict[str, Any]] = {}
        for phase in self.master["phases"]:
            for sp in phase["subphases"]:
                enriched = {**sp, "phase_id": phase["id"], "phase_title": phase["title"]}
                self.subphases_ordered.append(enriched)
                self.subphase_map[sp["id"]] = enriched

        self._init_db()
        if not self.live_state_path.is_file():
            self.sync_renders()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS subphase_receipts (
                    subphase_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    verified_at TEXT NOT NULL,
                    test_command TEXT NOT NULL,
                    test_duration_s REAL NOT NULL,
                    files_sha256_json TEXT NOT NULL,
                    receipt_digest TEXT NOT NULL,
                    notes TEXT DEFAULT ''
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS compass_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    subphase_id TEXT,
                    detail_json TEXT NOT NULL
                )
                """
            )

    def get_verified_receipts(self) -> Dict[str, Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT subphase_id, status, verified_at, test_command, test_duration_s, files_sha256_json, receipt_digest, notes FROM subphase_receipts"
            ).fetchall()
        out: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            out[r[0]] = {
                "subphase_id": r[0],
                "status": r[1],
                "verified_at": r[2],
                "test_command": r[3],
                "test_duration_s": r[4],
                "files_sha256": json.loads(r[5]),
                "receipt_digest": r[6],
                "notes": r[7],
            }
        return out

    def detect_drift(self) -> List[str]:
        """Compare current disk SHA-256 of verified files against recorded receipts."""
        receipts = self.get_verified_receipts()
        drifts: List[str] = []
        for sp_id, rec in receipts.items():
            if rec["status"] != "VERIFIED":
                continue
            for rel, expected_sha in rec["files_sha256"].items():
                # SEAL_SHA256_MANIFEST and LIVE_STATE legitimately evolve on re-sealing
                if rel in ("constitution/SEAL_SHA256_MANIFEST.json",):
                    continue
                target = self.root / rel
                if not target.is_file():
                    drifts.append(f"[{sp_id}] Missing verified file on disk: {rel}")
                else:
                    actual = compute_content_sha256(target)
                    if actual != expected_sha:
                        drifts.append(
                            f"[{sp_id}] File modified since verification: {rel} ({expected_sha[:10]} -> {actual[:10]})"
                        )
        guard = ConstitutionSealGuard(self.root)
        seal_ok, seal_errs = guard.verify_seal(require_manifest=False)
        if not seal_ok:
            drifts.extend(f"[SEAL_VIOLATION] {e}" for e in seal_errs)
        return drifts

    def next_ready_subphases(self) -> List[Dict[str, Any]]:
        receipts = self.get_verified_receipts()
        verified_ids = {k for k, v in receipts.items() if v["status"] == "VERIFIED"}
        ready: List[Dict[str, Any]] = []
        for sp in self.subphases_ordered:
            if sp["id"] in verified_ids:
                continue
            if all(dep in verified_ids for dep in sp["depends_on"]):
                ready.append(sp)
        return ready

    def _check_files_and_symbols(self, sp: Dict[str, Any]) -> Dict[str, str]:
        file_hashes: Dict[str, str] = {}
        combined_texts: List[str] = []
        for rel in sp["required_files"]:
            target = self.root / rel
            if not target.is_file():
                raise SubphaseVerificationError(f"[{sp['id']}] Missing required file: {rel}")
            if target.stat().st_size == 0:
                raise SubphaseVerificationError(f"[{sp['id']}] Empty file (0 bytes): {rel}")
            file_hashes[rel] = compute_content_sha256(target)
            if target.suffix in {".py", ".mjs", ".js", ".ts", ".json", ".md", ".cmd"}:
                txt = target.read_text(encoding="utf-8", errors="replace")
                combined_texts.append(txt)
                if "tools/project_compass.py" not in rel:
                    for pat in FORBIDDEN_STUB_PATTERNS:
                        if pat.search(txt):
                            raise SubphaseVerificationError(
                                f"[{sp['id']}] Stub marker '{pat.pattern}' found in {rel}"
                            )

        haystack = "\n".join(combined_texts)
        for sym in sp.get("required_symbols", []):
            sym_re = re.compile(rf"\b{re.escape(sym)}\b")
            if not sym_re.search(haystack):
                raise SubphaseVerificationError(
                    f"[{sp['id']}] Required symbol '{sym}' not found in required_files"
                )
        return file_hashes

    def _run_test_gate(self, sp: Dict[str, Any]) -> float:
        test_target = sp["test_command"]
        env = dict(os.environ)
        env["TMP"] = r"F:\AetherMind_Temp"
        env["TEMP"] = r"F:\AetherMind_Temp"
        env["TMPDIR"] = r"F:\AetherMind_Temp"
        py_paths = [
            str(self.root / "src"),
            str(self.root / "vendor" / "oh_my_hermes" / "src"),
            str(self.root / "vendor" / "hermes_agent"),
        ]
        if env.get("PYTHONPATH"):
            py_paths.append(env["PYTHONPATH"])
        env["PYTHONPATH"] = os.pathsep.join(py_paths)

        if test_target.startswith("eval/") and not test_target.endswith("_test.py"):
            cmd = [CANONICAL_PYTHON, str(self.root / test_target)]
        else:
            cmd = [CANONICAL_PYTHON, "-m", "pytest", str(self.root / test_target), "-q"]

        t0 = time.monotonic()
        proc = subprocess.run(
            cmd,
            cwd=str(self.root),
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
        )
        dt = time.monotonic() - t0
        if proc.returncode != 0:
            raise SubphaseVerificationError(
                f"[{sp['id']}] Test gate failed (exit {proc.returncode}): {' '.join(cmd)}\n"
                f"STDOUT:\n{proc.stdout[-2000:]}\nSTDERR:\n{proc.stderr[-2000:]}"
            )
        return round(dt, 3)

    def verify_subphase(self, subphase_id: str, *, notes: str = "") -> Dict[str, Any]:
        if subphase_id not in self.subphase_map:
            raise SubphaseVerificationError(f"Unknown subphase_id: {subphase_id}")
        sp = self.subphase_map[subphase_id]
        receipts = self.get_verified_receipts()

        for dep in sp["depends_on"]:
            if receipts.get(dep, {}).get("status") != "VERIFIED":
                raise SubphaseVerificationError(
                    f"[{subphase_id}] Upstream dependency '{dep}' is not VERIFIED yet"
                )

        file_hashes = self._check_files_and_symbols(sp)
        duration_s = self._run_test_gate(sp)

        guard = ConstitutionSealGuard(self.root)
        seal_ok, seal_errs = guard.verify_seal(require_manifest=False)
        if not seal_ok:
            raise SubphaseVerificationError(
                f"[{subphase_id}] Constitutional seal broken: {'; '.join(seal_errs)}"
            )

        now_iso = datetime.now(timezone.utc).isoformat()
        payload = {
            "subphase_id": subphase_id,
            "status": "VERIFIED",
            "verified_at": now_iso,
            "test_command": sp["test_command"],
            "test_duration_s": duration_s,
            "files_sha256": file_hashes,
        }
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO subphase_receipts
                (subphase_id, status, verified_at, test_command, test_duration_s, files_sha256_json, receipt_digest, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(subphase_id) DO UPDATE SET
                    status=excluded.status,
                    verified_at=excluded.verified_at,
                    test_command=excluded.test_command,
                    test_duration_s=excluded.test_duration_s,
                    files_sha256_json=excluded.files_sha256_json,
                    receipt_digest=excluded.receipt_digest,
                    notes=excluded.notes
                """,
                (
                    subphase_id,
                    "VERIFIED",
                    now_iso,
                    sp["test_command"],
                    duration_s,
                    json.dumps(file_hashes, sort_keys=True),
                    digest,
                    notes,
                ),
            )
            conn.execute(
                "INSERT INTO compass_events (ts, event_type, subphase_id, detail_json) VALUES (?, ?, ?, ?)",
                (now_iso, "SUBPHASE_VERIFIED", subphase_id, json.dumps({**payload, "receipt_digest": digest})),
            )

        self.sync_renders()
        return {**payload, "receipt_digest": digest}

    def verify_phase_or_list(self, ids: List[str], *, notes: str = "") -> List[Dict[str, Any]]:
        results = []
        for item in ids:
            if item in {p["id"] for p in self.master["phases"]}:
                for sp in self.subphases_ordered:
                    if sp["phase_id"] == item:
                        results.append(self.verify_subphase(sp["id"], notes=notes))
            else:
                results.append(self.verify_subphase(item, notes=notes))
        return results

    def build_status_snapshot(self) -> Dict[str, Any]:
        receipts = self.get_verified_receipts()
        verified_count = sum(1 for sp in self.subphases_ordered if receipts.get(sp["id"], {}).get("status") == "VERIFIED")
        total_count = len(self.subphases_ordered)
        ready = self.next_ready_subphases()
        drifts = self.detect_drift()
        homeo = HomeostasisGovernor().sample()
        return {
            "project_name": self.master["project_name"],
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "verified_subphases": verified_count,
            "total_subphases": total_count,
            "completion_pct": round((verified_count / float(total_count)) * 100.0, 2) if total_count else 100.0,
            "is_complete": verified_count == total_count and len(drifts) == 0,
            "next_subphase": ready[0] if ready else None,
            "ready_queue": [r["id"] for r in ready],
            "drift_alerts": drifts,
            "homeostasis": {
                "healthy": homeo.healthy,
                "temp_redirected_ok": homeo.temp_redirected_ok,
                "avail_ram_mb": homeo.avail_ram_mb,
                "f_free_gb": round(homeo.volumes.get("F:", None).free_bytes / (1024**3), 2) if "F:" in homeo.volumes else None,
                "c_free_gb": round(homeo.volumes.get("C:", None).free_bytes / (1024**3), 2) if "C:" in homeo.volumes else None,
            },
            "subphases": [
                {
                    "id": sp["id"],
                    "phase_id": sp["phase_id"],
                    "title": sp["title"],
                    "status": receipts.get(sp["id"], {}).get("status", "PENDING"),
                    "verified_at": receipts.get(sp["id"], {}).get("verified_at"),
                    "receipt_digest": receipts.get(sp["id"], {}).get("receipt_digest"),
                }
                for sp in self.subphases_ordered
            ],
        }

    def sync_renders(self) -> Dict[str, Any]:
        snap = self.build_status_snapshot()
        self.live_state_path.write_text(json.dumps(snap, indent=2) + "\n", encoding="utf-8")

        next_sp = snap["next_subphase"]
        next_block = (
            f"**`{next_sp['id']} — {next_sp['title']}`**\n"
            f"- Arquivos obrigatórios: `{', '.join(next_sp['required_files'])}`\n"
            f"- Símbolos obrigatórios: `{', '.join(next_sp['required_symbols'])}`\n"
            f"- Comando de prova: `{next_sp['test_command']}`\n"
            f"- Para validar e avançar: `aether-compass.cmd verify {next_sp['id']}`"
            if next_sp
            else "**TODAS AS 24 SUBFASES (`P0.1` → `P6.4`) ESTÃO 100% VERIFICADAS E HOMOLOGADAS NO TETO.**"
        )

        drift_md = (
            "\n".join(f"- ⚠️ {d}" for d in snap["drift_alerts"])
            if snap["drift_alerts"]
            else "- ✅ Zero drift detectado (todos os SHA-256 conferem com o ledger)."
        )

        narrative_lines = [
            "# AETHERMIND_NARRATIVE_STATE — Fio Condutor & Bússola Anti-Perda",
            "",
            f"- **Progresso Verificado:** `{snap['verified_subphases']}/{snap['total_subphases']}` subfases (`{snap['completion_pct']}%`)",
            f"- **Atualizado em:** `{snap['updated_at']}`",
            f"- **Disco `F:` livre:** `{snap['homeostasis']['f_free_gb']} GB` | **RAM livre:** `{snap['homeostasis']['avail_ram_mb']} MB` | **Temp seguro (`F:\\AetherMind_Temp`):** `{snap['homeostasis']['temp_redirected_ok']}`",
            "",
            "## 1. O Grande Objetivo (Narrative Intent)",
            self.master["grand_narrative"],
            "",
            "## 2. Onde Parou / Próxima Ação Exata",
            next_block,
            "",
            "## 3. Integridade & Detecção de Drift",
            drift_md,
            "",
            "## 4. Regras Invioláveis para Qualquer Agente Continuador",
            "1. Sempre rode `aether-compass.cmd status` antes de editar qualquer arquivo.",
            "2. Jamais toque em `F:\\rotor-llm`, `rotor-seed`, `D:\\AetherRE_Megazord`, `F:\\Modular Self-Evolving Agent (MSEA)` ou `E:\\Tools\\maps\\aetherscan`.",
            "3. Jamais use `-ngl 99` na GPU AMD RX 580; mantenha `TMP` e `TEMP` em `F:\\AetherMind_Temp`.",
            "4. Proibido `git push` ou criar repositório remoto no GitHub sem ordem explícita do Mestre Ruan.",
            "5. Nenhuma subfase avança manualmente: use `aether-compass.cmd verify <ID>`.",
            "",
        ]
        self.narrative_path.write_text("\n".join(narrative_lines), encoding="utf-8")

        panel_lines = [
            "# PAINEL HUMANO & AGÊNTICO — Mapa Completo de Fases e Subfases",
            "",
            f"**Status Geral:** `{snap['verified_subphases']}/{snap['total_subphases']}` (`{snap['completion_pct']}%`) | **Completo:** `{snap['is_complete']}`",
            "",
            "| Subfase | Fase | Título | Status | Receipt SHA-256 |",
            "|---|---|---|---|---|",
        ]
        for item in snap["subphases"]:
            icon = "✅ VERIFIED" if item["status"] == "VERIFIED" else ("🎯 NEXT" if next_sp and item["id"] == next_sp["id"] else "⏳ PENDING")
            digest_short = f"`{item['receipt_digest'][:12]}`" if item["receipt_digest"] else "—"
            panel_lines.append(f"| `{item['id']}` | `{item['phase_id']}` | {item['title']} | {icon} | {digest_short} |")
        panel_lines.append("")
        self.panel_path.write_text("\n".join(panel_lines), encoding="utf-8")
        return snap


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="AetherMind Anti-Amnesia Project Compass")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="Show full live progress, drift alerts, and next subphase")
    sub.add_parser("resume-brief", help="Print ultra-compact cold-start recovery brief for agents")

    p_verify = sub.add_parser("verify", help="Verify and advance one or more subphases/phases")
    p_verify.add_argument("targets", nargs="+", help="Subphase IDs (e.g. P0.1) or Phase IDs (e.g. P0)")
    p_verify.add_argument("--notes", default="", help="Optional verification note")

    sub.add_parser("verify-all", help="Re-verify every subphase from P0.1 through P6.4")

    args = parser.parse_args(argv)
    compass = ProjectCompass()

    if args.cmd == "status":
        snap = compass.sync_renders()
        print(json.dumps(snap, indent=2))
        return 0

    if args.cmd == "resume-brief":
        snap = compass.sync_renders()
        print(f"=== AETHERMIND COMPASS RESUME BRIEF ({snap['verified_subphases']}/{snap['total_subphases']} VERIFIED) ===")
        print(f"Complete: {snap['is_complete']} | Drift alerts: {len(snap['drift_alerts'])}")
        for d in snap["drift_alerts"]:
            print(f"  DRIFT: {d}")
        if snap["next_subphase"]:
            nxt = snap["next_subphase"]
            print(f"NEXT SUBPHASE: {nxt['id']} - {nxt['title']}")
            print(f"  Required files  : {', '.join(nxt['required_files'])}")
            print(f"  Required symbols: {', '.join(nxt['required_symbols'])}")
            print(f"  Test gate       : {nxt['test_command']}")
        else:
            print("ALL SUBPHASES P0.1..P6.4 ARE VERIFIED AT CEILING LEVEL.")
        return 0

    if args.cmd == "verify":
        res = compass.verify_phase_or_list(args.targets, notes=args.notes)
        print(json.dumps({"verified": res}, indent=2))
        return 0

    if args.cmd == "verify-all":
        all_ids = [sp["id"] for sp in compass.subphases_ordered]
        res = compass.verify_phase_or_list(all_ids, notes="full_reverification")
        print(json.dumps({"verified_total": len(res), "all_green": True}, indent=2))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
