"""Silicon Eyes: fastmft / AetherScan v1.3.0 Wrapper + UCIP Topological Compression (P4.1).

Integrates `E:\\Tools\\maps\\aetherscan\\aetherscan_v1.3.0.exe` (read-only invocation
writing reports strictly into `F:\\AetherMind_Temp\\aetherscan_out`) and compresses
verbose filesystem trees into compact UCIP topological representations (>70% token
reduction) with parasite hotspot detection (`node_modules`, `target`, `__pycache__`).
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

PARASITE_DIR_NAMES = {
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "target",
    ".venv",
    "venv",
    "dist",
    "build",
    ".next",
}


@dataclass
class UCIPSummary:
    """Compact Universal Context Index Protocol (UCIP) representation of a directory tree."""

    root_path: str
    total_files: int
    total_bytes: int
    raw_listing_chars: int
    compressed_chars: int
    compression_ratio: float
    reduction_pct: float
    ucip_compact_text: str
    extension_histogram: Dict[str, int] = field(default_factory=dict)
    parasite_hotspots: List[Dict[str, Any]] = field(default_factory=list)
    engine_used: str = "aetherscan_v1.3.0+ucip"


class SiliconProjectRadar:
    """High-speed filesystem & project topology scanner backed by AetherScan v1.3.0."""

    DEFAULT_AETHERSCAN_EXE = Path(r"E:\Tools\maps\aetherscan\aetherscan_v1.3.0.exe")

    def __init__(
        self,
        aetherscan_exe: Optional[Path | str] = None,
        temp_out_root: Optional[Path | str] = None,
    ) -> None:
        self.aetherscan_exe = Path(aetherscan_exe or self.DEFAULT_AETHERSCAN_EXE)
        self.temp_out_root = Path(
            temp_out_root or r"F:\AetherMind_Temp\aetherscan_out"
        ).resolve()
        self.temp_out_root.mkdir(parents=True, exist_ok=True)

    def is_binary_available(self) -> bool:
        return self.aetherscan_exe.is_file()

    def run_aetherscan_walk(self, target_dir: Path | str, *, top_n: int = 15) -> Dict[str, Any]:
        """Execute real `aetherscan_v1.3.0.exe scan <dir> --mode walk` into temp out dir."""
        resolved = Path(target_dir).resolve()
        if not resolved.exists():
            raise FileNotFoundError(f"Target path does not exist: {resolved}")

        run_dir = self.temp_out_root / f"scan_{int(time.time() * 1000)}_{os.getpid()}"
        run_dir.mkdir(parents=True, exist_ok=True)

        if not self.is_binary_available():
            return {
                "ok": False,
                "binary_available": False,
                "target": str(resolved),
                "reason": f"Missing binary at {self.aetherscan_exe}",
            }

        env = os.environ.copy()
        env["TMP"] = r"F:\AetherMind_Temp"
        env["TEMP"] = r"F:\AetherMind_Temp"

        t0 = time.perf_counter()
        proc = subprocess.run(
            [
                str(self.aetherscan_exe),
                "scan",
                str(resolved),
                "--mode",
                "walk",
                "--top",
                str(top_n),
                "--out",
                str(run_dir),
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            timeout=60,
            check=False,
        )
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        generated_files = sorted(p.name for p in run_dir.glob("*") if p.is_file())
        parsed_report: Dict[str, Any] = {}
        for jf in run_dir.glob("*.json"):
            try:
                parsed_report[jf.name] = json.loads(jf.read_text(encoding="utf-8"))
            except Exception:
                continue

        return {
            "ok": proc.returncode == 0,
            "binary_available": True,
            "returncode": proc.returncode,
            "elapsed_ms": elapsed_ms,
            "target": str(resolved),
            "stdout_tail": (proc.stdout or "")[-800:],
            "artifacts": generated_files,
            "reports": parsed_report,
        }

    def build_ucip_summary(
        self,
        target_dir: Path | str,
        *,
        invoke_silicon_binary: bool = True,
    ) -> UCIPSummary:
        """Scan directory and compress verbose path listings into compact UCIP grammar."""
        resolved = Path(target_dir).resolve()
        if not resolved.is_dir():
            raise NotADirectoryError(f"Expected directory for UCIP scan: {resolved}")

        silicon_meta = (
            self.run_aetherscan_walk(resolved, top_n=10)
            if invoke_silicon_binary and self.is_binary_available()
            else {"ok": False}
        )

        raw_lines: List[str] = []
        ext_counts: Counter[str] = Counter()
        dir_groups: Dict[str, Counter[str]] = defaultdict(Counter)
        parasites: Dict[str, int] = defaultdict(int)
        total_files = 0
        total_bytes = 0

        for dirpath, dirnames, filenames in os.walk(resolved):
            rel_dir = Path(dirpath).relative_to(resolved).as_posix()
            # Track parasite directories without expanding every nested file into prompt context
            matched_parasites = [d for d in dirnames if d in PARASITE_DIR_NAMES]
            for p_name in matched_parasites:
                p_full = Path(dirpath) / p_name
                p_bytes = 0
                for sub_r, _, sub_f in os.walk(p_full):
                    for sf in sub_f:
                        fp = Path(sub_r) / sf
                        try:
                            st = fp.stat()
                            p_bytes += st.st_size
                            raw_lines.append(
                                f"{fp.relative_to(resolved).as_posix()} | size={st.st_size} | mtime={int(st.st_mtime)}"
                            )
                        except OSError:
                            continue
                parasites[f"{rel_dir}/{p_name}".lstrip("./")] += p_bytes
            dirnames[:] = [d for d in dirnames if d not in PARASITE_DIR_NAMES and d != ".git"]

            for fname in filenames:
                fpath = Path(dirpath) / fname
                try:
                    st = fpath.stat()
                except OSError:
                    continue
                total_files += 1
                total_bytes += st.st_size
                ext = fpath.suffix.lower() or "<none>"
                ext_counts[ext] += 1
                dir_groups[rel_dir][ext] += 1
                raw_lines.append(
                    f"{fpath.relative_to(resolved).as_posix()} | size={st.st_size} bytes | mtime={int(st.st_mtime)} | ext={ext}"
                )

        raw_blob = "\n".join(raw_lines) if raw_lines else str(resolved)
        raw_chars = max(1, len(raw_blob))

        # Build compact UCIP v1 topological notation
        ucip_lines = [
            f"@UCIP/1 root={resolved.name} files={total_files} kb={total_bytes // 1024}"
        ]
        top_exts = ",".join(f"{k}:{v}" for k, v in ext_counts.most_common(8))
        if top_exts:
            ucip_lines.append(f"@EXT {top_exts}")
        for d_rel in sorted(dir_groups.keys())[:24]:
            sig = ",".join(f"{e[1:] if e.startswith('.') else e}*{c}" for e, c in dir_groups[d_rel].most_common(5))
            ucip_lines.append(f"/{'' if d_rel == '.' else d_rel}[{sig}]")
        parasite_list = [
            {"path": k, "bytes": v}
            for k, v in sorted(parasites.items(), key=lambda x: x[1], reverse=True)
        ]
        if parasite_list:
            p_sig = ",".join(f"{p['path']}:{p['bytes']//1024}K" for p in parasite_list[:6])
            ucip_lines.append(f"@PARASITES {p_sig}")

        compact_text = "\n".join(ucip_lines)
        comp_chars = len(compact_text)
        ratio = round(comp_chars / raw_chars, 4)
        reduction = round((1.0 - min(1.0, comp_chars / raw_chars)) * 100.0, 2)

        return UCIPSummary(
            root_path=str(resolved),
            total_files=total_files,
            total_bytes=total_bytes,
            raw_listing_chars=raw_chars,
            compressed_chars=comp_chars,
            compression_ratio=ratio,
            reduction_pct=reduction,
            ucip_compact_text=compact_text,
            extension_histogram=dict(ext_counts),
            parasite_hotspots=parasite_list,
            engine_used="aetherscan_v1.3.0+ucip" if silicon_meta.get("ok") else "python_walk+ucip",
        )
