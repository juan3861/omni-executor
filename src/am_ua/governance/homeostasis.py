"""Physical Homeostasis Governor, Casimir Disk Collapse Sensor & Economic Stop-Loss (R09).

Combines:
- AetherScan v1.3.0 Casimir bistable storage potential: Fc = -pi^2 / (240 * d^4)
- rotor-seed Homeostasis sensor discipline (disk, RAM, temp routing, RX 580 GPU lock)
- Astra R09 Economic Budget & Diminishing-Returns Stop-Loss controller
"""

from __future__ import annotations

import ctypes
import math
import os
import shutil
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


class ResourceExhaustedError(RuntimeError):
    """Raised when disk, RAM, time, or economic budget hits fail-closed bounds."""


class HardwareSafetyLockError(RuntimeError):
    """Raised when environment violates hardware safety constraints."""


def casimir_collapse_force(free_bytes: int, total_bytes: int) -> float:
    """Compute AetherScan Casimir attractive collapse force Fc = -pi^2 / (240 * d^4).

    As normalized free gap d = free/total drops below 0.20, |Fc| spikes sharply,
    signaling imminent storage collapse before OS ENOSPC failures occur.
    """
    if total_bytes <= 0:
        return -float("inf")
    d = max(free_bytes / float(total_bytes), 1e-6)
    return -(math.pi ** 2) / (240.0 * (d ** 4))


def casimir_bistable_diagnostics(
    free_bytes: int,
    total_bytes: int,
    reclaimable_bytes: int = 0,
) -> Dict[str, Any]:
    """Compute full fastmft v1.3.0 Casimir-Helmholtz-Langevin storage potential diagnostics.

    Mirrors ``computeCasimir`` in fastmft/advise.go:
      - Normalized gap: d = FreeBytes / TotalBytes (clamped >= 0.001)
      - Casimir force: F_C(d) = -pi^2 / (240 * d^4)
      - Bistable well: U(ds) = 0.5*k*(ds - d0)^2 - C_cas/ds^3 + C_rep/ds^12
      - Langevin drift: -dU/dds = -(k*(ds - d0) + 3*C_cas/ds^4 - 12*C_rep/ds^13)
    """
    tot = max(int(total_bytes), 1)
    free = max(int(free_bytes), 0)
    used = max(tot - free, 0)
    d = max(free / float(tot), 0.001)
    ds = max(d * 10.0, 0.15)
    k = 1.0
    d0 = 2.0
    c_cas = 1.2
    rep_c = 0.05
    pi_sq = math.pi ** 2

    fc = -(pi_sq / (240.0 * (d ** 4)))
    u_total = 0.5 * k * ((ds - d0) ** 2) - (c_cas / (ds ** 3)) + (rep_c / (ds ** 12))
    drift = -(k * (ds - d0) + (3.0 * c_cas / (ds ** 4)) - (12.0 * rep_c / (ds ** 13)))

    if d < 0.05:
        state = "COLAPSO_CASIMIR_CRITICO"
    elif d < 0.15:
        state = "LIMIAR_BIESTAVEL_MIGRACAO"
    else:
        state = "ESTAVEL_POCO_LOCAL"

    post_free = min(free + max(int(reclaimable_bytes), 0), tot)
    post_d = max(post_free / float(tot), 0.001)
    post_fc = -(pi_sq / (240.0 * (post_d ** 4)))

    return {
        "total_bytes": tot,
        "free_bytes": free,
        "used_bytes": used,
        "normalized_gap_d": round(d, 4),
        "casimir_force_fc": round(fc, 2),
        "bistable_potential_u": round(u_total, 3),
        "langevin_drift": round(drift, 3),
        "regime_state": state,
        "post_move_free_bytes": post_free,
        "post_move_gap_d": round(post_d, 4),
        "post_move_casimir_force": round(post_fc, 2),
    }


class _MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


def _sample_windows_ram() -> Dict[str, int | float]:
    if os.name != "nt":
        return {
            "memory_load_pct": 0.0,
            "avail_phys_bytes": 4 * 1024**3,
            "total_phys_bytes": 16 * 1024**3,
            "avail_commit_bytes": 8 * 1024**3,
        }
    stat = _MEMORYSTATUSEX()
    stat.dwLength = ctypes.sizeof(_MEMORYSTATUSEX)
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
    return {
        "memory_load_pct": float(stat.dwMemoryLoad),
        "avail_phys_bytes": int(stat.ullAvailPhys),
        "total_phys_bytes": int(stat.ullTotalPhys),
        "avail_commit_bytes": int(stat.ullAvailPageFile),
    }


@dataclass(frozen=True)
class VolumeHealth:
    drive: str
    free_bytes: int
    total_bytes: int
    free_ratio: float
    casimir_force: float
    collapse_regime: bool


@dataclass(frozen=True)
class HomeostasisSnapshot:
    timestamp: float
    safe_temp_dir: str
    temp_redirected_ok: bool
    memory_load_pct: float
    avail_ram_mb: float
    volumes: Dict[str, VolumeHealth]
    healthy: bool
    warnings: List[str] = field(default_factory=list)
    avail_commit_mb: float = 0.0

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


class HomeostasisGovernor:
    """Monitors host health, enforces F:\\ temp routing, and tracks R09 mission budgets."""

    def __init__(
        self,
        *,
        safe_temp_dir: Optional[str] = None,
        min_free_f_bytes: int = 1 * 1024**3,      # 1.0 GB hard floor on F:
        min_avail_ram_mb: float = 384.0,          # 384 MB hard floor
        max_tokens_budget: int = 500_000,
        max_wall_seconds: float = 3600.0,
        max_stagnant_turns: int = 4,
    ) -> None:
        import tempfile

        env_tmp = os.environ.get("AM_UA_TEMP_DIR", "").strip()
        if safe_temp_dir:
            self.safe_temp_dir = safe_temp_dir
        elif env_tmp:
            self.safe_temp_dir = env_tmp
        elif os.name == "nt" and Path("F:/").exists():
            self.safe_temp_dir = r"F:\AetherMind_Temp"
        else:
            self.safe_temp_dir = str(Path(tempfile.gettempdir()) / "omni_executor_tmp")
        self.min_free_f_bytes = min_free_f_bytes
        self.min_avail_ram_mb = min_avail_ram_mb
        self.max_tokens_budget = max_tokens_budget
        self.max_wall_seconds = max_wall_seconds
        self.max_stagnant_turns = max_stagnant_turns

        self._started_at = time.monotonic()
        self._tokens_spent = 0
        self._tool_calls_spent = 0
        self._stagnant_turns = 0
        self.enforce_safe_temp()

    def credit_paused_time(self, seconds: float) -> None:
        """Exclude human-intervention pause time from the R09 wall-clock budget."""
        if not math.isfinite(seconds) or seconds < 0:
            raise ValueError("paused seconds must be finite and >= 0")
        self._started_at += seconds

    def enforce_safe_temp(self) -> str:
        """Redirect TMP/TEMP away from C:\\ and 80 MB E:\\rotor_tmp onto F:\\AetherMind_Temp."""
        target = Path(self.safe_temp_dir)
        target.mkdir(parents=True, exist_ok=True)
        resolved = str(target.resolve())
        os.environ["TMP"] = resolved
        os.environ["TEMP"] = resolved
        os.environ["TMPDIR"] = resolved
        if resolved.upper().startswith("E:"):
            raise HardwareSafetyLockError(f"Temp directory cannot reside on E: ({resolved})")
        return resolved

    def sample(self, drives: tuple[str, ...] = ("C:\\", "D:\\", "E:\\", "F:\\")) -> HomeostasisSnapshot:
        self.enforce_safe_temp()
        ram = _sample_windows_ram()
        avail_mb = ram["avail_phys_bytes"] / (1024.0 * 1024.0)
        avail_commit_mb = ram["avail_commit_bytes"] / (1024.0 * 1024.0)
        vols: Dict[str, VolumeHealth] = {}
        warnings: List[str] = []
        healthy = True

        for drv in drives:
            if not os.path.exists(drv):
                continue
            usage = shutil.disk_usage(drv)
            ratio = usage.free / float(usage.total) if usage.total else 0.0
            fc = casimir_collapse_force(usage.free, usage.total)
            collapse = ratio < 0.05  # < 5% free
            key = drv.rstrip("\\")
            vols[key] = VolumeHealth(
                drive=key,
                free_bytes=usage.free,
                total_bytes=usage.total,
                free_ratio=round(ratio, 5),
                casimir_force=round(fc, 2),
                collapse_regime=collapse,
            )
            if key.upper() == "F:" and usage.free < self.min_free_f_bytes:
                healthy = False
                warnings.append(f"F: free space below hard floor ({usage.free} < {self.min_free_f_bytes})")
            elif collapse:
                warnings.append(f"Volume {key} in Casimir high-pressure regime (free_ratio={ratio:.4f})")

        if avail_mb < self.min_avail_ram_mb:
            healthy = False
            warnings.append(f"Available RAM critically low ({avail_mb:.1f} MB < {self.min_avail_ram_mb} MB)")

        temp_ok = os.environ.get("TMP", "").upper().startswith("F:") and os.environ.get("TEMP", "").upper().startswith("F:")
        if not temp_ok:
            healthy = False
            warnings.append("TMP/TEMP env not anchored to F:")

        return HomeostasisSnapshot(
            timestamp=time.time(),
            safe_temp_dir=self.safe_temp_dir,
            temp_redirected_ok=temp_ok,
            memory_load_pct=ram["memory_load_pct"],
            avail_ram_mb=round(avail_mb, 2),
            volumes=vols,
            healthy=healthy,
            warnings=warnings,
            avail_commit_mb=round(avail_commit_mb, 2),
        )

    def record_turn_cost(self, *, tokens: int, tool_calls: int = 1, made_verified_progress: bool = True) -> Dict[str, object]:
        """R09 Budget & Economic Stop-Loss check: halts unproductive loops automatically."""
        self._tokens_spent += max(0, int(tokens))
        self._tool_calls_spent += max(0, int(tool_calls))
        if made_verified_progress:
            self._stagnant_turns = 0
        else:
            self._stagnant_turns += 1

        elapsed = time.monotonic() - self._started_at
        if self._tokens_spent > self.max_tokens_budget:
            raise ResourceExhaustedError(
                f"R09 Token budget exceeded ({self._tokens_spent} > {self.max_tokens_budget})"
            )
        if elapsed > self.max_wall_seconds:
            raise ResourceExhaustedError(
                f"R09 Wall-clock deadline exceeded ({elapsed:.1f}s > {self.max_wall_seconds:.1f}s)"
            )
        if self._stagnant_turns >= self.max_stagnant_turns:
            raise ResourceExhaustedError(
                f"R09 Economic Stop-Loss triggered: {self._stagnant_turns} consecutive turns without verified progress"
            )
        return {
            "tokens_spent": self._tokens_spent,
            "tool_calls_spent": self._tool_calls_spent,
            "stagnant_turns": self._stagnant_turns,
            "elapsed_seconds": round(elapsed, 3),
        }

    def assert_healthy(self) -> HomeostasisSnapshot:
        snap = self.sample()
        if not snap.healthy:
            raise ResourceExhaustedError(f"Homeostasis gate tripped: {'; '.join(snap.warnings)}")
        return snap
