"""Human Wheel Gate — 'Take the Wheel' Graceful Intervention Engine (am_ua.execution.human_wheel).

Implements OpenBot-style state suspension and human-in-the-loop takeover.
When an agent encounters roadblocks (CAPTCHA, 2FA, credential requirements, high-risk ambivalence),
it pauses execution without state loss, records a durable REQUEST.json, and waits for human resolution
before resuming seamlessly.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

VALID_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,96}$")


@dataclass(frozen=True)
class WheelOutcome:
    """Outcome of a human intervention request."""
    action: str  # "RESUMED" | "ABORTED" | "TIMEOUT" | "CONTINUE_AUTONOMOUS"
    note: str
    paused_seconds: float
    request_data: Dict[str, Any]


class HumanWheelGate:
    """Manages the lifecycle of human intervention requests on disk."""

    DEFAULT_WHEEL_ROOT = Path(r"F:\AetherMind_Temp\wheel")

    def __init__(
        self,
        wheel_root: Optional[Path | str] = None,
        *,
        timeout_s: float = 0.0,
        poll_interval_s: float = 0.5,
    ) -> None:
        from am_ua.contracts.contracts import resolve_omni_temp_dir
        self.root = Path(wheel_root or resolve_omni_temp_dir("wheel")).resolve()
        self.timeout_s = max(0.0, float(timeout_s))
        self.poll_interval_s = max(0.1, float(poll_interval_s))
        self.root.mkdir(parents=True, exist_ok=True)

    def _mission_dir(self, mission_id: str) -> Path:
        if not VALID_ID_RE.match(mission_id):
            raise ValueError(f"Invalid mission_id for HumanWheel: '{mission_id}' (alphanumeric/._- only)")
        mdir = self.root / mission_id
        mdir.mkdir(parents=True, exist_ok=True)
        return mdir

    def pause_for_human(
        self,
        mission_id: str,
        reason: str,
        instructions: str,
        *,
        turn: int = 0,
        timeout_s: Optional[float] = None,
    ) -> WheelOutcome:
        """Suspends agent execution, writing REQUEST.json and waiting for human intervention."""
        if not VALID_ID_RE.match(mission_id):
            raise ValueError(f"Invalid mission_id for HumanWheel: '{mission_id}' (alphanumeric/._- only)")
        effective_timeout = self.timeout_s if timeout_s is None else max(0.0, float(timeout_s))
        req_data = {
            "mission_id": mission_id,
            "turn": turn,
            "reason": str(reason),
            "instructions": str(instructions),
            "requested_at": time.time(),
            "timeout_s": effective_timeout,
        }

        # If timeout is 0 (disabled), continue autonomously without blocking
        if effective_timeout <= 0.0:
            return WheelOutcome(
                action="CONTINUE_AUTONOMOUS",
                note="Human intervention is disabled (timeout_s=0). Continue autonomously.",
                paused_seconds=0.0,
                request_data=req_data,
            )

        mdir = self._mission_dir(mission_id)
        req_path = mdir / "REQUEST.json"
        resume_path = mdir / "RESUME.json"
        abort_path = mdir / "ABORT.json"
        hist_dir = mdir / "HISTORY"
        hist_dir.mkdir(parents=True, exist_ok=True)

        # Clear any stale resume/abort flags
        for p in (resume_path, abort_path):
            if p.exists():
                try:
                    p.unlink()
                except OSError:
                    pass

        # Atomic write of REQUEST.json
        tmp_req = mdir / f"REQUEST.tmp.{os.getpid()}"
        tmp_req.write_text(json.dumps(req_data, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp_req.replace(req_path)

        t_start = time.monotonic()
        deadline = t_start + effective_timeout

        while True:
            # Check for RESUME
            if resume_path.exists():
                elapsed = round(time.monotonic() - t_start, 3)
                note = "Proceed"
                try:
                    data = json.loads(resume_path.read_text(encoding="utf-8"))
                    note = str(data.get("note", note))
                except Exception:
                    pass
                self._archive_and_cleanup(mdir, req_data, "RESUMED", note, elapsed)
                return WheelOutcome(
                    action="RESUMED",
                    note=note,
                    paused_seconds=elapsed,
                    request_data=req_data,
                )

            # Check for ABORT
            if abort_path.exists():
                elapsed = round(time.monotonic() - t_start, 3)
                note = "Aborted by human"
                try:
                    data = json.loads(abort_path.read_text(encoding="utf-8"))
                    note = str(data.get("note", note))
                except Exception:
                    pass
                self._archive_and_cleanup(mdir, req_data, "ABORTED", note, elapsed)
                return WheelOutcome(
                    action="ABORTED",
                    note=note,
                    paused_seconds=elapsed,
                    request_data=req_data,
                )

            # Check for timeout
            now = time.monotonic()
            if now >= deadline:
                elapsed = round(now - t_start, 3)
                note = f"Human intervention timed out after {effective_timeout}s"
                self._archive_and_cleanup(mdir, req_data, "TIMEOUT", note, elapsed)
                return WheelOutcome(
                    action="TIMEOUT",
                    note=note,
                    paused_seconds=elapsed,
                    request_data=req_data,
                )

            time.sleep(self.poll_interval_s)

    def _archive_and_cleanup(
        self,
        mdir: Path,
        req_data: Dict[str, Any],
        outcome_action: str,
        note: str,
        paused_seconds: float,
    ) -> None:
        hist_dir = mdir / "HISTORY"
        ts = int(time.time() * 1000)
        record = {
            **req_data,
            "outcome": outcome_action,
            "human_note": note,
            "paused_seconds": paused_seconds,
            "closed_at": time.time(),
        }
        record_file = hist_dir / f"intervention_{ts}_{outcome_action.lower()}.json"
        try:
            record_file.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
        except OSError:
            pass

        # Cleanup active flags
        for f in ("REQUEST.json", "RESUME.json", "ABORT.json"):
            p = mdir / f
            if p.exists():
                try:
                    p.unlink()
                except OSError:
                    pass

    @classmethod
    def resume(
        cls,
        mission_id: str,
        note: str = "Proceed with mission",
        wheel_root: Optional[Path | str] = None,
    ) -> Dict[str, Any]:
        """Human operator command: resumes a paused mission with an optional note."""
        root = Path(wheel_root or cls.DEFAULT_WHEEL_ROOT).resolve()
        if not VALID_ID_RE.match(mission_id):
            return {"ok": False, "error": f"Invalid mission_id: {mission_id}"}
        mdir = root / mission_id
        req_path = mdir / "REQUEST.json"
        if not req_path.is_file():
            return {
                "ok": False,
                "error": f"No active intervention request found for mission '{mission_id}' at {req_path}",
            }
        resume_path = mdir / "RESUME.json"
        payload = {"mission_id": mission_id, "note": note, "resumed_at": time.time()}
        resume_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return {"ok": True, "mission_id": mission_id, "action": "RESUME", "note": note}

    @classmethod
    def abort(
        cls,
        mission_id: str,
        note: str = "Aborted by human operator",
        wheel_root: Optional[Path | str] = None,
    ) -> Dict[str, Any]:
        """Human operator command: aborts a paused mission with an optional reason."""
        root = Path(wheel_root or cls.DEFAULT_WHEEL_ROOT).resolve()
        if not VALID_ID_RE.match(mission_id):
            return {"ok": False, "error": f"Invalid mission_id: {mission_id}"}
        mdir = root / mission_id
        req_path = mdir / "REQUEST.json"
        if not req_path.is_file():
            return {
                "ok": False,
                "error": f"No active intervention request found for mission '{mission_id}' at {req_path}",
            }
        abort_path = mdir / "ABORT.json"
        payload = {"mission_id": mission_id, "note": note, "aborted_at": time.time()}
        abort_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return {"ok": True, "mission_id": mission_id, "action": "ABORT", "note": note}

    @classmethod
    def list_active_requests(cls, wheel_root: Optional[Path | str] = None) -> List[Dict[str, Any]]:
        """Lists all currently waiting intervention requests across all missions."""
        root = Path(wheel_root or cls.DEFAULT_WHEEL_ROOT).resolve()
        if not root.exists():
            return []
        active = []
        for mdir in root.iterdir():
            if mdir.is_dir():
                req_file = mdir / "REQUEST.json"
                if req_file.is_file():
                    try:
                        data = json.loads(req_file.read_text(encoding="utf-8"))
                        active.append(data)
                    except Exception:
                        pass
        return active
