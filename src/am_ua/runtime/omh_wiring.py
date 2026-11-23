"""oh-my-hermes v4.0.4 Maestro Host Wiring & Astra R10 Experimental Arbitrator."""

from __future__ import annotations

from contextlib import contextmanager
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional

from am_ua import PROJECT_ROOT

_VENDOR_HERMES = Path(PROJECT_ROOT) / "vendor" / "hermes_agent"
_VENDOR_OMH_SRC = Path(PROJECT_ROOT) / "vendor" / "oh_my_hermes" / "src"


def _ensure_vendor_paths() -> None:
    for p in (_VENDOR_OMH_SRC, _VENDOR_HERMES):
        s = str(p)
        if p.is_dir() and s not in sys.path:
            sys.path.insert(0, s)


class OMHMaestroBridge:
    """Wires oh-my-hermes v4.0.4 category_maestro, /dag-ulw wave planner, and browser identity seam."""

    def __init__(self, *, omh_home: Optional[Path | str] = None) -> None:
        _ensure_vendor_paths()
        self.omh_home = Path(omh_home or (Path(PROJECT_ROOT) / "data" / "omh_home"))
        self.omh_home.mkdir(parents=True, exist_ok=True)

        # Ensure `omh.*` alias resolves to `vendor/oh_my_hermes/src/*` just like installed package
        import types
        if "omh" not in sys.modules:
            pkg = types.ModuleType("omh")
            pkg.__path__ = [str(_VENDOR_OMH_SRC)]
            sys.modules["omh"] = pkg

        from omh.coding import category_maestro  # type: ignore[import-not-found]
        from omh.plugin_bundle.omh import browser_bridge  # type: ignore[import-not-found]

        self.category_maestro = category_maestro
        self.browser_bridge = browser_bridge

    @contextmanager
    def bind_request_browser_identity(
        self,
        *,
        session_id: str,
        principal: str = "mestre_ruan_local",
        transport_family: str = "cli_trusted",
        message_id: str = "msg_001",
    ) -> Iterator[Dict[str, Any]]:
        """Sets all 4 ContextVars + request-bound schema cache bypass required by OMH browser_bridge."""
        _ensure_vendor_paths()
        if "gateway" not in sys.modules:
            try:
                import gateway.session_context  # type: ignore[import-not-found]  # noqa: F401
            except ModuleNotFoundError:
                gw_dir = _VENDOR_HERMES / "gateway"
                if (gw_dir / "session_context.py").is_file():
                    import types
                    gw_pkg = types.ModuleType("gateway")
                    gw_pkg.__path__ = [str(gw_dir)]
                    sys.modules["gateway"] = gw_pkg
        from gateway import session_context  # type: ignore[import-not-found]
        from tools import registry  # type: ignore[import-not-found]

        t1 = session_context._SESSION_ID.set(session_id)
        t2 = session_context._BROWSER_CONTROL_PRINCIPAL.set(principal)
        t3 = session_context._BROWSER_CONTROL_TRANSPORT_FAMILY.set(transport_family)
        t4 = session_context._SESSION_MESSAGE_ID.set(message_id)
        t5 = registry._CHECK_FN_SCOPE_VAR.set(registry.CHECK_FN_CACHE_BYPASS)
        try:
            yield self.browser_bridge.host_browser_capability()
        finally:
            registry._CHECK_FN_SCOPE_VAR.reset(t5)
            session_context._SESSION_MESSAGE_ID.reset(t4)
            session_context._BROWSER_CONTROL_TRANSPORT_FAMILY.reset(t3)
            session_context._BROWSER_CONTROL_PRINCIPAL.reset(t2)
            session_context._SESSION_ID.reset(t1)

    def resolve_lane(self, category: str) -> Dict[str, Any]:
        """Resolve execution lane chain (`ultrabrain`, `deep`, `visual-engineering`, `quick`)."""
        defaults = getattr(self.category_maestro, "DEFAULT_CATEGORY_CONFIGS", None) or getattr(
            self.category_maestro, "CATEGORY_DEFAULTS", {}
        )
        if isinstance(defaults, dict) and category in defaults:
            return {"category": category, "config": defaults[category], "source": "omh_category_maestro"}
        # Fallback deterministic mapping if internal constant name differs across OMH minor builds
        fallback_chains = {
            "ultrabrain": {"tier": "ceiling_reasoning", "effort": "high", "allow_silent_downgrade": False},
            "deep": {"tier": "deep_code", "effort": "high", "allow_silent_downgrade": False},
            "visual-engineering": {"tier": "multimodal_gui", "effort": "medium", "allow_silent_downgrade": False},
            "quick": {"tier": "fast_low_latency", "effort": "low", "allow_silent_downgrade": False},
        }
        return {
            "category": category,
            "config": fallback_chains.get(category, fallback_chains["deep"]),
            "source": "omh_maestro_bridge",
        }


class ExperimentalArbitrator:
    """Astra R10 Anti-Blind-Consensus Arbitrator.

    Resolves disagreements between multiple agents/models (`PolyCouncil` or `/dag-ulw` candidates)
    NOT by majority vote (which fails under shared false premises), but by executing an empirical
    verification oracle against each candidate!
    """

    def arbitrate(
        self,
        candidates: List[Dict[str, Any]],
        *,
        oracle_fn: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        if not candidates:
            raise ValueError("ExperimentalArbitrator requires at least 1 candidate")

        evaluated: List[Dict[str, Any]] = []
        for cand in candidates:
            cid = str(cand["candidate_id"])
            t0 = time.monotonic()
            if oracle_fn is not None:
                outcome = oracle_fn(cand)
                passed = bool(outcome.get("passed", False))
                score = float(outcome.get("score", 1.0 if passed else 0.0))
                evidence = str(outcome.get("evidence", ""))
            elif "verify_command" in cand:
                proc = subprocess.run(
                    cand["verify_command"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                passed = proc.returncode == 0
                score = 1.0 if passed else 0.0
                evidence = (proc.stdout + proc.stderr).strip()[:500]
            else:
                raise ValueError(f"R10 violation: candidate '{cid}' lacks empirical oracle or verify_command")

            dt_ms = round((time.monotonic() - t0) * 1000.0, 3)
            evaluated.append(
                {
                    "candidate_id": cid,
                    "votes": int(cand.get("votes", 1)),
                    "passed_experiment": passed,
                    "score": score,
                    "latency_ms": dt_ms,
                    "evidence": evidence,
                }
            )

        # Rank strictly by empirical experiment pass -> score -> speed (NEVER raw vote count first!)
        evaluated.sort(
            key=lambda x: (
                not x["passed_experiment"],
                -x["score"],
                x["latency_ms"],
                -x["votes"],
            )
        )
        winner = evaluated[0]
        return {
            "protocol": "ASTRA-R10-EXPERIMENTAL-ARBITRATION",
            "winner_id": winner["candidate_id"] if winner["passed_experiment"] else None,
            "majority_overruled": bool(
                winner["passed_experiment"]
                and any(e["votes"] > winner["votes"] and not e["passed_experiment"] for e in evaluated)
            ),
            "ranking": evaluated,
        }
