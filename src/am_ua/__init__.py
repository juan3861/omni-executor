"""OmniExecutor Agent (package `am_ua`): autonomous coding, browser and desktop automation harness."""

from __future__ import annotations

import os

# Enforce safe temporary directory on F:\ across all imports on Windows
# (protects C:\ with ~2 GB free and E:\rotor_tmp with ~80 MB free).
if os.name == "nt":
    _SAFE_TEMP = r"F:\AetherMind_Temp"
    if os.path.isdir("F:\\"):
        os.makedirs(_SAFE_TEMP, exist_ok=True)
        os.environ["TMP"] = _SAFE_TEMP
        os.environ["TEMP"] = _SAFE_TEMP
        os.environ["TMPDIR"] = _SAFE_TEMP

__version__ = "4.1.0"
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def __getattr__(name: str):
    """Lazy public entry point: `from am_ua import OmniExecutorAgent` (avoids importing the kernel eagerly)."""
    if name == "OmniExecutorAgent":
        from am_ua.agent_kernel import AetherMindUniversalAgent as _Kernel

        cls = type(
            "OmniExecutorAgent",
            (_Kernel,),
            {"__doc__": "OmniExecutor Agent: public facade over the agent kernel.", "__module__": __name__},
        )
        globals()["OmniExecutorAgent"] = cls
        return cls
    raise AttributeError(f"module 'am_ua' has no attribute {name!r}")
