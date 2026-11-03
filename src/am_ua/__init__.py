"""AetherMind Universal Agent (am_ua) — Ceiling-Level Super-Union Package."""

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

__version__ = "1.0.0"
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
