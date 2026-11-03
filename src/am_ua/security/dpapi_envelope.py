"""Windows DPAPI Private Key Provider & Nonce-Protected Authenticated Envelopes.

Unites MSEA Host Bridge security (`windows_dpapi_private_key_provider.mjs`,
`authenticated_envelope.mjs`, `durable_nonce_replay_inspection.mjs`) in native
Python over Win32 `CryptProtectData` / `CryptUnprotectData`.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, Optional

from am_ua import PROJECT_ROOT
from am_ua.contracts.contracts import CognitiveEnvelope


class EnvelopeTamperedError(PermissionError):
    """Raised when HMAC-SHA256 signature or TTL check fails."""


class ReplayAttackError(PermissionError):
    """Raised when a previously consumed nonce/event_id is replayed."""


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


class WindowsDPAPIProvider:
    """Hardware/User-session bound secret storage using Win32 Crypt32 DPAPI."""

    CRYPTPROTECT_UI_FORBIDDEN = 0x1

    @classmethod
    def protect(cls, plaintext: bytes, entropy: bytes = b"AetherMind_UA_v1") -> bytes:
        if os.name != "nt":
            raise RuntimeError("WindowsDPAPIProvider requires Windows NT")
        in_buf = (ctypes.c_ubyte * len(plaintext)).from_buffer_copy(plaintext)
        in_blob = _DATA_BLOB(len(plaintext), in_buf)
        ent_buf = (ctypes.c_ubyte * len(entropy)).from_buffer_copy(entropy)
        ent_blob = _DATA_BLOB(len(entropy), ent_buf)
        out_blob = _DATA_BLOB()

        ok = ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(in_blob),
            "AetherMindUniversalAgentKey",
            ctypes.byref(ent_blob),
            None,
            None,
            cls.CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(out_blob),
        )
        if not ok:
            raise ctypes.WinError()
        try:
            return ctypes.string_at(out_blob.pbData, out_blob.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(out_blob.pbData)

    @classmethod
    def unprotect(cls, ciphertext: bytes, entropy: bytes = b"AetherMind_UA_v1") -> bytes:
        if os.name != "nt":
            raise RuntimeError("WindowsDPAPIProvider requires Windows NT")
        in_buf = (ctypes.c_ubyte * len(ciphertext)).from_buffer_copy(ciphertext)
        in_blob = _DATA_BLOB(len(ciphertext), in_buf)
        ent_buf = (ctypes.c_ubyte * len(entropy)).from_buffer_copy(entropy)
        ent_blob = _DATA_BLOB(len(entropy), ent_buf)
        out_blob = _DATA_BLOB()

        ok = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(in_blob),
            None,
            ctypes.byref(ent_blob),
            None,
            None,
            cls.CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(out_blob),
        )
        if not ok:
            raise ctypes.WinError()
        try:
            return ctypes.string_at(out_blob.pbData, out_blob.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(out_blob.pbData)

    @classmethod
    def load_or_create_master_key(cls, key_file: Optional[Path | str] = None) -> bytes:
        path = Path(key_file or (Path(PROJECT_ROOT) / "data" / "dpapi_master_key.bin"))
        path.parent.mkdir(parents=True, exist_ok=True)
        for attempt in range(8):
            if path.is_file():
                try:
                    return cls.unprotect(path.read_bytes())
                except PermissionError:
                    time.sleep(0.01 * (attempt + 1))
                    continue
            raw_key = secrets.token_bytes(32)
            encrypted = cls.protect(raw_key)
            tmp = path.with_suffix(f".{os.getpid()}.{secrets.token_hex(4)}.tmp")
            tmp.write_bytes(encrypted)
            try:
                os.replace(tmp, path)
                return raw_key
            except PermissionError:
                tmp.unlink(missing_ok=True)
                time.sleep(0.01 * (attempt + 1))
        return cls.unprotect(path.read_bytes())


class AuthenticatedEnvelopeManager:
    """Signs CognitiveEnvelopes with DPAPI-protected HMAC-SHA256 & durable SQLite nonce store."""

    def __init__(
        self,
        *,
        key_file: Optional[Path | str] = None,
        nonce_db_path: Optional[Path | str] = None,
        max_skew_seconds: float = 300.0,
    ) -> None:
        self._key = WindowsDPAPIProvider.load_or_create_master_key(key_file)
        self.nonce_db_path = Path(
            nonce_db_path or (Path(PROJECT_ROOT) / "data" / "security_nonces.db")
        )
        self.nonce_db_path.parent.mkdir(parents=True, exist_ok=True)
        self.max_skew_seconds = max_skew_seconds
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.nonce_db_path), timeout=30.0)
        conn.execute("PRAGMA busy_timeout=30000;")
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS seen_nonces (
                    nonce TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL,
                    seen_at REAL NOT NULL
                )
                """
            )

    def sign(self, envelope: CognitiveEnvelope, *, nonce: Optional[str] = None) -> Dict[str, Any]:
        nonce_val = nonce or secrets.token_hex(16)
        issued_at = time.time()
        body_bytes = envelope.canonical_bytes()
        signing_input = f"{nonce_val}:{issued_at:.6f}:".encode("utf-8") + body_bytes
        sig = hmac.new(self._key, signing_input, hashlib.sha256).hexdigest()
        return {
            "protocol": "AETHERMIND-DPAPI-ENVELOPE-1",
            "nonce": nonce_val,
            "issued_at": issued_at,
            "envelope": envelope.to_dict(),
            "signature": sig,
        }

    def verify_and_consume(self, signed_packet: Dict[str, Any]) -> CognitiveEnvelope:
        if signed_packet.get("protocol") != "AETHERMIND-DPAPI-ENVELOPE-1":
            raise EnvelopeTamperedError("Invalid envelope protocol header")
        nonce_val = str(signed_packet.get("nonce", ""))
        issued_at = float(signed_packet.get("issued_at", 0.0))
        sig = str(signed_packet.get("signature", ""))
        env_dict = signed_packet.get("envelope")
        if not nonce_val or not sig or not isinstance(env_dict, dict):
            raise EnvelopeTamperedError("Malformed signed envelope fields")

        if abs(time.time() - issued_at) > self.max_skew_seconds:
            raise EnvelopeTamperedError("Signed envelope expired or clock skew exceeded")

        env = CognitiveEnvelope(**env_dict)
        expected_input = f"{nonce_val}:{issued_at:.6f}:".encode("utf-8") + env.canonical_bytes()
        expected_sig = hmac.new(self._key, expected_input, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            raise EnvelopeTamperedError("HMAC-SHA256 signature mismatch")

        with self._connect() as conn:
            try:
                conn.execute(
                    "INSERT INTO seen_nonces (nonce, event_id, seen_at) VALUES (?, ?, ?)",
                    (nonce_val, env.event_id, time.time()),
                )
            except sqlite3.IntegrityError as exc:
                raise ReplayAttackError(f"Replay detected for nonce '{nonce_val}'") from exc

        return env
