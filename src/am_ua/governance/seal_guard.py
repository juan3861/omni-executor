"""Immutable Constitution & Real-Byte SHA-256 Seal Guard (rotor-seed + Astra R17).

Fixes the P0 metadata-only canary defect flagged in MSEA Audit R2 by hashing
actual file byte streams (never st_size + st_mtime alone), blocking agent writes
to protected governance/eval paths, and protecting external canonical repos.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


class ConstitutionalViolationError(PermissionError):
    """Raised fail-closed when an action violates the Immutable Constitution."""


def compute_content_sha256(file_path: Path | str) -> str:
    """Compute real cryptographic SHA-256 over full file content bytes (zero-churn C buffer)."""
    p = Path(file_path)
    if not p.is_file():
        raise ConstitutionalViolationError(f"Expected regular file for SHA-256: {p}")
    if p.is_symlink():
        raise ConstitutionalViolationError(f"Symlink rejected in sealed zone: {p}")
    with p.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


class ConstitutionSealGuard:
    """Enforces R16/R17 constitutional immutability and external repo non-mutation."""

    SEAL_MANIFEST_REL = "constitution/SEAL_SHA256_MANIFEST.json"

    def __init__(self, project_root: Optional[Path | str] = None) -> None:
        self.root = Path(
            project_root
            or Path(__file__).resolve().parents[3]
        ).resolve()
        self.constitution_path = self.root / "constitution" / "IMMUTABLE_CONSTITUTION.json"
        if not self.constitution_path.is_file():
            raise ConstitutionalViolationError(
                f"Missing IMMUTABLE_CONSTITUTION.json at {self.constitution_path}"
            )
        self.policy = json.loads(self.constitution_path.read_text(encoding="utf-8"))
        self.seal_manifest_path = self.root / self.SEAL_MANIFEST_REL

    def _normalize_rel(self, target_path: Path | str) -> Tuple[Path, Optional[str]]:
        raw = Path(target_path)
        resolved = (raw if raw.is_absolute() else (self.root / raw)).resolve()
        try:
            rel = resolved.relative_to(self.root).as_posix()
            return resolved, rel
        except ValueError:
            return resolved, None

    def assert_write_allowed(
        self,
        target_path: Path | str,
        *,
        actor: str = "agent",
    ) -> Path:
        """Fail-closed check before any agent or evolver writes to disk."""
        resolved, rel = self._normalize_rel(target_path)
        norm_str = os.path.normcase(str(resolved))

        for ext in self.policy.get("untouchable_external_paths", []):
            ext_norm = os.path.normcase(str(Path(ext).resolve()))
            if norm_str == ext_norm or norm_str.startswith(ext_norm + os.sep):
                raise ConstitutionalViolationError(
                    f"Actor '{actor}' forbidden from writing to untouchable repo: {resolved}"
                )

        if rel is None:
            # Allow controlled writes inside safe_temp_root only; block arbitrary host paths.
            safe_temp = os.path.normcase(
                str(Path(self.policy["hardware_safety_locks"]["safe_temp_root"]).resolve())
            )
            if norm_str == safe_temp or norm_str.startswith(safe_temp + os.sep):
                return resolved
            raise ConstitutionalViolationError(
                f"Actor '{actor}' forbidden from writing outside project/temp root: {resolved}"
            )

        if actor != "constitutional_sealer":
            for prefix in self.policy.get("self_modification_forbidden_prefixes", []):
                clean_p = prefix.rstrip("/")
                if rel == clean_p or rel.startswith(clean_p + "/"):
                    raise ConstitutionalViolationError(
                        f"R17 violation: actor '{actor}' cannot modify sealed path '{rel}'"
                    )
        return resolved

    def assert_command_safe(self, command_line: str) -> None:
        """Reject GPU crash flags (-ngl 99 on RX 580) and forbidden git push."""
        lower = command_line.lower()
        for bad_flag in self.policy["hardware_safety_locks"].get("forbidden_cli_flags", []):
            if bad_flag.lower() in lower:
                raise ConstitutionalViolationError(
                    f"Hardware lock violation (RX 580): forbidden flag '{bad_flag}' in command"
                )
        if not self.policy["operational_laws"].get("allow_remote_git_push", False):
            if "git push" in lower or "gh repo create" in lower:
                raise ConstitutionalViolationError(
                    "Canonical directive violation: remote git push / repo creation is locked"
                )

    def collect_protected_hashes(self) -> Dict[str, str]:
        """Hash every regular file inside protected prefixes (excluding the manifest itself)."""
        hashes: Dict[str, str] = {}
        for prefix in self.policy.get("self_modification_forbidden_prefixes", []):
            target = self.root / prefix.rstrip("/")
            if not target.exists():
                continue
            if target.is_file():
                rel = target.relative_to(self.root).as_posix()
                if rel != self.SEAL_MANIFEST_REL:
                    hashes[rel] = compute_content_sha256(target)
            elif target.is_dir():
                for item in sorted(target.rglob("*")):
                    if "__pycache__" in item.parts or item.suffix == ".pyc":
                        continue
                    if item.is_symlink():
                        raise ConstitutionalViolationError(f"Symlink in sealed dir: {item}")
                    if item.is_file():
                        rel = item.relative_to(self.root).as_posix()
                        if rel != self.SEAL_MANIFEST_REL:
                            hashes[rel] = compute_content_sha256(item)
        return dict(sorted(hashes.items()))

    def write_seal_manifest(self) -> Dict[str, object]:
        """Seal current protected files into SEAL_SHA256_MANIFEST.json."""
        files = self.collect_protected_hashes()
        aggregate = hashlib.sha256(
            json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        payload = {
            "schema_version": "aethermind_seal_manifest/v1",
            "aggregate_sha256": aggregate,
            "file_count": len(files),
            "files": files,
        }
        self.seal_manifest_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return payload

    def verify_seal(self, *, require_manifest: bool = True) -> Tuple[bool, List[str]]:
        """Verify byte-level SHA-256 parity of all sealed files against manifest."""
        if not self.seal_manifest_path.is_file():
            if require_manifest:
                return False, ["Missing SEAL_SHA256_MANIFEST.json"]
            return True, []
        manifest = json.loads(self.seal_manifest_path.read_text(encoding="utf-8"))
        expected: Dict[str, str] = manifest.get("files", {})
        current = self.collect_protected_hashes()
        errors: List[str] = []
        for rel, exp_hash in expected.items():
            if rel not in current:
                errors.append(f"Deleted sealed file: {rel}")
            elif current[rel] != exp_hash:
                errors.append(
                    f"Tampered sealed file: {rel} (expected {exp_hash[:12]}, got {current[rel][:12]})"
                )
        for rel in current:
            if rel not in expected:
                errors.append(f"Unsealed file injected into protected zone: {rel}")
        return len(errors) == 0, errors
