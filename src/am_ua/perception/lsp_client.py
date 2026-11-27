"""Persistent Language Server Protocol (LSP) Client with Real JSON-RPC 2.0 & AST Fallback (v13.0).

Implements standard JSON-RPC 2.0 `Content-Length` stdio framing (both encode and read) for
persistent language servers (`basedpyright-langserver`, `pyright-langserver`,
`typescript-language-server`, `rust-analyzer`, `gopls`), paired with deterministic CLI
typecheck (`basedpyright`/`pyright`/`mypy`/`ruff`) and Python AST fallback when external
stdio LSP servers are unavailable.

OMNI_TOPOLOGY_V2 compliant: imports stdlib only (`perception` layer rule).
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
import re
import shutil
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional


class PersistentLSPClient:
    """Persistent stdio LSP JSON-RPC 2.0 client with deterministic typecheck + AST fallback."""

    SERVER_CANDIDATES: Dict[str, List[List[str]]] = {
        "python": [["basedpyright-langserver", "--stdio"], ["pyright-langserver", "--stdio"], ["pylsp"]],
        "typescript": [["typescript-language-server", "--stdio"]],
        "rust": [["rust-analyzer"]],
        "go": [["gopls"]],
    }

    def __init__(self, workspace: Path | str, *, language: str = "python") -> None:
        self.workspace = Path(workspace).resolve()
        self.language = (language or "python").strip().lower()
        self._proc: Optional[subprocess.Popen[bytes]] = None
        self._req_id = 0
        self._io_lock = threading.RLock()
        self._notifications: List[Dict[str, Any]] = []
        self._published_diagnostics: Dict[str, List[Dict[str, Any]]] = {}
        self.backend = "ast_fallback"
        self.server_capabilities: Dict[str, Any] = {}

    @classmethod
    def detect_server_command(cls, language: str = "python") -> Optional[List[str]]:
        for cmd in cls.SERVER_CANDIDATES.get(language.lower(), []):
            if shutil.which(cmd[0]):
                return list(cmd)
        return None

    @staticmethod
    def encode_lsp_message(payload: Dict[str, Any]) -> bytes:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        return header + body

    @staticmethod
    def decode_lsp_stream(raw_stream: bytes) -> List[Dict[str, Any]]:
        """Parse one or more Content-Length framed JSON-RPC 2.0 payloads from raw bytes."""
        messages: List[Dict[str, Any]] = []
        idx = 0
        total = len(raw_stream)
        while idx < total:
            sep = raw_stream.find(b"\r\n\r\n", idx)
            sep_len = 4
            if sep < 0:
                sep = raw_stream.find(b"\n\n", idx)
                sep_len = 2
            if sep < 0:
                break
            hdr = raw_stream[idx:sep].decode("ascii", errors="ignore")
            m = re.search(r"Content-Length:\s*(\d+)", hdr, re.IGNORECASE)
            if not m:
                idx = sep + sep_len
                continue
            length = int(m.group(1))
            body_start = sep + sep_len
            body_end = body_start + length
            if body_end > total:
                break
            try:
                messages.append(json.loads(raw_stream[body_start:body_end].decode("utf-8", errors="replace")))
            except json.JSONDecodeError:
                pass
            idx = body_end
        return messages

    def _read_one_frame(self, timeout_s: float = 2.0) -> Optional[Dict[str, Any]]:
        """Read a single Content-Length framed JSON-RPC message from stdout with bounded timeout."""
        if self._proc is None or self._proc.stdout is None:
            return None
        stream = self._proc.stdout
        result_box: List[Optional[Dict[str, Any]]] = []

        def _reader() -> None:
            try:
                content_len = 0
                while True:
                    line = stream.readline()
                    if not line:
                        return
                    stripped = line.strip()
                    if not stripped:
                        break
                    m = re.match(rb"Content-Length:\s*(\d+)", line, re.IGNORECASE)
                    if m:
                        content_len = int(m.group(1))
                if content_len <= 0:
                    return
                body = stream.read(content_len)
                if body:
                    result_box.append(json.loads(body.decode("utf-8", errors="replace")))
            except Exception:
                return

        t = threading.Thread(target=_reader, daemon=True)
        t.start()
        t.join(timeout=max(0.1, timeout_s))
        return result_box[0] if result_box else None

    def _send_notification(self, method: str, params: Dict[str, Any]) -> None:
        if self._proc is None or self._proc.stdin is None:
            return
        with self._io_lock:
            msg = self.encode_lsp_message({"jsonrpc": "2.0", "method": method, "params": params})
            self._proc.stdin.write(msg)
            self._proc.stdin.flush()

    def _send_request(self, method: str, params: Dict[str, Any], *, await_reply: bool = False, timeout_s: float = 3.0) -> Optional[Dict[str, Any]]:
        if self._proc is None or self._proc.stdin is None:
            return None
        with self._io_lock:
            self._req_id += 1
            rid = self._req_id
            msg = self.encode_lsp_message({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
            self._proc.stdin.write(msg)
            self._proc.stdin.flush()
            if not await_reply:
                return None
            deadline = time.monotonic() + timeout_s
            while time.monotonic() < deadline:
                frame = self._read_one_frame(timeout_s=max(0.15, deadline - time.monotonic()))
                if frame is None:
                    break
                if frame.get("id") == rid:
                    return frame
                if frame.get("method"):
                    self._handle_notification(frame)
        return None

    def _handle_notification(self, frame: Dict[str, Any]) -> None:
        self._notifications.append(frame)
        if frame.get("method") == "textDocument/publishDiagnostics":
            params = frame.get("params") or {}
            uri = str(params.get("uri") or "")
            diags = list(params.get("diagnostics") or [])
            if uri:
                self._published_diagnostics[uri] = diags

    def start(self, *, prefer_external: bool = False) -> Dict[str, Any]:
        """Start an external stdio LSP server (`initialize` -> `initialized`) if requested & available, else AST fallback."""
        if prefer_external:
            cmd = self.detect_server_command(self.language)
            if cmd:
                try:
                    self._proc = subprocess.Popen(
                        cmd,
                        cwd=str(self.workspace),
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    init_reply = self._send_request(
                        "initialize",
                        {
                            "processId": None,
                            "rootUri": self.workspace.as_uri(),
                            "capabilities": {
                                "textDocument": {
                                    "publishDiagnostics": {"relatedInformation": True},
                                    "hover": {"contentFormat": ["plaintext", "markdown"]},
                                    "definition": {"linkSupport": False},
                                    "references": {},
                                }
                            },
                        },
                        await_reply=True,
                        timeout_s=4.0,
                    )
                    if isinstance(init_reply, dict) and "result" in init_reply:
                        self.server_capabilities = dict((init_reply.get("result") or {}).get("capabilities") or {})
                        self._send_notification("initialized", {})
                        self.backend = f"lsp:{cmd[0]}"
                        return {
                            "ok": True,
                            "backend": self.backend,
                            "capabilities_count": len(self.server_capabilities),
                        }
                    self.shutdown()
                except Exception:
                    self._proc = None
        self.backend = "ast_fallback"
        return {"ok": True, "backend": self.backend}

    def notify_did_open(self, rel_or_abs_path: str) -> None:
        if self._proc is None:
            return
        p = Path(rel_or_abs_path)
        target = (self.workspace / p).resolve() if not p.is_absolute() else p.resolve()
        if not target.is_file():
            return
        lang_id = {".py": "python", ".ts": "typescript", ".js": "javascript", ".go": "go", ".rs": "rust"}.get(target.suffix.lower(), self.language)
        self._send_notification(
            "textDocument/didOpen",
            {
                "textDocument": {
                    "uri": target.as_uri(),
                    "languageId": lang_id,
                    "version": 1,
                    "text": target.read_text(encoding="utf-8", errors="replace"),
                }
            },
        )

    def _run_cli_typecheck_diags(self, target: Path) -> List[Dict[str, Any]]:
        """Run single-file `basedpyright` / `pyright` / `mypy` / `ruff` CLI checks when present."""
        out: List[Dict[str, Any]] = []
        if target.suffix.lower() != ".py":
            return out
        for tool_name in ("basedpyright", "pyright"):
            tool_bin = shutil.which(tool_name)
            if tool_bin:
                try:
                    proc = subprocess.run(
                        [tool_bin, "--outputjson", str(target)],
                        cwd=str(self.workspace),
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        timeout=6.0,
                        check=False,
                    )
                    payload = json.loads((proc.stdout or "{}").strip() or "{}")
                    for d in (payload.get("generalDiagnostics") or [])[:25]:
                        st = ((d.get("range") or {}).get("start") or {})
                        out.append({
                            "file": target.relative_to(self.workspace).as_posix() if self.workspace in target.parents else str(target),
                            "line": int(st.get("line", 0)) + 1,
                            "col": int(st.get("character", 0)) + 1,
                            "severity": str(d.get("severity") or "error"),
                            "code": str(d.get("rule") or tool_name),
                            "message": str(d.get("message") or ""),
                            "source": tool_name,
                        })
                    return out
                except Exception:
                    break
        mypy_bin = shutil.which("mypy")
        if mypy_bin:
            try:
                proc = subprocess.run(
                    [mypy_bin, "--hide-error-context", "--no-color-output", "--ignore-missing-imports", "--follow-imports=silent", str(target)],
                    cwd=str(self.workspace),
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=6.0,
                    check=False,
                )
                for ln in (proc.stdout or "").splitlines():
                    m = re.match(r"^.+?:(\d+):(?:\s*(\d+):)?\s*(error|warning):\s*(.+)$", ln.strip())
                    if m:
                        out.append({
                            "file": target.relative_to(self.workspace).as_posix() if self.workspace in target.parents else str(target),
                            "line": int(m.group(1)),
                            "col": int(m.group(2) or 1),
                            "severity": m.group(3),
                            "code": "mypy",
                            "message": m.group(4)[:240],
                            "source": "mypy",
                        })
                return out[:25]
            except Exception:
                pass
        return out

    def get_diagnostics(self, rel_or_abs_path: str, *, include_typecheck: bool = False) -> Dict[str, Any]:
        """Return structured line/col syntax + optional LSP/typecheck diagnostics for a file."""
        p = Path(rel_or_abs_path)
        target = (self.workspace / p).resolve() if not p.is_absolute() else p.resolve()
        if not target.is_file():
            return {"ok": False, "error": f"File not found: {rel_or_abs_path}", "diagnostics": []}

        src = target.read_text(encoding="utf-8", errors="replace")
        diagnostics: List[Dict[str, Any]] = []
        rel_str = target.relative_to(self.workspace).as_posix() if self.workspace in target.parents else str(target)
        if target.suffix.lower() == ".py":
            try:
                ast.parse(src, filename=str(target))
            except SyntaxError as exc:
                diagnostics.append({
                    "file": rel_str,
                    "line": int(exc.lineno or 1),
                    "col": int(exc.offset or 1),
                    "severity": "error",
                    "code": "SyntaxError",
                    "message": str(exc.msg),
                    "source": "python_ast",
                })
        if not diagnostics and (include_typecheck or self.backend.startswith("lsp:")):
            if self.backend.startswith("lsp:"):
                self.notify_did_open(str(target))
                frame = self._read_one_frame(timeout_s=1.2)
                if frame and frame.get("method"):
                    self._handle_notification(frame)
                lsp_diags = self._published_diagnostics.get(target.as_uri(), [])
                for d in lsp_diags[:25]:
                    st = ((d.get("range") or {}).get("start") or {})
                    sev_num = d.get("severity", 1)
                    sev = "error" if sev_num == 1 else ("warning" if sev_num == 2 else "info")
                    diagnostics.append({
                        "file": rel_str,
                        "line": int(st.get("line", 0)) + 1,
                        "col": int(st.get("character", 0)) + 1,
                        "severity": sev,
                        "code": str(d.get("code") or self.backend),
                        "message": str(d.get("message") or ""),
                        "source": self.backend,
                    })
            if not diagnostics and include_typecheck:
                diagnostics.extend(self._run_cli_typecheck_diags(target))

        has_error = any(d.get("severity", "error") == "error" for d in diagnostics)
        return {
            "ok": not has_error,
            "backend": self.backend,
            "diagnostic_count": len(diagnostics),
            "diagnostics": diagnostics,
        }

    def goto_definition(self, symbol_name: str, *, target_dir: str = ".") -> Dict[str, Any]:
        """Locate exact definition(s) of a function/class/method across workspace Python files."""
        sym = (symbol_name or "").strip()
        if not sym:
            return {"ok": False, "error": "Missing symbol_name", "locations": []}
        base = (self.workspace / target_dir).resolve()
        locations: List[Dict[str, Any]] = []
        for py in sorted(base.rglob("*.py")):
            if any(part in {".git", "__pycache__", ".venv", "venv", "node_modules"} for part in py.parts):
                continue
            try:
                tree = ast.parse(py.read_text(encoding="utf-8", errors="replace"), filename=str(py))
            except (OSError, SyntaxError):
                continue
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == sym:
                    locations.append({
                        "file": py.relative_to(self.workspace).as_posix(),
                        "line": int(node.lineno),
                        "col": int(node.col_offset) + 1,
                        "kind": type(node).__name__,
                    })
        return {
            "ok": len(locations) > 0,
            "backend": self.backend,
            "symbol": sym,
            "locations": locations[:50],
        }

    def find_references(self, symbol_name: str, *, target_dir: str = ".") -> Dict[str, Any]:
        """Locate AST symbol call, import, attribute, and name references across workspace Python files."""
        sym = (symbol_name or "").strip()
        if not sym:
            return {"ok": False, "error": "Missing symbol_name", "references": []}
        base = (self.workspace / target_dir).resolve()
        refs: List[Dict[str, Any]] = []
        for py in sorted(base.rglob("*.py")):
            if any(part in {".git", "__pycache__", ".venv", "venv", "node_modules"} for part in py.parts):
                continue
            try:
                txt = py.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(txt, filename=str(py))
            except (OSError, SyntaxError):
                continue
            rel = py.relative_to(self.workspace).as_posix()
            for node in ast.walk(tree):
                hit_kind = ""
                if isinstance(node, ast.Name) and node.id == sym:
                    hit_kind = "name"
                elif isinstance(node, ast.Attribute) and node.attr == sym:
                    hit_kind = "attribute"
                elif isinstance(node, ast.ImportFrom) and any(a.name == sym for a in node.names):
                    hit_kind = "import"
                if hit_kind:
                    refs.append({"file": rel, "line": int(getattr(node, "lineno", 1)), "kind": hit_kind})
                    if len(refs) >= 100:
                        return {"ok": True, "backend": self.backend, "symbol": sym, "references": refs, "truncated": True}
        return {"ok": len(refs) > 0, "backend": self.backend, "symbol": sym, "references": refs, "truncated": False}

    def hover_signature(self, rel_or_abs_path: str, line: int = 1) -> Dict[str, Any]:
        """Return function/class signature & docstring at or nearest `line` (AST / LSP)."""
        p = Path(rel_or_abs_path)
        target = (self.workspace / p).resolve() if not p.is_absolute() else p.resolve()
        if not target.is_file():
            return {"ok": False, "error": f"File not found: {rel_or_abs_path}"}
        try:
            tree = ast.parse(target.read_text(encoding="utf-8", errors="replace"), filename=str(target))
        except SyntaxError as exc:
            return {"ok": False, "error": f"SyntaxError: {exc}"}
        best_node: Any = None
        best_dist = 10**9
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                dist = abs(int(node.lineno) - int(line))
                if dist < best_dist:
                    best_dist = dist
                    best_node = node
        if best_node is None:
            return {"ok": False, "error": "No function or class signature found"}
        if isinstance(best_node, ast.ClassDef):
            sig = f"class {best_node.name}"
        else:
            args = [a.arg for a in best_node.args.args]
            sig = f"def {best_node.name}({', '.join(args)})"
        doc = ast.get_docstring(best_node) or ""
        return {
            "ok": True,
            "symbol": best_node.name,
            "line": int(best_node.lineno),
            "signature": sig,
            "docstring": doc[:400],
            "backend": self.backend,
        }

    def shutdown(self) -> None:
        if self._proc is not None:
            try:
                self._send_request("shutdown", {}, await_reply=False)
                self._send_notification("exit", {})
                self._proc.terminate()
                self._proc.wait(timeout=3)
            except Exception:
                pass
            self._proc = None
