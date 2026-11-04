"""Polyglot Eyes: RepoMap PageRank + Structural AST Search + OMNI_TOPOLOGY_V2 + MCP Federation (P4.2).

Unites:
  1. `PolyglotRepoMapper` (`aider` RepoMap architecture): Extracts definitions & cross-file
     symbol references across Python (`ast`), JS/TS, Rust, and Go, runs PageRank centrality
     to rank the highest-leverage architectural hubs within a token budget, and provides
     `ast-grep` / AST structural pattern search.
  2. `InterRepoTopologyGate` (`MSEA Factory OMNI_TOPOLOGY_V2`): Enforces acyclic / declared
     architectural layer boundaries and rejects undeclared or forbidden cross-layer imports.
  3. `MCPStdioClient`: Standards-compliant JSON-RPC 2.0 over stdio client (`initialize`,
     `tools/list`, `tools/call`) for `codex mcp-server`, `codebase-memory-mcp`, and
     `aetherre-megazord`.
"""

from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

SKIP_SCAN_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    "vendor",
    "target",
    ".venv",
    "venv",
    ".agent_comm",
}

POLYGLOT_DEF_PATTERNS: Dict[str, List[Tuple[str, re.Pattern[str]]]] = {
    ".js": [
        ("class", re.compile(r"\b(?:export\s+)?class\s+([A-Za-z_$][A-Za-z0-9_$]*)")),
        ("function", re.compile(r"\b(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)")),
    ],
    ".mjs": [
        ("class", re.compile(r"\b(?:export\s+)?class\s+([A-Za-z_$][A-Za-z0-9_$]*)")),
        ("function", re.compile(r"\b(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)")),
    ],
    ".ts": [
        ("class", re.compile(r"\b(?:export\s+)?class\s+([A-Za-z_$][A-Za-z0-9_$]*)")),
        ("interface", re.compile(r"\b(?:export\s+)?interface\s+([A-Za-z_$][A-Za-z0-9_$]*)")),
        ("function", re.compile(r"\b(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)")),
    ],
    ".rs": [
        ("struct", re.compile(r"\b(?:pub\s+)?struct\s+([A-Za-z_][A-Za-z0-9_]*)")),
        ("trait", re.compile(r"\b(?:pub\s+)?trait\s+([A-Za-z_][A-Za-z0-9_]*)")),
        ("fn", re.compile(r"\b(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)")),
    ],
    ".go": [
        ("type", re.compile(r"\btype\s+([A-Za-z_][A-Za-z0-9_]*)\s+(?:struct|interface)\b")),
        ("func", re.compile(r"\bfunc\s+(?:\([^)]+\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\(")),
    ],
}

IDENTIFIER_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]{2,}\b")


@dataclass
class SymbolDef:
    name: str
    kind: str
    rel_path: str
    line: int


@dataclass
class RankedFileSummary:
    rel_path: str
    pagerank: float
    symbols: List[SymbolDef] = field(default_factory=list)


class PolyglotRepoMapper:
    """Builds an aider-style PageRank symbol dependency map across Python/JS/TS/Rust/Go."""

    def __init__(self, repo_root: Path | str) -> None:
        self.root = Path(repo_root).resolve()

    def _extract_python_symbols(self, rel_path: str, text: str) -> Tuple[List[SymbolDef], Set[str]]:
        defs: List[SymbolDef] = []
        refs: Set[str] = set()
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return defs, set(IDENTIFIER_RE.findall(text))

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                defs.append(SymbolDef(node.name, "class", rel_path, node.lineno))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Record top-level functions and public methods
                if not node.name.startswith("__") or node.name == "__init__":
                    defs.append(SymbolDef(node.name, "def", rel_path, node.lineno))
            elif isinstance(node, ast.Name):
                refs.add(node.id)
            elif isinstance(node, ast.Attribute):
                refs.add(node.attr)
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    refs.add(alias.name)
        return defs, refs

    def _extract_polyglot_symbols(
        self, ext: str, rel_path: str, text: str
    ) -> Tuple[List[SymbolDef], Set[str]]:
        defs: List[SymbolDef] = []
        patterns = POLYGLOT_DEF_PATTERNS.get(ext, [])
        for lineno, line in enumerate(text.splitlines(), start=1):
            for kind, pat in patterns:
                for m in pat.finditer(line):
                    defs.append(SymbolDef(m.group(1), kind, rel_path, lineno))
        refs = set(IDENTIFIER_RE.findall(text))
        return defs, refs

    def build_ranked_map(
        self,
        *,
        max_chars: int = 4000,
        damping: float = 0.85,
        iterations: int = 25,
    ) -> Tuple[List[RankedFileSummary], str]:
        """Compute cross-file symbol PageRank and render compact ranked RepoMap."""
        file_defs: Dict[str, List[SymbolDef]] = {}
        file_refs: Dict[str, Set[str]] = {}
        symbol_owners: Dict[str, List[str]] = defaultdict(list)

        supported_exts = {".py", *POLYGLOT_DEF_PATTERNS.keys()}
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_SCAN_DIRS]
            for fname in sorted(filenames):
                fpath = Path(dirpath) / fname
                ext = fpath.suffix.lower()
                if ext not in supported_exts:
                    continue
                rel = fpath.relative_to(self.root).as_posix()
                try:
                    text = fpath.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                if ext == ".py":
                    defs, refs = self._extract_python_symbols(rel, text)
                else:
                    defs, refs = self._extract_polyglot_symbols(ext, rel, text)
                file_defs[rel] = defs
                file_refs[rel] = refs
                for d in defs:
                    if d.name != "__init__":
                        symbol_owners[d.name].append(rel)

        nodes = sorted(file_defs.keys())
        n = len(nodes)
        if n == 0:
            return [], ""

        # Directed edge u -> v if file u references a symbol defined in file v
        outgoing: Dict[str, Dict[str, float]] = {u: defaultdict(float) for u in nodes}
        for u in nodes:
            defined_here = {d.name for d in file_defs[u]}
            for sym in file_refs[u]:
                if sym in defined_here or sym not in symbol_owners:
                    continue
                owners = symbol_owners[sym]
                # Rarer symbols carry stronger architectural coupling weight
                weight = 1.0 / max(1, len(owners))
                for v in owners:
                    if v != u:
                        outgoing[u][v] += weight

        scores: Dict[str, float] = {u: 1.0 / n for u in nodes}
        base = (1.0 - damping) / n
        for _ in range(iterations):
            nxt: Dict[str, float] = {u: base for u in nodes}
            dangling_mass = 0.0
            for u in nodes:
                edges = outgoing[u]
                total_w = sum(edges.values())
                if total_w <= 0.0:
                    dangling_mass += scores[u]
                else:
                    for v, w in edges.items():
                        nxt[v] += damping * scores[u] * (w / total_w)
            if dangling_mass > 0.0:
                share = damping * dangling_mass / n
                for u in nodes:
                    nxt[u] += share
            scores = nxt

        ranked = [
            RankedFileSummary(
                rel_path=u,
                pagerank=round(scores[u], 6),
                symbols=file_defs[u],
            )
            for u in sorted(nodes, key=lambda k: scores[k], reverse=True)
        ]

        lines: List[str] = []
        used = 0
        for item in ranked:
            header = f"{item.rel_path} (PR={item.pagerank:.4f}):"
            sym_lines = [
                f"  L{s.line} {s.kind} {s.name}"
                for s in item.symbols[:16]
                if s.name != "__init__"
            ]
            block = "\n".join([header, *sym_lines]) if sym_lines else header
            if used + len(block) + 1 > max_chars and lines:
                break
            lines.append(block)
            used += len(block) + 1

        return ranked, "\n".join(lines)

    def structural_search(self, pattern: str, *, lang: str = "python") -> List[Dict[str, Any]]:
        """Execute `ast-grep` (`sg`) if installed, else deterministic AST/structural matcher."""
        sg_bin = shutil.which("ast-grep") or shutil.which("sg")
        if sg_bin:
            proc = subprocess.run(
                [sg_bin, "run", "--pattern", pattern, "--lang", lang, "--json", str(self.root)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip().startswith("["):
                raw = json.loads(proc.stdout)
                return [
                    {
                        "file": item.get("file", ""),
                        "line": item.get("range", {}).get("start", {}).get("line", 0) + 1,
                        "text": item.get("text", ""),
                        "engine": "ast-grep",
                    }
                    for item in raw
                ]

        # Native structural AST/regex fallback supporting `$VAR` meta-variables
        escaped = re.escape(pattern)
        regex_str = re.sub(r"\\\$[A-Z_][A-Z0-9_]*", r"(.+?)", escaped)
        compiled = re.compile(regex_str)
        matches: List[Dict[str, Any]] = []
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_SCAN_DIRS]
            for fname in sorted(filenames):
                fpath = Path(dirpath) / fname
                if lang == "python" and fpath.suffix.lower() != ".py":
                    continue
                try:
                    lines = fpath.read_text(encoding="utf-8", errors="ignore").splitlines()
                except OSError:
                    continue
                rel = fpath.relative_to(self.root).as_posix()
                for idx, line in enumerate(lines, start=1):
                    if compiled.search(line):
                        matches.append(
                            {
                                "file": rel,
                                "line": idx,
                                "text": line.strip(),
                                "engine": "native_structural",
                            }
                        )
        return matches


class InterRepoTopologyGate:
    """Enforces MSEA Autonomous Software Factory `OMNI_TOPOLOGY_V2` layer contracts."""

    DEFAULT_ALLOWED_DAG: Dict[str, Set[str]] = {
        "governance": set(),
        "contracts": {"governance"},
        "security": {"governance", "contracts"},
        "memory": {"governance", "contracts", "security"},
        "perception": {"governance", "contracts"},
        "routing": {"governance", "contracts"},
        "cognition": {"governance", "contracts"},
        "execution": {"governance", "contracts", "security", "perception", "cognition"},
        "runtime": {"governance", "contracts", "security", "execution", "memory"},
        "gui": {"governance", "contracts", "security", "execution"},
        "evolution": {"governance", "contracts", "execution", "cognition"},
        "lifecycle": {"governance", "contracts", "execution", "memory", "perception"},
    }

    def __init__(self, allowed_dag: Optional[Dict[str, Set[str]]] = None) -> None:
        self.allowed_dag = allowed_dag or {k: set(v) for k, v in self.DEFAULT_ALLOWED_DAG.items()}

    def audit_package_imports(self, package_root: Path | str) -> Dict[str, Any]:
        """Verify that `am_ua.<organ>` modules never violate `OMNI_TOPOLOGY_V2` DAG rules."""
        pkg = Path(package_root).resolve()
        violations: List[Dict[str, Any]] = []
        checked_edges = 0

        for py_file in sorted(pkg.rglob("*.py")):
            rel = py_file.relative_to(pkg).as_posix()
            parts = rel.split("/")
            if len(parts) < 2:
                continue  # top-level kernel/cli may orchestrate all organs
            source_organ = parts[0]
            if source_organ not in self.allowed_dag:
                continue
            try:
                tree = ast.parse(py_file.read_text(encoding="utf-8"))
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                target_mod: Optional[str] = None
                if isinstance(node, ast.ImportFrom) and node.module:
                    if node.module.startswith("am_ua."):
                        sub = node.module.split(".")
                        if len(sub) >= 2:
                            target_mod = sub[1]
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.startswith("am_ua."):
                            sub = alias.name.split(".")
                            if len(sub) >= 2:
                                target_mod = sub[1]
                if target_mod and target_mod != source_organ and target_mod in self.allowed_dag:
                    checked_edges += 1
                    if target_mod not in self.allowed_dag[source_organ]:
                        violations.append(
                            {
                                "file": rel,
                                "line": getattr(node, "lineno", 0),
                                "source_organ": source_organ,
                                "forbidden_target": target_mod,
                            }
                        )
        return {
            "protocol": "OMNI_TOPOLOGY_V2",
            "ok": len(violations) == 0,
            "checked_edges": checked_edges,
            "violations": violations,
        }


class MCPStdioClient:
    """Standards-compliant MCP JSON-RPC 2.0 client over stdio (newline-delimited JSON)."""

    def __init__(
        self,
        command: List[str],
        *,
        cwd: Optional[Path | str] = None,
        env: Optional[Dict[str, str]] = None,
        startup_timeout_s: float = 30.0,
    ) -> None:
        self.command = list(command)
        self.cwd = str(cwd) if cwd else None
        merged_env = os.environ.copy()
        merged_env["TMP"] = r"F:\AetherMind_Temp"
        merged_env["TEMP"] = r"F:\AetherMind_Temp"
        if env:
            merged_env.update(env)
        self.env = merged_env
        self.startup_timeout_s = startup_timeout_s
        self._proc: Optional[subprocess.Popen[str]] = None
        self._req_id = 0
        self._responses: Dict[int, Dict[str, Any]] = {}
        self._cv = threading.Condition()
        self._reader_thread: Optional[threading.Thread] = None

    def start(self) -> Dict[str, Any]:
        if self._proc is not None:
            raise RuntimeError("MCPStdioClient already started")
        self._proc = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            cwd=self.cwd,
            env=self.env,
        )
        self._reader_thread = threading.Thread(target=self._read_loop, daemon=True)
        self._reader_thread.start()
        init_res = self.request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "aethermind-universal-agent",
                    "title": "AetherMind Universal Agent",
                    "version": "3.1.0",
                },
            },
            timeout_s=self.startup_timeout_s,
        )
        self.notify("notifications/initialized", {})
        return init_res

    def _read_loop(self) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        while True:
            raw_line = self._proc.stdout.readline()
            if not raw_line:
                break
            line = raw_line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "id" in msg and isinstance(msg["id"], int):
                with self._cv:
                    self._responses[msg["id"]] = msg
                    self._cv.notify_all()

    def notify(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        if self._proc is None or self._proc.stdin is None:
            raise RuntimeError("MCP process not running")
        payload: Dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        self._proc.stdin.write(json.dumps(payload) + "\n")
        self._proc.stdin.flush()

    def request(
        self,
        method: str,
        params: Optional[Dict[str, Any]] = None,
        *,
        timeout_s: float = 30.0,
    ) -> Dict[str, Any]:
        if self._proc is None or self._proc.stdin is None:
            raise RuntimeError("MCP process not running")
        with self._cv:
            self._req_id += 1
            rid = self._req_id
        payload: Dict[str, Any] = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            payload["params"] = params
        self._proc.stdin.write(json.dumps(payload) + "\n")
        self._proc.stdin.flush()

        deadline = time.monotonic() + timeout_s
        with self._cv:
            while rid not in self._responses:
                if self._proc.poll() is not None:
                    err_txt = ""
                    if self._proc.stderr:
                        try:
                            err_txt = self._proc.stderr.read()
                        except Exception:
                            err_txt = ""
                    raise RuntimeError(
                        f"MCP server exited prematurely (rc={self._proc.returncode}) on '{method}': {err_txt.strip()}"
                    )
                rem = deadline - time.monotonic()
                if rem <= 0:
                    raise TimeoutError(f"MCP request '{method}' timed out after {timeout_s}s")
                self._cv.wait(timeout=min(0.25, rem))
            resp = self._responses.pop(rid)

        if "error" in resp:
            raise RuntimeError(f"MCP error on '{method}': {resp['error']}")
        return dict(resp.get("result", {}))

    def list_tools(self, *, timeout_s: float = 15.0) -> List[Dict[str, Any]]:
        res = self.request("tools/list", {}, timeout_s=timeout_s)
        return list(res.get("tools", []))

    def call_tool(
        self, name: str, arguments: Dict[str, Any], *, timeout_s: float = 30.0
    ) -> Dict[str, Any]:
        return self.request(
            "tools/call",
            {"name": name, "arguments": arguments},
            timeout_s=timeout_s,
        )

    def close(self) -> None:
        proc = self._proc
        self._proc = None
        if proc is None:
            return
        try:
            if proc.stdin:
                proc.stdin.close()
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    def __enter__(self) -> "MCPStdioClient":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()
