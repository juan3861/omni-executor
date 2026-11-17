"""Hierarchical Knowledge Graph & Tree Index (src/am_ua/perception/knowledge_index.py).

Inspired by Graphify (Graphify-Labs/graphify) and PageIndex (VectifyAI/PageIndex):
vectorless, reasoning-friendly tree indexing over Markdown headings, JSON/TOML/YAML
configs, SQL schemas, and Python symbols with lightweight entity graph links.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple


_SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "node_modules", ".venv", "venv", "third_party"}
_HEADING_RX = re.compile(r"^(#{1,4})\s+(.+?)\s*$")
_SQL_TABLE_RX = re.compile(r"(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`\"']?([A-Za-z0-9_.]+)[`\"']?")
_PY_DEF_RX = re.compile(r"^(?:def|class|async\s+def)\s+([A-Za-z0-9_]+)")
_TOKEN_RX = re.compile(r"[a-z0-9_]{2,}")


class HierarchicalKnowledgeIndex:
    """Builds a queryable multi-format document/schema/code tree index with entity links."""

    TARGET_EXTS = {".md", ".markdown", ".json", ".toml", ".yaml", ".yml", ".sql", ".py", ".txt"}

    def __init__(self, root: Path | str, *, max_files: int = 300) -> None:
        self.root = Path(root).resolve()
        self.max_files = max_files
        self.nodes: List[Dict[str, Any]] = []
        self.entity_links: Dict[str, Set[str]] = {}
        self.build()

    def build(self) -> int:
        self.nodes.clear()
        self.entity_links.clear()
        scanned = 0
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for fname in filenames:
                if scanned >= self.max_files:
                    return len(self.nodes)
                fp = Path(dirpath) / fname
                if fp.suffix.lower() not in self.TARGET_EXTS:
                    continue
                try:
                    if fp.stat().st_size > 256_000:
                        continue
                    text = fp.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                scanned += 1
                rel = str(fp.relative_to(self.root)).replace("\\", "/")
                self._index_file(rel, fp.suffix.lower(), text)
        return len(self.nodes)

    def _index_file(self, rel: str, ext: str, text: str) -> None:
        lines = text.splitlines()
        if ext in (".md", ".markdown"):
            stack: List[str] = []
            for idx, ln in enumerate(lines, 1):
                m = _HEADING_RX.match(ln)
                if m:
                    lvl = len(m.group(1))
                    title = m.group(2).strip()
                    stack = stack[: lvl - 1] + [title]
                    snippet = "\n".join(lines[idx : idx + 6]).strip()
                    self._add_node(rel, "heading", " > ".join(stack), idx, snippet)
            if not any(n["file"] == rel for n in self.nodes):
                self._add_node(rel, "doc", Path(rel).name, 1, "\n".join(lines[:10]))
        elif ext == ".sql":
            for idx, ln in enumerate(lines, 1):
                m = _SQL_TABLE_RX.search(ln)
                if m:
                    self._add_node(rel, "sql_table", m.group(1), idx, "\n".join(lines[idx - 1 : idx + 8]))
        elif ext == ".json":
            try:
                data = json.loads(text)
                if isinstance(data, dict):
                    keys = list(data.keys())[:20]
                    self._add_node(rel, "json_schema", f"{rel}:[{','.join(keys)}]", 1, json.dumps(data, ensure_ascii=False)[:400])
            except Exception:
                self._add_node(rel, "json", rel, 1, "\n".join(lines[:10]))
        elif ext == ".py":
            for idx, ln in enumerate(lines, 1):
                m = _PY_DEF_RX.match(ln)
                if m:
                    self._add_node(rel, "symbol", m.group(1), idx, "\n".join(lines[idx - 1 : idx + 4]))
        else:
            self._add_node(rel, "config", rel, 1, "\n".join(lines[:12]))

    def _add_node(self, rel: str, kind: str, title: str, line: int, snippet: str) -> None:
        toks = set(_TOKEN_RX.findall(f"{rel} {title} {snippet}".lower()))
        self.nodes.append(
            {
                "file": rel,
                "kind": kind,
                "title": title[:160],
                "line": line,
                "snippet": snippet[:320],
                "_tokens": toks,
            }
        )
        for t in list(toks)[:25]:
            if len(t) >= 4:
                self.entity_links.setdefault(t, set()).add(rel)

    def query(self, question: str, *, top_k: int = 5) -> Dict[str, Any]:
        q_toks = set(_TOKEN_RX.findall((question or "").lower()))
        if not q_toks:
            return {"ok": True, "node_count": len(self.nodes), "hits": [], "related_files": []}
        scored: List[Tuple[float, Dict[str, Any]]] = []
        for n in self.nodes:
            overlap = len(q_toks & n["_tokens"])
            if overlap == 0:
                continue
            title_toks = set(_TOKEN_RX.findall(n["title"].lower()))
            bonus = 1.5 * len(q_toks & title_toks)
            score = overlap + bonus
            scored.append((score, n))
        scored.sort(key=lambda x: x[0], reverse=True)
        hits = [
            {
                "file": n["file"],
                "kind": n["kind"],
                "title": n["title"],
                "line": n["line"],
                "score": round(sc, 2),
                "snippet": n["snippet"],
            }
            for sc, n in scored[:top_k]
        ]
        related: Set[str] = set()
        for t in q_toks:
            related.update(self.entity_links.get(t, set()))
        return {
            "ok": True,
            "node_count": len(self.nodes),
            "hits": hits,
            "related_files": sorted(related)[:12],
        }
