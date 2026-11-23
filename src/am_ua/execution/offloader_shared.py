"""Shared path/file helpers and rail registry for DeterministicTaskOffloader."""

from __future__ import annotations

import ast
import csv
from dataclasses import dataclass
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class DeterministicRailSpec:
    name: str
    description: str
    estimated_tokens_saved: int
    mutates_workspace: bool = False


BUILTIN_DETERMINISTIC_RAILS: Dict[str, DeterministicRailSpec] = {
    "list_capabilities": DeterministicRailSpec(
        name="list_capabilities",
        description="List all deterministic rails and detected host backends (ruff, libcst, tree_sitter, hypothesis, git, uv, etc.).",
        estimated_tokens_saved=1000,
    ),
    "shield_audit": DeterministicRailSpec(
        name="shield_audit",
        description="Run static SAST & secret scan across workspace without LLM turns.",
        estimated_tokens_saved=3500,
    ),
    "repo_topology_map": DeterministicRailSpec(
        name="repo_topology_map",
        description="Build polyglot PageRank RepoMap and AST symbol summary deterministically.",
        estimated_tokens_saved=4000,
    ),
    "ast_syntax_sweep": DeterministicRailSpec(
        name="ast_syntax_sweep",
        description="Parse all Python files in workspace to catch SyntaxError/IndentationError in 0 tokens.",
        estimated_tokens_saved=2500,
    ),
    "verify_only_check": DeterministicRailSpec(
        name="verify_only_check",
        description="Execute verification command directly when objective asks only to run/verify tests.",
        estimated_tokens_saved=3000,
    ),
    "workspace_preflight": DeterministicRailSpec(
        name="workspace_preflight",
        description="Single-shot deterministic bundle: file inventory + AST sweep + SAST + RepoMap.",
        estimated_tokens_saved=6000,
    ),
    "code_autofix_and_lint": DeterministicRailSpec(
        name="code_autofix_and_lint",
        description="Auto-fix lint/formatting issues deterministically via ruff (or builtin Python AST/whitespace normalizer).",
        estimated_tokens_saved=4500,
        mutates_workspace=True,
    ),
    "structural_search_replace": DeterministicRailSpec(
        name="structural_search_replace",
        description="AST-aware structural symbol/pattern search (and optional safe replacement) across Python files.",
        estimated_tokens_saved=4000,
        mutates_workspace=True,
    ),
    "type_and_contract_check": DeterministicRailSpec(
        name="type_and_contract_check",
        description="Run mypy/pyright if installed, or deterministic Python AST annotation & signature audit.",
        estimated_tokens_saved=3500,
    ),
    "property_edge_fuzz": DeterministicRailSpec(
        name="property_edge_fuzz",
        description="Fuzz a workspace Python callable (`module:func`) with deterministic boundary inputs (None, '', 0, -1, [], {}).",
        estimated_tokens_saved=5000,
    ),
    "git_forensics": DeterministicRailSpec(
        name="git_forensics",
        description="Return structured git status, branch, diff --stat, and recent commits in a single call.",
        estimated_tokens_saved=2500,
    ),
    "data_sql_query": DeterministicRailSpec(
        name="data_sql_query",
        description="Run read-only SQL SELECT over CSV/JSON/JSONL/SQLite files using duckdb or builtin sqlite3.",
        estimated_tokens_saved=4000,
    ),
    "sbom_and_deps_audit": DeterministicRailSpec(
        name="sbom_and_deps_audit",
        description="Extract deterministic SBOM dependency inventory from pyproject.toml, requirements, package.json, Cargo.toml, go.mod.",
        estimated_tokens_saved=3000,
    ),
    "structural_diff": DeterministicRailSpec(
        name="structural_diff",
        description="Compare two Python files/snippets by AST symbol structure (added/removed/modified functions & classes).",
        estimated_tokens_saved=3000,
    ),
    "generate_pytest_skeleton": DeterministicRailSpec(
        name="generate_pytest_skeleton",
        description="Generate deterministic pytest skeleton with boundary cases from Python AST signatures.",
        estimated_tokens_saved=5500,
        mutates_workspace=True,
    ),
    "extract_document_structured": DeterministicRailSpec(
        name="extract_document_structured",
        description="Extract structured sections, tables, and metadata from md/csv/json/html/pdf/docx/xlsx in 0 LLM tokens.",
        estimated_tokens_saved=4500,
    ),
    "polyglot_outline": DeterministicRailSpec(
        name="polyglot_outline",
        description="Extract AST/symbol outline for Python, JS/TS, Rust, and Go files in 1 deterministic call.",
        estimated_tokens_saved=3000,
    ),
    "libcst_safe_codemod": DeterministicRailSpec(
        name="libcst_safe_codemod",
        description="Format-preserving Python CST symbol rename via LibCST (with AST fallback).",
        estimated_tokens_saved=4000,
        mutates_workspace=True,
    ),
    "replace_function_body": DeterministicRailSpec(
        name="replace_function_body",
        description="Replace a Python function/method definition by AST symbol name without fragile text matching.",
        estimated_tokens_saved=4500,
        mutates_workspace=True,
    ),
    "pytest_failure_diagnoser": DeterministicRailSpec(
        name="pytest_failure_diagnoser",
        description="Run pytest (or parse pytest output) into structured failure records (test, file, line, assertion).",
        estimated_tokens_saved=3500,
    ),
    "z3_constraint_solve": DeterministicRailSpec(
        name="z3_constraint_solve",
        description="Solve integer/real/boolean constraint systems formally using Z3 SMT solver (sat/unsat + exact model).",
        estimated_tokens_saved=5000,
    ),
    "hypothesis_property_test": DeterministicRailSpec(
        name="hypothesis_property_test",
        description="Run Hypothesis property-based fuzzing with automatic shrinking and post-condition invariant checks.",
        estimated_tokens_saved=5500,
    ),
    "codegen_from_openapi": DeterministicRailSpec(
        name="codegen_from_openapi",
        description="Deterministically generate typed Python models and HTTP client from an OpenAPI JSON spec in 0 LLM tokens.",
        estimated_tokens_saved=6500,
        mutates_workspace=True,
    ),
    "codegen_sql_to_python": DeterministicRailSpec(
        name="codegen_sql_to_python",
        description="Deterministically generate typed Python SQLite/DuckDB repository code from a .sql schema in 0 LLM tokens.",
        estimated_tokens_saved=5500,
        mutates_workspace=True,
    ),
    "os_sql_query": DeterministicRailSpec(
        name="os_sql_query",
        description="Query workspace files, sanitized env vars, and host processes as SQL tables (osquery-style).",
        estimated_tokens_saved=3500,
    ),
    "fastmft_radar": DeterministicRailSpec(
        name="fastmft_radar",
        description="Ultra-fast NTFS/filesystem topology radar, Casimir bistable storage diagnostics, ARIA 7-lens advise, UCIP compression, and build parasite detection/cleanup via fastmft v1.3.0.",
        estimated_tokens_saved=6500,
    ),
    "ledger_audit": DeterministicRailSpec(
        name="ledger_audit",
        description="Deterministic double-entry accounting ledger verifier using exact Decimal math (zero floating-point error) for journal balance and reconciliation.",
        estimated_tokens_saved=4500,
    ),
    "lsp_diagnostics": DeterministicRailSpec(
        name="lsp_diagnostics",
        description="Persistent LSP JSON-RPC (with instant AST fallback) file diagnostics and go-to-definition lookup in 0 LLM tokens.",
        estimated_tokens_saved=3500,
    ),
    "windows_system_rail": DeterministicRailSpec(
        name="windows_system_rail",
        description="Pre-built 0-token Windows Desktop & OS rail: window list/find, UIA/OCR probe, process & TCP port owner inspection, clipboard, and Casimir storage/RAM health.",
        estimated_tokens_saved=5000,
    ),
    "browser_playbook_rail": DeterministicRailSpec(
        name="browser_playbook_rail",
        description="Pre-built 0-token Browser & Web rail: SSRF/domain guard verification, clean HTML/form/link/table extraction, and deterministic multi-step CDP playbook execution.",
        estimated_tokens_saved=5500,
    ),
    "patch_validate_and_apply": DeterministicRailSpec(
        name="patch_validate_and_apply",
        description="Deterministically validate and optionally apply a unified diff patch with in-memory Python AST syntax verification before disk write.",
        estimated_tokens_saved=4500,
        mutates_workspace=True,
    ),
}

from am_ua.execution.deterministic_matrix_100 import (  # noqa: E402
    MATRIX_69_SPECS,
    execute_matrix_69_rail,
    match_matrix_69_rail,
)

for _m_name, (_m_desc, _m_tok, _m_mut) in MATRIX_69_SPECS.items():
    BUILTIN_DETERMINISTIC_RAILS[_m_name] = DeterministicRailSpec(
        name=_m_name,
        description=_m_desc,
        estimated_tokens_saved=_m_tok,
        mutates_workspace=_m_mut,
    )

# Never intercept tasks that ask to modify, create, fix, or refactor code.
_MUTATION_INTENT_RX = re.compile(
    r"\b(fix|implement|create|write|add|edit|modify|refactor|update|patch|build|remove|delete|"
    r"corrija|conserte|implemente|crie|escreva|adicione|edite|altere|refatore|atualize|remova)\b",
    re.IGNORECASE,
)

_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".pytest_cache", ".mypy_cache", "vendor", "HANDOFF_PACK"}


def _iter_py_files(workspace: Path) -> List[Path]:
    out: List[Path] = []
    for py in workspace.rglob("*.py"):
        if any(part in _SKIP_DIRS for part in py.parts):
            continue
        out.append(py)
    return sorted(out)


def _resolve_in_workspace(workspace: Path, rel_or_abs: str) -> Path:
    ws = workspace.resolve()
    p = Path(rel_or_abs)
    target = (ws / p).resolve() if not p.is_absolute() else p.resolve()
    if target != ws and ws not in target.parents:
        raise PermissionError(f"Path escapes workspace boundary: {rel_or_abs}")
    return target

