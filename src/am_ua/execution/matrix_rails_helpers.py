"""Shared helpers and specs for the 100-rail deterministic matrix."""

from __future__ import annotations

import ast
import base64
import csv
from decimal import Decimal, InvalidOperation
import difflib
import hashlib
from html.parser import HTMLParser
import json
import math
import os
from pathlib import Path
import re
import shutil
import sqlite3
import statistics
import struct
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
import xml.etree.ElementTree as ET
import zipfile

_SKIP_DIRS = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    ".pytest_cache",
    ".mypy_cache",
    "vendor",
    "HANDOFF_PACK",
}

MATRIX_69_SPECS: Dict[str, Tuple[str, int, bool]] = {
    # Domain A: Code Intelligence, AST & Refactoring (32-45)
    "dead_code_detector": ("Detect unused functions, classes, and imports across Python ASTs (vulture/ruff style).", 4500, False),
    "cyclomatic_complexity_audit": ("Compute McCabe cyclomatic complexity per function via Python AST (radon style).", 4000, False),
    "circular_import_detector": ("Build static import graph and detect circular import cycles via DFS (graphify style).", 4500, False),
    "docstring_coverage_audit": ("Calculate module/class/function docstring coverage percentage (interrogate style).", 3000, False),
    "unused_import_cleaner": ("Deterministically detect and optionally remove unused imports in Python files.", 3500, True),
    "sort_imports_deterministic": ("Deterministically sort Python top-level imports (stdlib, third-party, local).", 3000, True),
    "type_stub_generator": ("Generate PEP-484 .pyi type stub declarations from a Python source file AST.", 4500, True),
    "call_graph_extractor": ("Extract static caller-to-callee adjacency graph across Python AST functions.", 4500, False),
    "exception_anti_pattern_scan": ("Detect bare excepts, swallowed exceptions, and mutable default arguments via AST.", 3500, False),
    "constant_folding_optimizer": ("Evaluate and fold constant arithmetic/string expressions in Python AST.", 3500, False),
    "json_to_dataclass_codegen": ("Generate typed Python @dataclass definitions from a JSON object or file.", 5000, True),
    "regex_safety_redos_audit": ("Audit regular expressions for catastrophic backtracking (nested quantifiers / ReDoS).", 4000, False),
    "magic_number_extractor": ("Find repeated numeric/string magic literals in Python AST that should be named constants.", 3000, False),
    "api_surface_diff": ("Compare public API signatures between two Python files to detect breaking changes.", 4500, False),
    # Domain B: Git, CI/CD & DevOps Automation (46-56)
    "git_conflict_scanner": ("Scan workspace files for unresolved Git merge conflict markers (<<<<<<< / ======= / >>>>>>>).", 3000, False),
    "git_changelog_generator": ("Generate deterministic Conventional Commits markdown changelog from git log.", 4500, False),
    "git_blame_hotspot_analysis": ("Analyze git commit frequency and file churn hotspots across the repository.", 4000, False),
    "git_large_file_auditor": ("Detect oversized files and binary blobs in workspace before git commit/push.", 3000, False),
    "github_actions_validator": ("Validate .github/workflows YAML files for required keys, pinned actions, and structure.", 4000, False),
    "dockerfile_linter": ("Audit Dockerfile instructions for root-user risks, unpinned tags, and layer hygiene.", 3500, False),
    "dotenv_schema_validator": ("Compare .env against .env.example for missing/extra keys without exposing values.", 3000, False),
    "semver_bump_calculator": ("Compute next SemVer major/minor/patch version from current version and commit messages.", 3000, False),
    "gitignore_hygiene_auditor": ("Audit .gitignore coverage and detect tracked cache/build parasite directories.", 3000, False),
    "license_compatibility_auditor": ("Inspect repository LICENSE and package manifests for license compliance.", 3500, False),
    "makefile_task_extractor": ("Extract targets, dependencies, and commands from Makefile / Justfile / task scripts.", 3000, False),
    # Domain C: DataFrames, SQL, Formats & Integrity (57-68)
    "csv_schema_and_stats": ("Infer column types, null counts, and numeric min/max/mean/median statistics from CSV.", 4500, False),
    "json_schema_validator": ("Deterministically validate a JSON payload against a Draft-7 JSON schema.", 4000, False),
    "json_to_csv_converter": ("Convert a JSON array of objects into deterministic RFC-4180 CSV format.", 3500, True),
    "csv_to_json_converter": ("Convert a CSV file or string into typed JSON records.", 3500, True),
    "yaml_toml_json_transpiler": ("Transpile configuration data between JSON, TOML, and INI/key-value formats.", 4000, True),
    "sqlite_schema_inspector": ("Introspect SQLite database tables, columns, indexes, foreign keys, and row counts.", 4500, False),
    "sqlite_vacuum_and_integrity": ("Run SQLite PRAGMA integrity_check and quick foreign_key_check on a database.", 3500, False),
    "jsonl_stream_deduplicator": ("Deterministically deduplicate JSONL lines by content hash or key field.", 4000, True),
    "parquet_arrow_inspector": ("Inspect tabular dataset metadata and column schema (Parquet/CSV/JSONL).", 4000, False),
    "text_diff_unified": ("Compute deterministic unified diff and similarity ratio between two files or texts.", 3000, False),
    "archive_manifest_inspector": ("Inspect ZIP/TAR archive file list, compression ratio, and zip-slip path traversal safety.", 4000, False),
    "checksum_manifest_generator": ("Generate or verify SHA-256 / BLAKE2b cryptographic file integrity manifest.", 3500, False),
    # Domain D: Web, Browser, Scraping & Document Intelligence (69-79)
    "html_to_clean_markdown": ("Convert raw HTML into clean structured Markdown stripping scripts/styles (crawl4ai style).", 5000, False),
    "html_table_to_json": ("Extract HTML <table> elements into structured JSON arrays of rows.", 4500, False),
    "html_meta_opengraph_extractor": ("Extract HTML title, meta tags, OpenGraph properties, and canonical links.", 3500, False),
    "sitemap_robots_parser": ("Parse robots.txt directives and sitemap.xml URLs deterministically.", 3500, False),
    "url_normalizer_and_deparam": ("Canonicalize URLs and strip tracking query parameters (utm_*, fbclid, gclid).", 3000, False),
    "css_selector_locator_gen": ("Synthesize stable CSS selectors (#id, [data-testid], [name]) for interactive HTML elements.", 4500, False),
    "accessibility_aria_tree_dump": ("Build a compact deterministic accessibility/ARIA tree from HTML for browser agents.", 5000, False),
    "har_network_analyzer": ("Analyze HTTP Archive (HAR) JSON logs for status errors, slow endpoints, and payload sizes.", 4500, False),
    "pdf_type_classifier": ("Classify a PDF file as text-native vs scanned-image and count pages via raw stream inspection.", 4000, False),
    "markdown_toc_and_links_audit": ("Extract Markdown heading hierarchy TOC and detect broken local file links.", 3500, False),
    "rss_atom_feed_parser": ("Parse XML RSS 2.0 or Atom feeds into structured JSON items.", 3500, False),
    # Domain E: Windows OS, Desktop, Processes & Hardware (80-90)
    "win_service_inspector": ("Inspect Windows services state or portable daemon service status.", 4000, False),
    "win_scheduled_tasks_audit": ("Query scheduled tasks (schtasks CSV / cron) deterministically.", 4000, False),
    "win_startup_programs_audit": ("Inspect Windows startup folder and Run registry persistence entries.", 4000, False),
    "win_event_log_triage": ("Summarize recent Windows system/application warning & error events.", 4500, False),
    "win_network_connections": ("List active TCP/UDP listening ports and established connections via netstat.", 4000, False),
    "win_dns_and_hosts_audit": ("Inspect hosts file entries and test deterministic DNS hostname resolution.", 3500, False),
    "win_winget_package_audit": ("Query installed packages or winget/pip inventory deterministically.", 4000, False),
    "win_clipboard_inspect": ("Inspect current clipboard text length and line count safely.", 2500, False),
    "win_temp_hygiene_analyzer": ("Analyze temporary directory file count and reclaimable disk space.", 3500, False),
    "win_power_and_battery_probe": ("Probe CPU logical cores, platform architecture, and power/battery status.", 3000, False),
    "win_dll_pe_header_inspect": ("Parse Windows PE (.exe/.dll) MZ/PE headers, machine architecture, and section table.", 5000, False),
    # Domain F: Security, Cryptography, Math & Sandboxing (91-100)
    "jwt_token_inspector": ("Decode JWT header and payload claims (iss, sub, exp) without secret key.", 3500, False),
    "tls_certificate_inspector": ("Inspect PEM certificate metadata or TLS version capabilities.", 3500, False),
    "secret_entropy_scanner": ("Compute Shannon entropy across tokens to detect leaked high-entropy secrets.", 4500, False),
    "pii_redaction_rail": ("Deterministically redact emails, CPFs, SSNs, phones, and credit cards from text.", 4000, False),
    "cron_expression_evaluator": ("Validate 5-field cron expressions and expand matching minute/hour/day sets.", 3000, False),
    "math_symbolic_evaluator": ("Evaluate safe deterministic math expressions, statistics, and linear systems.", 4000, False),
    "financial_irr_npv_calculator": ("Compute exact Decimal Net Present Value (NPV), ROI, and loan amortization.", 4500, False),
    "rbac_policy_simulator": ("Simulate deterministic RBAC/ACL permission decisions for principal/action/resource.", 4000, False),
    "sandbox_escape_auditor": ("Audit code or shell scripts for path traversal, privileged calls, and escape vectors.", 4500, False),
    "deterministic_batch_pipeline": ("Execute a sequence of deterministic rails in a single zero-token pipeline.", 6000, False),
    # Domain G: OpenHands v1 SDK & OpenHuman Core Maximum Extraction Organs (101-110)
    "stuck_loop_detector": ("Analyze Action/Observation event stream for all 5 OpenHands stuck loop patterns.", 4500, False),
    "shell_policy_rails_audit": ("Evaluate shell command pipelines against structural policy rails (fetch-to-exec, raw-disk-op, catastrophic-delete).", 5000, False),
    "v4a_multifile_patch": ("Atomically validate and apply OpenHands/GPT-5 V4A multi-file patches with AST check and undo history.", 5500, True),
    "trajectory_critic_eval": ("Score agent execution trajectory via composite AgentFinished + EmptyPatch + Verification critic.", 4500, False),
    "tom_intent_consultant": ("Theory-of-Mind user intent & ambiguity profiler (0-token ToM consultation).", 3500, False),
    "sleeptime_compute_indexer": ("Consolidate idle-time agent trajectories into persistent hot-files and user preference profile.", 4500, True),
    "ask_oracle_dilemma": ("Distill architectural dilemma into compact brief and provide deterministic second-opinion guidance.", 5000, False),
    "planning_file_editor_rail": ("Strictly edit only PLAN.md / .omni_todo.md during PLAN mode while blocking code edits.", 3500, True),
    "stateful_python_kernel_rail": ("Execute Python expressions inside a persistent stateful session kernel preserving variables.", 4500, False),
    "inbound_debounce_triage": ("Coalesce rapid burst inbound user messages and audit plan review readiness (OpenHuman style).", 4000, False),
    # Domain H: Sub-Millisecond Token & Latency Savers from Top 100 Mature Repos (111-120)
    "ast_skeleton_compress": ("Fold Python function bodies into 1-line summaries preserving full API signatures (-80% tokens in <1ms).", 5500, False),
    "comby_template_rewrite": ("Balanced-hole :[var] structural template search & rewrite across any language (<1ms).", 4500, False),
    "prompt_token_pruner": ("Strip ANSI escapes, deduplicate log lines, and prune conversational filler (-60% tokens in <1ms).", 5000, False),
    "grammar_json_repair": ("Deterministically heal truncated, fenced, trailing-comma, or Python-literal JSON (<0.5ms, 0 retries).", 4500, False),
    "delta_debug_minimizer": ("Isolate the 1-minimal failing subset of lines/inputs in O(log N) steps via Zeller's ddmin.", 5500, False),
    "dom_semantic_distiller": ("Distill noisy raw HTML into a compact headings + interactive controls + content digest (-95% tokens).", 6000, False),
    "pyupgrade_modernizer": ("Upgrade legacy Python typing and super() idioms deterministically with AST validation.", 3500, False),
    "gitleaks_precommit_gate": ("Sub-millisecond pre-commit credential & private-key blocker (AWS, GitHub, OpenAI, PEM, Slack).", 4500, False),
    "semantic_cache_lookup": ("64-bit trigram SimHash near-duplicate prompt cache lookup (<0.1ms, -100% tokens on hit).", 6500, False),
    "pytest_affected_test_selector": ("Select only pytest files affected by modified source files via static import graph (-85% test latency).", 5000, False),
    # Domain I: 2077 Apex Senior AGI Engineering Organs (121-135)
    "sbfl_ochiai_fault_localize": ("Spectrum-Based Fault Localization (Ochiai & Tarantula formulas) ranking suspicious lines from test coverage.", 5500, False),
    "agentless_three_phase_localize": ("Zero-token Agentless 3-phase localizer (file ranking -> AST skeletons -> numbered code windows).", 6500, False),
    "autocoderover_ast_guard_synth": ("Synthesize AST-verified guard patch candidates for division, subscript, and None-attribute hazards.", 6000, False),
    "swe_agent_aci_window_view": ("Stateful SWE-agent ACI windowed file viewer with goto_line and scroll up/down navigation.", 4500, False),
    "swe_agent_aci_search_file": ("SWE-agent ACI windowed in-file pattern search returning numbered line matches and window bounds.", 4000, False),
    "aider_fuzzy_search_replace": ("4-level Aider fuzzy search/replace patch engine (exact, whitespace, indent, SequenceMatcher >= 0.92) with AST check.", 6000, True),
    "codeact_ast_multi_tool_run": ("Execute multi-step Python tool-chaining expressions inside a strict AST-whitelist CodeAct sandbox.", 6500, False),
    "dirty_worktree_snapshot_guard": ("Capture pre-edit SHA-256 worktree snapshots, inspect dirty status, and atomically rollback mutations.", 5000, True),
    "senior_architect_readiness_audit": ("Audit Python codebase across 5 senior-architect readiness metrics (AST, types, docstrings, complexity, hygiene).", 5500, False),
    "ast_import_dependency_layers": ("Build module and architectural layer dependency graph and detect DAG violations or cycles.", 5000, False),
    "deterministic_test_assertion_strengthener": ("Detect weak pytest assertions (assert True, bare assert x) and suggest stronger equality/type checks.", 4500, False),
    "exception_root_cause_chain_parser": ("Parse Python traceback text into ordered stack frames, root cause location, and exception class/message.", 4000, False),
    "api_backward_compat_contract_gate": ("Verify public API backward compatibility between old and new Python sources (removed symbols or required params).", 5000, False),
    "deterministic_pr_review_scorecard": ("Compute composite 0-100 senior PR review scorecard across readiness, layer DAG, compat, test strength, and security.", 6500, False),
    "apex_2077_full_diagnostic_sweep": ("Single-shot zero-token Apex 2077 sweep combining AST syntax check, senior architect audit, import layers, and secret gate.", 8000, False),
    # Domain J: TLA+ Formal Contracts, Raft/Paxos Self-Healing & CPU Cache Hardware Telemetry (136-150)
    "tla_plus_spec_transpiler": ("Compile declarative state-machine contracts into formal TLA+ (.tla) modules and TLC (.cfg) specs.", 6000, False),
    "tla_bounded_model_checker": ("Explicit-state BFS Kripke model checker verifying temporal invariants ([]I), deadlock freedom, and shortest counterexample traces.", 6500, False),
    "hoare_triple_contract_verifier": ("Verify Hoare logic triples {P} C {Q} and TLA+ UNCHANGED <<vars>> frame conditions across state transitions.", 5000, False),
    "temporal_liveness_leads_to": ("Verify temporal leads-to (P ~> Q / [](P => <>Q)) over finite transition graphs detecting livelock cycles and starvation.", 5500, False),
    "raft_consensus_election_sim": ("Simulate in-process multi-node Raft leader election (§5.2, §5.4.1 log up-to-dateness) and quorum log replication.", 6000, False),
    "raft_partition_self_healer": ("Simulate network split-brain partition, majority leader election, stale leader step-down, and SHA-256 log reconciliation.", 6500, False),
    "paxos_synod_decree_verifier": ("Execute Lamport's Single-Decree / Multi-Paxos Synod Phase 1a/1b (Prepare/Promise) and Phase 2a/2b (Accept/Accepted).", 6000, False),
    "phi_accrual_cluster_healer": ("Compute Hayashibara Phi-Accrual suspicion level Phi(t), detect Byzantine state-hash divergence, and emit self-healing actions.", 5500, False),
    "cpu_cache_hierarchy_probe": ("Probe CPU architecture, L1d/L2/L3 cache line capacities, and optimal FP64 matrix loop-tiling block dimensions.", 4500, False),
    "cache_line_false_sharing_audit": ("Detect 64-byte cache-line straddling and multi-thread false-sharing collisions and synthesize alignas(64) padded layouts.", 5500, False),
    "set_associative_cache_simulator": ("Simulate N-way set-associative LRU hardware cache hit/miss rates, evictions, AMAT cycles, and spatial stride efficiency.", 6000, False),
    "roofline_arithmetic_intensity": ("Evaluate compute kernels against the Williams-Waterman-Patterson Roofline model (Arithmetic Intensity, Ridge Point, regime).", 5500, False),
    "loop_tiling_cache_optimizer": ("Compute optimal L1/L2 tile block dimensions and simulate cache miss reduction via CPUCacheTopologyProbe & SetAssociativeCacheSimulator.", 6000, False),
    "distributed_contract_safety_gate": ("Combined TLA+ invariant bounded model check and Raft quorum consensus safety verification in a single zero-token call.", 7000, False),
    "omega_150_supreme_frontier_sweep": ("Execute combined zero-token verification across TLA+ bounded model checking, Raft partition self-healing, and CPU cache false-sharing + Roofline telemetry.", 9000, False),
    # Domain K: Nov 2026 Top-100 x Top-100 Total Extraction (REA, Ponytail, OpenCode HTTP-VCR, DeepSeek Cordis, Claw-Code Parity, Data Eng, App Router) (151-160)
    "ponytail_reuse_before_write_gate": ("Index workspace AST symbols before authoring so agents reuse existing functions (-53% code, -45% tokens).", 5500, False),
    "rea_binary_app_triage": ("Static reverse triage of PE/ELF binaries, ZIP/app bundles, and embedded URLs/API routes in 0 LLM tokens.", 6000, False),
    "http_vcr_record_replay": ("Deterministic SHA-256 HTTP cassette record/replay engine (<0.5ms zero-cost API mocking & test replay).", 5000, True),
    "cordis_plugin_lifecycle": ("Dependency-sorted composable plugin boot resolver & context container (DeepSeek-Harness Cordis style).", 4500, False),
    "claw_behavioral_parity_harness": ("Scripted multi-turn behavioral parity & contract verifier across tool calls (claw-code PARITY style).", 5500, False),
    "etl_sql_lineage_dag": ("Extract SQL CTE/FROM/JOIN table lineage DAG and topological execution order across ETL models.", 5500, False),
    "data_quality_expectation_gate": ("Deterministic Great-Expectations dataset quality gate (not_null, unique, between, in_set).", 5000, False),
    "sqlite_query_plan_auditor": ("Run EXPLAIN QUERY PLAN in isolated SQLite memory DB to detect full table scans and synthesize CREATE INDEX DDL.", 5500, False),
    "universal_app_command_router": ("Resolve software, VCS, container, browser-headless, and Windows OS intents to exact verified CLI argv.", 5000, False),
    "v62_top100_cross_parity_audit": ("Verify zero Windows stubs, live-wiring of Apex/OpenHands/TokenSavers inside AgentLoop, and 160 active rails.", 7500, False),
}

from am_ua.execution.deterministic_matrix_v70 import (  # noqa: E402
    V70_60_SPECS,
    execute_v70_60_rail,
    match_v70_60_rail,
)

MATRIX_69_SPECS.update(V70_60_SPECS)

_WORKSPACE_SNAPSHOT_GUARDS: Dict[str, Any] = {}


def _iter_py(workspace: Path, target: str = ".") -> List[Path]:
    ws = workspace.resolve()
    tgt = (ws / target).resolve() if not Path(target).is_absolute() else Path(target).resolve()
    if tgt != ws and ws not in tgt.parents:
        raise PermissionError(f"Target escapes workspace: {target}")
    if tgt.is_file():
        return [tgt] if tgt.suffix.lower() == ".py" else []
    out: List[Path] = []
    for p in tgt.rglob("*.py"):
        if not any(part in _SKIP_DIRS for part in p.parts):
            out.append(p)
    return sorted(out)


def _safe_path(workspace: Path, rel_or_abs: str) -> Path:
    ws = workspace.resolve()
    p = Path(rel_or_abs)
    tgt = (ws / p).resolve() if not p.is_absolute() else p.resolve()
    if tgt != ws and ws not in tgt.parents:
        raise PermissionError(f"Path escapes workspace boundary: {rel_or_abs}")
    return tgt


__all__ = ['_SKIP_DIRS', '_WORKSPACE_SNAPSHOT_GUARDS', 'MATRIX_69_SPECS', 'V70_60_SPECS', 'execute_v70_60_rail', 'match_v70_60_rail', '_iter_py', '_safe_path']
