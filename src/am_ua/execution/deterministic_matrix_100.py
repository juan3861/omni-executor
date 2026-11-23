"""100-Rail Deterministic Matrix (`am_ua.execution.deterministic_matrix_100`)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict, Optional

from am_ua.execution.apex_v62_extracts import execute_real_win_os_rail  # live-wiring anchor
from am_ua.execution.matrix_rails_apex_v62 import execute_apex_v62
from am_ua.execution.matrix_rails_code_git_data import execute_code_git_data
from am_ua.execution.matrix_rails_helpers import (
    MATRIX_69_SPECS,
    V70_60_SPECS,
    _SKIP_DIRS,
    _WORKSPACE_SNAPSHOT_GUARDS,
    _iter_py,
    _safe_path,
    execute_v70_60_rail,
    match_v70_60_rail,
)
from am_ua.execution.matrix_rails_nov26_v62 import execute_nov26_v62
from am_ua.execution.matrix_rails_tla_raft_cpu import execute_tla_raft_cpu
from am_ua.execution.matrix_rails_web_win_sec import execute_web_win_sec

def match_matrix_69_rail(low: str) -> Optional[str]:
    """Match natural-language diagnostic objectives to any of Rails 32-100."""
    keyword_map: List[Tuple[Tuple[str, ...], str]] = [
        (("dead code", "codigo morto", "unused function"), "dead_code_detector"),
        (("cyclomatic", "complexidade ciclomatica", "mccabe"), "cyclomatic_complexity_audit"),
        (("circular import", "import circular", "import cycle"), "circular_import_detector"),
        (("docstring coverage", "cobertura de docstring"), "docstring_coverage_audit"),
        (("call graph", "grafo de chamadas"), "call_graph_extractor"),
        (("anti pattern", "bare except", "mutable default"), "exception_anti_pattern_scan"),
        (("redos", "regex safety", "backtracking"), "regex_safety_redos_audit"),
        (("magic number", "numeros magicos"), "magic_number_extractor"),
        (("merge conflict", "conflito de merge", "git conflict"), "git_conflict_scanner"),
        (("changelog", "release notes"), "git_changelog_generator"),
        (("git hotspot", "code churn", "git blame"), "git_blame_hotspot_analysis"),
        (("large file", "arquivos grandes"), "git_large_file_auditor"),
        (("github actions", "workflow yaml"), "github_actions_validator"),
        (("dockerfile lint", "audit dockerfile"), "dockerfile_linter"),
        (("dotenv", ".env.example"), "dotenv_schema_validator"),
        (("semver", "bump version", "proxima versao"), "semver_bump_calculator"),
        (("gitignore hygiene", "audit gitignore"), "gitignore_hygiene_auditor"),
        (("license audit", "licenca"), "license_compatibility_auditor"),
        (("makefile", "extract tasks"), "makefile_task_extractor"),
        (("csv stats", "csv schema", "estatisticas csv"), "csv_schema_and_stats"),
        (("json schema", "validar json"), "json_schema_validator"),
        (("sqlite schema", "inspecionar sqlite"), "sqlite_schema_inspector"),
        (("sqlite integrity", "pragma integrity"), "sqlite_vacuum_and_integrity"),
        (("checksum manifest", "sha256 manifest"), "checksum_manifest_generator"),
        (("html to markdown", "clean markdown"), "html_to_clean_markdown"),
        (("html table", "tabela html"), "html_table_to_json"),
        (("opengraph", "meta tags"), "html_meta_opengraph_extractor"),
        (("robots.txt", "sitemap.xml"), "sitemap_robots_parser"),
        (("normalize url", "strip utm"), "url_normalizer_and_deparam"),
        (("css selector", "gerar seletor"), "css_selector_locator_gen"),
        (("aria tree", "accessibility tree"), "accessibility_aria_tree_dump"),
        (("har analyze", "network har"), "har_network_analyzer"),
        (("pdf classify", "scanned pdf"), "pdf_type_classifier"),
        (("markdown toc", "broken links"), "markdown_toc_and_links_audit"),
        (("rss feed", "atom feed"), "rss_atom_feed_parser"),
        (("windows service", "servicos do windows"), "win_service_inspector"),
        (("scheduled task", "schtasks", "tarefas agendadas"), "win_scheduled_tasks_audit"),
        (("startup program", "programas de inicializacao"), "win_startup_programs_audit"),
        (("event log", "visualizador de eventos"), "win_event_log_triage"),
        (("netstat", "network connections", "conexoes de rede"), "win_network_connections"),
        (("hosts file", "dns audit"), "win_dns_and_hosts_audit"),
        (("winget", "installed packages"), "win_winget_package_audit"),
        (("clipboard", "area de transferencia"), "win_clipboard_inspect"),
        (("temp hygiene", "limpeza temp"), "win_temp_hygiene_analyzer"),
        (("battery probe", "power plan"), "win_power_and_battery_probe"),
        (("pe header", "dll header", "inspect exe"), "win_dll_pe_header_inspect"),
        (("jwt decode", "inspect jwt"), "jwt_token_inspector"),
        (("tls cert", "inspect certificate"), "tls_certificate_inspector"),
        (("shannon entropy", "secret entropy"), "secret_entropy_scanner"),
        (("redact pii", "anonimizar pii"), "pii_redaction_rail"),
        (("cron expression", "avaliar cron"), "cron_expression_evaluator"),
        (("npv", "irr", "amortization"), "financial_irr_npv_calculator"),
        (("rbac simulate", "acl simulate"), "rbac_policy_simulator"),
        (("sandbox escape", "audit escape"), "sandbox_escape_auditor"),
        (("sbfl", "ochiai", "tarantula"), "sbfl_ochiai_fault_localize"),
        (("three phase localize", "agentless localize", "3-phase localize"), "agentless_three_phase_localize"),
        (("guard synth", "autocoderover"), "autocoderover_ast_guard_synth"),
        (("senior architect", "readiness audit"), "senior_architect_readiness_audit"),
        (("import dependency layers", "import layers"), "ast_import_dependency_layers"),
        (("assertion strengthener", "weak assertions"), "deterministic_test_assertion_strengthener"),
        (("traceback root cause", "parse exception traceback", "root cause chain"), "exception_root_cause_chain_parser"),
        (("backward compat", "api backward"), "api_backward_compat_contract_gate"),
        (("pr review scorecard", "pr scorecard"), "deterministic_pr_review_scorecard"),
        (("apex 2077", "full diagnostic sweep"), "apex_2077_full_diagnostic_sweep"),
        (("tla+", "tla spec", "transpile tla"), "tla_plus_spec_transpiler"),
        (("model check", "tlc model", "kripke"), "tla_bounded_model_checker"),
        (("hoare triple", "hoare contract", "frame condition"), "hoare_triple_contract_verifier"),
        (("leads to", "temporal liveness", "livelock"), "temporal_liveness_leads_to"),
        (("raft consensus", "raft election", "leader election"), "raft_consensus_election_sim"),
        (("raft partition", "split brain heal", "partition heal"), "raft_partition_self_healer"),
        (("paxos", "synod consensus", "lamport paxos"), "paxos_synod_decree_verifier"),
        (("phi accrual", "failure detector", "byzantine heal"), "phi_accrual_cluster_healer"),
        (("cpu cache", "cache hierarchy", "cache topology"), "cpu_cache_hierarchy_probe"),
        (("false sharing", "cache line straddling", "alignas 64"), "cache_line_false_sharing_audit"),
        (("set associative", "lru cache sim", "cache simulator"), "set_associative_cache_simulator"),
        (("roofline", "arithmetic intensity", "ridge point"), "roofline_arithmetic_intensity"),
        (("loop tiling", "cache blocking", "tile optimizer"), "loop_tiling_cache_optimizer"),
        (("distributed contract safety", "tla raft gate"), "distributed_contract_safety_gate"),
        (("omega 150", "supreme frontier sweep"), "omega_150_supreme_frontier_sweep"),
    ]
    for keys, r_name in keyword_map:
        if any(k in low for k in keys):
            return r_name
    return match_v70_60_rail(low)


def execute_matrix_69_rail(
    rail_name: str,
    workspace: Path,
    args: Dict[str, Any],
    execute_rail_fn: Optional[Callable[..., Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Dispatch any of Rails 32-160 deterministically in 0 LLM tokens."""
    ws = Path(workspace).resolve()
    target = str(args.get("target") or args.get("file_path") or ".")

    for fn in (
        execute_code_git_data,
        execute_web_win_sec,
        execute_apex_v62,
        execute_tla_raft_cpu,
        execute_nov26_v62,
    ):
        res = fn(rail_name, ws, target, args, execute_rail_fn)
        if res is not None:
            return res

    if rail_name in V70_60_SPECS:
        return execute_v70_60_rail(rail_name, ws, args, execute_rail_fn=execute_rail_fn)

    return {"ok": False, "rail": rail_name, "error": f"Unhandled matrix rail: {rail_name}"}
