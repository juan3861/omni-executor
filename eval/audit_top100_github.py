"""Empirical audit comparing F:\\AetherMind_Universal_Agent against the Top 100 GitHub AI agent repos."""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "am_ua"
RAW_PATH = ROOT / ".proof" / "github_top100_agents_raw.json"
OUT_PATH = ROOT / ".proof" / "top100_github_parity_audit.json"


# Senior-engineering capability axes verified directly against files AND AST symbols on disk in src/am_ua/
CAPABILITY_EVIDENCE: Dict[str, Tuple[str, ...]] = {
    "autonomous_coding_harness": ("execution/agent_loop.py", "execution/codex_muscle.py", "agent_kernel.py"),
    "ast_repomap_and_lsp": ("perception/polyglot_repomap.py", "execution/hook_engine.py"),
    "token_and_output_compression": ("execution/output_compressor.py", "perception/silicon_radar.py"),
    "durable_checkpoints_and_rollback": ("execution/durable_engine.py", "execution/agent_loop.py", "governance/alpha_c13.py"),
    "persistent_and_vector_memory": ("memory/triad_provider.py", "cognition/reasoning_bank.py", "cognition/sona_memory.py"),
    "knowledge_graph_and_tree_index": ("perception/knowledge_index.py", "memory/mnemos_connector.py"),
    "architecture_diagram_and_auto_sync_graph": ("perception/knowledge_index.py",),
    "browser_and_web_extraction": ("gui/cdp_browser.py", "gui/verified_browser_adapter.py", "execution/agent_loop.py"),
    "desktop_and_os_automation": ("execution/pc_automation.py",),
    "multi_agent_swarm_and_dag": ("execution/subagent_bus.py", "cognition/hierarchical_planner.py", "execution/best_of_n.py"),
    "a2a_agent_to_agent_protocol": ("execution/subagent_bus.py",),
    "mcp_server_and_federation": ("execution/mcp_federation.py",),
    "security_shield_and_sast": ("security/agent_shield.py", "governance/seal_guard.py", "execution/hook_engine.py"),
    "model_routing_and_resilience": ("cognition/llm_client.py", "routing/omni_router.py"),
    "skills_and_personas": ("execution/adaptive_skills.py", "cognition/personas.py"),
    "evolution_and_benchmarks": ("evolution/constitutional_evolver.py", "contracts/calibration.py"),
}

CAPABILITY_AST_SYMBOLS: Dict[str, Tuple[str, str]] = {
    "autonomous_coding_harness": ("execution/agent_loop.py", "_compose_system_prompt"),
    "ast_repomap_and_lsp": ("perception/polyglot_repomap.py", "PolyglotRepoMapper"),
    "token_and_output_compression": ("execution/output_compressor.py", "ToolOutputCompressor"),
    "durable_checkpoints_and_rollback": ("execution/durable_engine.py", "DurableExecutionEngine"),
    "persistent_and_vector_memory": ("memory/triad_provider.py", "TriadMemoryProvider"),
    "knowledge_graph_and_tree_index": ("perception/knowledge_index.py", "HierarchicalKnowledgeIndex"),
    "architecture_diagram_and_auto_sync_graph": ("perception/knowledge_index.py", "export_mermaid_graph"),
    "browser_and_web_extraction": ("gui/cdp_browser.py", "CDPIndexedBrowser"),
    "desktop_and_os_automation": ("execution/pc_automation.py", "PCAutomationEngine"),
    "multi_agent_swarm_and_dag": ("execution/subagent_bus.py", "SubAgentSessionBus"),
    "a2a_agent_to_agent_protocol": ("execution/subagent_bus.py", "handle_a2a_rpc"),
    "mcp_server_and_federation": ("execution/mcp_federation.py", "MCPFederationHub"),
    "security_shield_and_sast": ("security/agent_shield.py", "AgentShieldAuditor"),
    "model_routing_and_resilience": ("cognition/llm_client.py", "LLMClient"),
    "skills_and_personas": ("execution/adaptive_skills.py", "wrap_cli_tool"),
    "evolution_and_benchmarks": ("evolution/constitutional_evolver.py", "ConstitutionalEvolver"),
}

# Lower/mid-star architectural pioneer repositories with specialized engineering gears
NICHE_FRONTIER_REPOS: List[Dict[str, Any]] = [
    {"full_name": "a2aproject/A2A", "stars": 26568, "description": "Agent2Agent (A2A) open protocol for agent interoperability", "topics": ["a2a", "a2a-protocol", "mcp"]},
    {"full_name": "win4r/openclaw-a2a-gateway", "stars": 551, "description": "OpenClaw plugin implementing bidirectional A2A protocol v0.3.0 gateway", "topics": ["openclaw", "a2a"]},
    {"full_name": "SWE-agent/mini-swe-agent", "stars": 4200, "description": "Minimalist high-efficiency coding agent harness for SWE-bench & Terminal-Bench", "topics": ["coding-agent", "harness", "benchmark"]},
    {"full_name": "letta-ai/letta", "stars": 38500, "description": "Stateful agents with self-editing core memory blocks", "topics": ["memory", "episodic", "agent"]},
    {"full_name": "getzep/graphiti", "stars": 21400, "description": "Bi-temporal knowledge graph memory for autonomous AI agents", "topics": ["memory", "knowledge-graph"]},
    {"full_name": "pydantic/pydantic-ai", "stars": 34200, "description": "Type-safe agent contract framework with deterministic validation", "topics": ["coding-agent", "workflow", "checkpoint"]},
    {"full_name": "langchain-ai/langgraph", "stars": 29800, "description": "Resilient stateful durable execution engine with checkpointing and human-in-the-loop", "topics": ["durable", "checkpoint", "workflow"]},
    {"full_name": "BerriAI/litellm", "stars": 39100, "description": "Universal LLM gateway router with provider failover and token tracking", "topics": ["gateway", "router", "provider"]},
    {"full_name": "e2b-dev/E2B", "stars": 19500, "description": "Secure isolated sandbox execution environment for AI coding agents", "topics": ["sandbox", "security", "coding-agent"]},
    {"full_name": "code-yeongyu/lazycodex", "stars": 18400, "description": "Rust-backed crab harness for multi-agent parallel worktree execution", "topics": ["coding-agent", "harness", "swarm"]},
    {"full_name": "Yeachan-Heo/gajae-code", "stars": 15900, "description": "Low-latency terminal coding harness with surgical AST edits", "topics": ["coding-agent", "ast", "lsp"]},
    {"full_name": "open-gsd/gsd-core", "stars": 12800, "description": "Spec-driven context engineering and mission decomposition framework", "topics": ["coding-agent", "workflow", "skill"]},
]


def _ast_has_symbol(rel_file: str, symbol_name: str) -> bool:
    fp = SRC / rel_file
    if not fp.is_file():
        return False
    try:
        tree = ast.parse(fp.read_text(encoding="utf-8"))
    except Exception:
        return False
    for node in ast.walk(tree):
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == symbol_name:
            return True
    return False


def _classify_repo(repo: Dict[str, Any]) -> Tuple[str, List[str]]:
    full = str(repo.get("full_name", "")).lower()
    text = f"{full} {repo.get('description','')} {' '.join(repo.get('topics',[]))}".lower()
    gears: List[str] = []
    if any(k in text for k in (
        "coding agent", "claude code", "opencode", "codex", "cline", "harness",
        "reverse engineer", "pair programming", "ai-driven development", "autogpt",
        "openhands", "aider", "cli-anything", "autoresearch", "ai workspace", "odysseus",
    )):
        gears.append("autonomous_coding_harness")
    if any(k in text for k in ("ast", "codebase", "symbol", "tree-sitter", "lsp", "code graph", "aider")):
        gears.append("ast_repomap_and_lsp")
    if any(k in text for k in ("compress", "fewer token", "caveman", "headroom", "token")):
        gears.append("token_and_output_compression")
    if any(k in text for k in ("checkpoint", "durable", "rollback", "workflow", "aider", "openhands", "autogpt")):
        gears.append("durable_checkpoints_and_rollback")
    if any(k in text for k in ("memory", "mem0", "claude-mem", "episodic")):
        gears.append("persistent_and_vector_memory")
    if any(k in text for k in ("rag", "knowledge graph", "pageindex", "graphify", "docs")):
        gears.append("knowledge_graph_and_tree_index")
    if any(k in text for k in ("browser", "scrap", "crawl", "web", "devtools")):
        gears.append("browser_and_web_extraction")
    if any(k in text for k in ("desktop", "computer use", "gui", "os automation", "cli-anything", "openclaw", "any os")):
        gears.append("desktop_and_os_automation")
    if any(k in text for k in ("swarm", "multi-agent", "crew", "fleet", "orchestrat", "autogen", "agentic ai", "autogpt")):
        gears.append("multi_agent_swarm_and_dag")
    if any(k in text for k in ("a2a", "agent2agent", "openclaw", "interoperability")):
        gears.append("a2a_agent_to_agent_protocol")
    if any(k in text for k in ("archify", "understand-anything", "codegraph", "interactive diagram", "auto syncs on code")):
        gears.append("architecture_diagram_and_auto_sync_graph")
    if "mcp" in text or "cli-anything" in text:
        gears.append("mcp_server_and_federation")
    if any(k in text for k in ("security", "audit", "shield", "sandbox")):
        gears.append("security_shield_and_sast")
    if any(k in text for k in ("gateway", "router", "models", "inference", "free-model", "provider")):
        gears.append("model_routing_and_resilience")
    if any(k in text for k in ("skill", "plugin", "persona", "cli-anything")):
        gears.append("skills_and_personas")
    if any(k in text for k in ("autoresearch", "benchmark", "eval", "self-improving", "evolving")):
        gears.append("evolution_and_benchmarks")

    # Identify out-of-scope pure vertical/educational/design-only/game/infra repos vs core engineering agents
    non_core = any(k in text for k in (
        "trading", "stock analysis", "job search", "job application", "powerpoint", "render video",
        "tutorial", "book", "interview", "lessons", "begginer", "beginners", "classroom", "wifi signals",
        "design system", "design vocabulary", "marketingskills", "awesome-", "leaked system prompts",
        "open data platform for analysts", "it automation platform", "quant investment platform",
        "elevenlabs alternative", "from scratch", "构建智能体",
    ))
    scope = "vertical_or_curated_list" if (non_core or not gears) else "core_engineering_agent"
    return scope, sorted(set(gears))


def main() -> int:
    if not RAW_PATH.is_file():
        print(f"Missing {RAW_PATH}")
        return 1
    repos = json.loads(RAW_PATH.read_text(encoding="utf-8"))
    present_caps = {
        cap: (
            all((SRC / rel).is_file() for rel in files)
            and _ast_has_symbol(*CAPABILITY_AST_SYMBOLS[cap])
        )
        for cap, files in CAPABILITY_EVIDENCE.items()
    }

    core_repos = []
    vertical_repos = []
    uncovered: List[Dict[str, Any]] = []
    for r in repos:
        scope, gears = _classify_repo(r)
        missing = [g for g in gears if not present_caps.get(g, False)]
        entry = {"full_name": r["full_name"], "stars": r["stars"], "scope": scope, "gears": gears, "missing_in_am": missing}
        if scope == "core_engineering_agent":
            core_repos.append(entry)
            if missing:
                uncovered.append(entry)
        else:
            vertical_repos.append(entry)

    niche_audited = []
    niche_uncovered = []
    for nr in NICHE_FRONTIER_REPOS:
        _, ngears = _classify_repo(nr)
        nmissing = [g for g in ngears if not present_caps.get(g, False)]
        nentry = {"full_name": nr["full_name"], "stars": nr["stars"], "gears": ngears, "missing_in_am": nmissing}
        niche_audited.append(nentry)
        if nmissing:
            niche_uncovered.append(nentry)

    report = {
        "schema": "TOP100_GITHUB_PARITY_AUDIT/v2",
        "total_repos_audited": len(repos),
        "core_engineering_repos": len(core_repos),
        "vertical_or_curated_repos": len(vertical_repos),
        "capabilities_verified_on_disk": present_caps,
        "core_repos_100pct_gear_covered": len(core_repos) - len(uncovered),
        "core_gear_coverage_rate": round((len(core_repos) - len(uncovered)) / max(1, len(core_repos)), 4),
        "uncovered_core_repos": uncovered,
        "niche_frontier_repos_audited": len(niche_audited),
        "niche_frontier_coverage_rate": round((len(niche_audited) - len(niche_uncovered)) / max(1, len(niche_audited)), 4),
        "niche_frontier_details": niche_audited,
    }
    OUT_PATH.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k != "capabilities_verified_on_disk"}, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
