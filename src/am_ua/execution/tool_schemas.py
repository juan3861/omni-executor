"""Strict Native JSON Tool Schemas & Dynamic MCP Tool Mounting (v8.0).

Provides:
  - `TOOL_JSON_SCHEMAS`: Canonical OpenAI/Anthropic/Gemini-compatible JSON Schemas
    aligned 1:1 with `WorkspaceTools` and `AgentLoop` control tools.
  - `build_native_tool_schemas(...)`: Role-scoped and objective-ranked tool surface
    generator so native tool-calling stays minimal, cache-stable, and role-safe.
  - `discover_mcp_tool_schemas(...)`: Dynamically discovers external MCP server tools
    from `MCPFederationHub` and mounts them as first-class native `mcp__<srv>__<tool>`
    functions with an exact routing table.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from am_ua.execution.loop_prompts_and_scopes import ROLE_TOOL_SCOPES, rank_tools_for_objective
from am_ua.execution.mcp_federation import MCPFederationHub


def _fn(
    name: str,
    description: str,
    properties: Dict[str, Any],
    required: Sequence[str] = (),
    *,
    additional_properties: bool = False,
) -> Dict[str, Any]:
    schema: Dict[str, Any] = {
        "type": "object",
        "properties": properties,
        "additionalProperties": additional_properties,
    }
    if required:
        schema["required"] = list(required)
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": schema,
        },
    }


TOOL_JSON_SCHEMAS: Dict[str, Dict[str, Any]] = {
    "list_dir": _fn(
        "list_dir",
        "List files and subdirectories inside a workspace directory.",
        {
            "path": {"type": "string", "description": "Relative directory path (default '.')."},
            "depth": {"type": "integer", "description": "Max traversal depth (1-4, default 2)."},
        },
    ),
    "read_file": _fn(
        "read_file",
        "Read a text file in the workspace with 1-based line numbers.",
        {
            "file": {"type": "string", "description": "Relative file path to read."},
            "start_line": {"type": "integer", "description": "1-based start line (default 1)."},
            "end_line": {"type": "integer", "description": "1-based inclusive end line."},
        },
        required=("file",),
    ),
    "search": _fn(
        "search",
        "Regex search across text files in the workspace.",
        {
            "pattern": {"type": "string", "description": "Regular expression pattern to search for."},
            "path": {"type": "string", "description": "Optional relative directory/file scope."},
        },
        required=("pattern",),
    ),
    "write_file": _fn(
        "write_file",
        "Create or overwrite a file in the workspace with exact content.",
        {
            "path": {"type": "string", "description": "Relative file path to write."},
            "content": {"type": "string", "description": "Complete file contents."},
        },
        required=("path", "content"),
    ),
    "replace_in_file": _fn(
        "replace_in_file",
        "Replace an existing text block or list of hunks in a workspace file (with 4-level fuzzy indentation fallback).",
        {
            "path": {"type": "string", "description": "Relative file path to edit."},
            "old": {"type": "string", "description": "Existing text block to match."},
            "new": {"type": "string", "description": "Replacement text block."},
            "hunks": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {"old": {"type": "string"}, "new": {"type": "string"}},
                },
            },
        },
        required=("path",),
    ),
    "run": _fn(
        "run",
        "Execute a shell command inside the workspace under constitutional and semantic policy guards.",
        {
            "command": {"type": "string", "description": "Shell command to run."},
            "timeout_s": {"type": "number", "description": "Timeout in seconds (default 120)."},
            "sandbox": {"type": "string", "enum": ["", "hermetic", "docker"]},
        },
        required=("command",),
    ),
    "task_tracker": _fn(
        "task_tracker",
        "Inspect or update structured mission subtasks (`view` or `plan`).",
        {
            "command": {"type": "string", "enum": ["view", "plan"]},
            "task_list": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "status": {"type": "string"},
                        "notes": {"type": "string"},
                    },
                },
            },
        },
    ),
    "repo_map": _fn(
        "repo_map",
        "Build a PageRank-ranked polyglot repository symbol map.",
        {"max_chars": {"type": "integer", "description": "Character budget (default 3000)."}},
    ),
    "cpg_impact": _fn(
        "cpg_impact",
        "Query Code Property Graph (AST/CFG/Dataflow taint slicing), SCIP index, goto_definition, find_references, and refactoring blast radius.",
        {
            "action": {"type": "string", "enum": ["summary", "goto_definition", "find_references", "impact", "taint", "scip_build"]},
            "symbol": {"type": "string", "description": "Symbol name to query."},
            "direction": {"type": "string", "enum": ["forward", "backward"]},
            "out_path": {"type": "string", "description": "Optional SCIP JSON output path inside workspace."},
        },
        required=("action",),
    ),
    "ast_grep_search": _fn(
        "ast_grep_search",
        "Run structural AST pattern search across code files (`ast-grep` with Python fallback).",
        {
            "pattern": {"type": "string", "description": "AST pattern with optional $VAR metavariables."},
            "lang": {"type": "string", "description": "Language name (default 'python')."},
            "path": {"type": "string", "description": "Optional relative directory/file scope."},
            "max_hits": {"type": "integer"},
        },
        required=("pattern",),
    ),
    "lsp_query": _fn(
        "lsp_query",
        "Run LSP diagnostics (including type/lint checks), goto_definition, find_references, or hover signature.",
        {
            "action": {"type": "string", "enum": ["diagnostics", "definition", "references", "hover"]},
            "file": {"type": "string", "description": "Target relative file path (for diagnostics/hover)."},
            "symbol": {"type": "string", "description": "Target symbol name (for definition/references)."},
            "line": {"type": "integer", "description": "1-based line number (for hover)."},
            "path": {"type": "string", "description": "Optional relative scope directory."},
            "language": {"type": "string", "description": "Language (default 'python')."},
            "include_typecheck": {"type": "boolean"},
        },
        required=("action",),
    ),
    "knowledge_query": _fn(
        "knowledge_query",
        "Query the workspace SQLite FTS5 / knowledge index.",
        {
            "question": {"type": "string", "description": "Search query string."},
            "top_k": {"type": "integer", "description": "Max hits to return (default 5)."},
        },
        required=("question",),
    ),
    "web_fetch": _fn(
        "web_fetch",
        "Fetch a public HTTP/HTTPS URL safely (with SSRF protection) and extract clean Markdown text.",
        {
            "url": {"type": "string", "description": "Public HTTP/HTTPS URL."},
            "max_chars": {"type": "integer", "description": "Max characters to return."},
        },
        required=("url",),
    ),
    "spill_query": _fn(
        "spill_query",
        "Query or slice a previously spilled large tool observation file on disk.",
        {
            "spill_path": {"type": "string", "description": "Path to spilled observation file."},
            "pattern": {"type": "string", "description": "Optional regex pattern to filter lines."},
            "start_line": {"type": "integer"},
            "max_lines": {"type": "integer"},
        },
        required=("spill_path",),
    ),
    "code_sandbox": _fn(
        "code_sandbox",
        "Run pure, isolated Python snippet inside an AST-validated sandbox for math/JSON checks.",
        {"code": {"type": "string", "description": "Python code snippet to evaluate."}},
        required=("code",),
    ),
    "deterministic_preflight": _fn(
        "deterministic_preflight",
        "Single-shot deterministic bundle: AST syntax sweep + AgentShield SAST + PageRank RepoMap.",
        {"max_chars": {"type": "integer", "description": "Character budget (default 3500)."}},
    ),
    "deterministic_exec": _fn(
        "deterministic_exec",
        "Execute one of the 220 deterministic zero-token rails directly on the workspace.",
        {
            "rail": {"type": "string", "description": "Exact deterministic rail name."},
            "action": {"type": "string", "description": "Alias for rail name."},
            "params": {"type": "object", "description": "Optional rail parameters."},
        },
        additional_properties=True,
    ),
    "run_playbook": _fn(
        "run_playbook",
        "List or execute a pre-fixed deterministic parametric playbook across Code, Windows, or Browser with runtime variables.",
        {
            "action": {"type": "string", "description": "Set 'list' to list playbooks or omit/'execute' to run."},
            "playbook": {"type": "string", "description": "Registered playbook name (e.g. 'code_patch_and_verify', 'win_ui_sequence', 'web_navigate_fill_extract')."},
            "domain": {"type": "string", "description": "Optional filter ('code'|'windows'|'browser') when action='list'."},
            "variables": {"type": "object", "description": "Runtime variable bindings for {{var}} placeholders."},
        },
    ),
    "checkpoint": _fn(
        "checkpoint",
        "Create a workspace state snapshot checkpoint before risky edits.",
        {"name": {"type": "string", "description": "Checkpoint name (default 'default')."}},
    ),
    "restore_checkpoint": _fn(
        "restore_checkpoint",
        "Restore workspace files to a previously created checkpoint.",
        {"name": {"type": "string", "description": "Checkpoint name to restore."}},
        required=("name",),
    ),
    "browser_observe": _fn(
        "browser_observe",
        "Open or inspect a web page in the CDP browser and return indexed DOM elements + screenshot.",
        {
            "url": {"type": "string", "description": "Optional URL to navigate to."},
            "headless": {"type": "boolean"},
            "wait_ms": {"type": "integer"},
            "force_reload": {"type": "boolean"},
        },
    ),
    "browser_act": _fn(
        "browser_act",
        "Perform a browser action (click, fill, type, press, scroll, navigate) on an indexed element.",
        {
            "action": {"type": "string", "description": "Action kind (click, fill, type, press, scroll, navigate)."},
            "idx": {"type": "integer", "description": "Indexed DOM element number."},
            "target": {"type": "string", "description": "Fallback element label/selector."},
            "text": {"type": "string", "description": "Text to enter or key to press."},
            "url": {"type": "string", "description": "URL for navigate action."},
            "headless": {"type": "boolean"},
        },
        required=("action",),
    ),
    "browser_extract": _fn(
        "browser_extract",
        "Extract structured text/tables/links from the active browser page.",
        {
            "selector": {"type": "string", "description": "Optional CSS selector (default 'body')."},
            "headless": {"type": "boolean"},
        },
    ),
    "pc_observe": _fn(
        "pc_observe",
        "Observe the desktop via screenshot, OCR, and UIA accessibility tree.",
        {
            "hwnd": {"type": "integer"},
            "window_title": {"type": "string"},
            "include_ocr": {"type": "boolean"},
            "max_elements": {"type": "integer"},
        },
    ),
    "pc_ground_vlm": _fn(
        "pc_ground_vlm",
        "Ground a visual target on the desktop using multimodal Set-of-Mark vision.",
        {
            "target": {"type": "string", "description": "Visual element description to locate."},
            "window_title": {"type": "string"},
            "refresh": {"type": "boolean"},
        },
        required=("target",),
    ),
    "pc_act": _fn(
        "pc_act",
        "Execute a verified desktop input action (click, type, hotkey, scroll).",
        {
            "action_type": {"type": "string", "description": "Action kind (click, double_click, type, hotkey, scroll)."},
            "tag_id": {"type": "integer"},
            "target": {"type": "string"},
            "x": {"type": "integer"},
            "y": {"type": "integer"},
            "text": {"type": "string"},
            "keys": {"type": "array", "items": {"type": "string"}},
            "scroll_clicks": {"type": "integer"},
            "button": {"type": "string"},
            "dry_run": {"type": "boolean"},
        },
        required=("action_type",),
        additional_properties=True,
    ),
    "pc_window": _fn(
        "pc_window",
        "List, inspect, launch, focus, resize, or close OS windows.",
        {
            "action": {"type": "string", "enum": ["list", "active", "find", "launch", "cleanup", "focus", "minimize", "maximize", "close"]},
            "locator": {"type": "string"},
            "title": {"type": "string"},
            "app_cmd": {"type": "string"},
        },
        required=("action",),
        additional_properties=True,
    ),
    "pc_clipboard": _fn(
        "pc_clipboard",
        "Get or set OS clipboard text.",
        {
            "action": {"type": "string", "enum": ["get", "set"]},
            "text": {"type": "string"},
        },
        required=("action",),
    ),
    "pc_process": _fn(
        "pc_process",
        "Inspect running OS processes or find the process owning a TCP port.",
        {
            "action": {"type": "string", "enum": ["list", "port_owner"]},
            "filter": {"type": "string"},
            "port": {"type": "integer"},
        },
    ),
    "skill_forge": _fn(
        "skill_forge",
        "Create and validate a reusable Python skill in the AdaptiveSkillForge.",
        {
            "name": {"type": "string"},
            "description": {"type": "string"},
            "code": {"type": "string"},
            "tags": {"type": "array", "items": {"type": "string"}},
            "test_kwargs": {"type": "object"},
        },
        required=("name", "code"),
    ),
    "skill_run": _fn(
        "skill_run",
        "List, search, or execute a registered AdaptiveSkillForge skill.",
        {
            "action": {"type": "string", "enum": ["run", "list", "search"]},
            "name": {"type": "string"},
            "query": {"type": "string"},
            "kwargs": {"type": "object"},
        },
    ),
    "spawn_agent": _fn(
        "spawn_agent",
        "Spawn a specialized subagent session on the SubAgentSessionBus.",
        {
            "role": {"type": "string"},
            "objective": {"type": "string"},
            "wait": {"type": "boolean"},
        },
        required=("objective",),
    ),
    "spawn_team": _fn(
        "spawn_team",
        "Orchestrate a multi-wave hierarchical team of specialist subagents.",
        {
            "objective": {"type": "string"},
            "workspace_file_count": {"type": "integer"},
        },
        required=("objective",),
    ),
    "send_agent": _fn(
        "send_agent",
        "Send a message to an active subagent session.",
        {
            "recipient_id": {"type": "string"},
            "content": {"type": "string"},
            "sender_id": {"type": "string"},
        },
        required=("recipient_id", "content"),
    ),
    "await_agents": _fn(
        "await_agents",
        "Await results from spawned subagent sessions.",
        {
            "session_ids": {"type": "array", "items": {"type": "string"}},
            "timeout_s": {"type": "number"},
        },
    ),
    "mcp_call": _fn(
        "mcp_call",
        "List or invoke tools on a registered external MCP server.",
        {
            "action": {"type": "string", "enum": ["call", "list"]},
            "server": {"type": "string", "description": "Registered MCP server name."},
            "tool": {"type": "string", "description": "Tool name when action='call'."},
            "arguments": {"type": "object", "description": "Tool input arguments."},
        },
        required=("server",),
    ),
    "handoff_agent": _fn(
        "handoff_agent",
        "Transfer active control to another specialist persona role.",
        {
            "target_role": {"type": "string"},
            "reason": {"type": "string"},
            "context_note": {"type": "string"},
        },
        required=("target_role",),
    ),
    "request_human": _fn(
        "request_human",
        "Pause mission execution and request human intervention (Take the Wheel).",
        {
            "reason": {"type": "string"},
            "instructions": {"type": "string"},
        },
        required=("reason",),
    ),
    "finish": _fn(
        "finish",
        "Complete the mission after verification passes, reporting summary, confidence, and optional structured output.",
        {
            "summary": {"type": "string", "description": "Concise verified summary of changes and proof."},
            "confidence": {"type": "number", "description": "Calibrated probability 0.0-1.0."},
            "output": {"type": "object", "description": "Optional structured output matching output_schema."},
        },
        required=("summary",),
    ),
}


_SAFE_NAME_RE = re.compile(r"[^a-zA-Z0-9_-]+")


def _sanitize_tool_slug(raw: str, max_len: int = 24) -> str:
    cleaned = _SAFE_NAME_RE.sub("_", (raw or "").strip()).strip("_")
    return (cleaned or "tool")[:max_len]


def discover_mcp_tool_schemas(
    mcp_hub: Optional[MCPFederationHub],
    *,
    timeout_s: float = 5.0,
) -> Tuple[List[Dict[str, Any]], Dict[str, Tuple[str, str]]]:
    """Discover tools across all configured MCP servers and convert them into native function schemas.

    Returns:
      - `schemas`: List of OpenAI/Anthropic-compatible function tool definitions named `mcp__<srv>__<tool>`.
      - `routing`: Mapping `mounted_name -> (server_name, original_tool_name)`.
    """
    if mcp_hub is None:
        return [], {}
    servers = mcp_hub.list_servers()
    if not servers:
        return [], {}

    schemas: List[Dict[str, Any]] = []
    routing: Dict[str, Tuple[str, str]] = {}
    used_names: set[str] = set(TOOL_JSON_SCHEMAS.keys())

    for server_name in servers:
        res = mcp_hub.list_server_tools(server_name, timeout_s=timeout_s)
        if not res.get("ok"):
            continue
        srv_slug = _sanitize_tool_slug(server_name, max_len=20)
        for item in res.get("tools") or []:
            if not isinstance(item, dict):
                continue
            orig_name = str(item.get("name") or "").strip()
            if not orig_name:
                continue
            tool_slug = _sanitize_tool_slug(orig_name, max_len=32)
            mounted = f"mcp__{srv_slug}__{tool_slug}"[:64]
            idx = 2
            while mounted in used_names:
                suffix = f"_{idx}"
                mounted = f"{mounted[: 64 - len(suffix)]}{suffix}"
                idx += 1
            used_names.add(mounted)
            routing[mounted] = (server_name, orig_name)

            input_schema = item.get("inputSchema")
            if not isinstance(input_schema, dict) or input_schema.get("type") != "object":
                input_schema = {"type": "object", "properties": {}}
            desc = str(item.get("description") or f"MCP tool '{orig_name}' on server '{server_name}'.").strip()
            schemas.append(
                {
                    "type": "function",
                    "function": {
                        "name": mounted,
                        "description": f"[MCP:{server_name}] {desc}"[:512],
                        "parameters": input_schema,
                    },
                }
            )
    return schemas, routing


def build_native_tool_schemas(
    *,
    objective: str = "",
    role: str = "general_engineer",
    execution_mode: str = "act",
    allowed_tools: Optional[Iterable[str]] = None,
    mcp_schemas: Optional[Sequence[Dict[str, Any]]] = None,
    max_builtin_tools: int = 22,
) -> List[Dict[str, Any]]:
    """Build a minimal, role-scoped, cache-stable list of native tool schemas for one mission."""
    if allowed_tools is not None:
        pool = [t for t in allowed_tools if t in TOOL_JSON_SCHEMAS]
    else:
        ranked = rank_tools_for_objective(objective, role=role)
        pool = list(ranked.get("selected_tools") or [])
        role_scope = ROLE_TOOL_SCOPES.get(role)
        # Ensure core workspace tools remain available whenever permitted by role
        for core_t in ("list_dir", "read_file", "search", "replace_in_file", "write_file", "run", "deterministic_exec", "run_playbook"):
            if core_t not in pool and (role_scope is None or core_t in role_scope):
                pool.append(core_t)

    if execution_mode.strip().lower() == "plan":
        mutating = {
            "write_file",
            "replace_in_file",
            "run",
            "pc_act",
            "pc_window",
            "browser_act",
            "skill_forge",
            "skill_run",
            "restore_checkpoint",
        }
        pool = [t for t in pool if t not in mutating]

    # Deduplicate preserving stable order, always include finish & handoff_agent
    selected: List[str] = []
    seen: set[str] = set()
    for t in pool:
        if t in TOOL_JSON_SCHEMAS and t not in seen:
            selected.append(t)
            seen.add(t)
        if len(selected) >= max_builtin_tools:
            break
    for ctrl in ("finish", "handoff_agent"):
        if ctrl in TOOL_JSON_SCHEMAS and ctrl not in seen:
            selected.append(ctrl)
            seen.add(ctrl)

    out = [TOOL_JSON_SCHEMAS[t] for t in selected]
    if mcp_schemas:
        out.extend(mcp_schemas)
    return out
