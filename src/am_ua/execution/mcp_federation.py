"""MCP Federation Client Hub & Sovereign Stdio Server (F8 — Goose / OpenHands / Claude Code MCP).

Unites:
1. `MCPFederationHub`: Connects to external Model Context Protocol (MCP) JSON-RPC 2.0 stdio servers
   via `MCPStdioClient` (`am_ua.perception.polyglot_repomap`), discovers their tools (`tools/list`),
   and dispatches governed `tools/call` invocations.
2. `AetherMindMCPServer`: Exposes AetherMind Universal Agent's sovereign organs (`am_pc_probe`,
   `am_pc_windows`, `am_pc_observe`, `am_skill_list`, `am_skill_forge`, `am_skill_run`) as a
   standards-compliant MCP JSON-RPC 2.0 stdio server (`aether-ua.cmd mcp-serve`).
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

from am_ua.execution.adaptive_skills import AdaptiveSkillForge
from am_ua.execution.pc_automation import PCAutomationEngine
from am_ua.perception.polyglot_repomap import MCPStdioClient


class MCPFederationHub:
    """Manages connections and tool calls across external MCP stdio servers."""

    def __init__(self, config_path: Optional[Path | str] = None) -> None:
        self.config_path = Path(config_path).resolve() if config_path else None
        self._servers: Dict[str, Dict[str, Any]] = {}
        if self.config_path and self.config_path.is_file():
            self._load_config(self.config_path)

    def _load_config(self, path: Path) -> None:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            for name, spec in data.get("mcpServers", {}).items():
                cmd = [spec["command"]] + list(spec.get("args", []))
                self.register_server(name, cmd, env=spec.get("env"))
        except Exception:
            pass

    def register_server(
        self,
        name: str,
        command: List[str],
        *,
        cwd: Optional[Path | str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> None:
        self._servers[name] = {
            "command": list(command),
            "cwd": str(cwd) if cwd else None,
            "env": dict(env) if env else None,
        }

    def list_servers(self) -> List[str]:
        return sorted(self._servers.keys())

    def list_server_tools(self, server_name: str, *, timeout_s: float = 15.0) -> Dict[str, Any]:
        if server_name not in self._servers:
            return {"ok": False, "error": f"Unknown MCP server: {server_name!r}"}
        spec = self._servers[server_name]
        client = MCPStdioClient(
            spec["command"],
            cwd=spec["cwd"],
            env=spec["env"],
            startup_timeout_s=timeout_s,
        )
        try:
            client.start()
            tools = client.list_tools(timeout_s=timeout_s)
            return {"ok": True, "server": server_name, "tools": tools}
        except Exception as exc:
            return {"ok": False, "server": server_name, "error": str(exc)}
        finally:
            client.close()

    def call_server_tool(
        self,
        server_name: str,
        tool_name: str,
        arguments: Optional[Dict[str, Any]] = None,
        *,
        timeout_s: float = 30.0,
    ) -> Dict[str, Any]:
        if server_name not in self._servers:
            return {"ok": False, "error": f"Unknown MCP server: {server_name!r}"}
        spec = self._servers[server_name]
        client = MCPStdioClient(
            spec["command"],
            cwd=spec["cwd"],
            env=spec["env"],
            startup_timeout_s=timeout_s,
        )
        try:
            client.start()
            res = client.call_tool(tool_name, arguments or {}, timeout_s=timeout_s)
            return {"ok": True, "server": server_name, "tool": tool_name, "result": res}
        except Exception as exc:
            return {"ok": False, "server": server_name, "tool": tool_name, "error": str(exc)}
        finally:
            client.close()


class AetherMindMCPServer:
    """Standards-compliant JSON-RPC 2.0 MCP Server exposing AetherMind organs over stdio."""

    def __init__(
        self,
        *,
        pc_engine: Optional[PCAutomationEngine] = None,
        skill_forge: Optional[AdaptiveSkillForge] = None,
        security_auditor: Any = None,
    ) -> None:
        self.pc_engine = pc_engine or PCAutomationEngine()
        self.skill_forge = skill_forge or AdaptiveSkillForge()
        self.security_auditor = security_auditor
        self._tools: Dict[str, Tuple[Dict[str, Any], Callable[[Dict[str, Any]], Any]]] = {}
        self._register_default_tools()

    def _register_default_tools(self) -> None:
        self.register_tool(
            name="am_pc_probe",
            description="Probe desktop resolution, active window, OCR readiness, and protected safety zones.",
            input_schema={"type": "object", "properties": {}},
            handler=lambda _: self.pc_engine.probe_capabilities(),
        )
        if self.security_auditor is not None:
            self.register_tool(
                name="am_security_shield",
                description="Run AgentShield static security audit over a directory for secrets, MCP risks, and hook injection.",
                input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
                handler=lambda a: self.security_auditor.scan_directory(a.get("path", ".")).to_dict(),
            )
        self.register_tool(
            name="am_pc_windows",
            description="List visible Windows top-level windows with HWND, PID, and executable.",
            input_schema={
                "type": "object",
                "properties": {"title_filter": {"type": "string"}},
            },
            handler=lambda args: {
                "windows": self.pc_engine.window_organ.list_windows(
                    title_filter=str(args.get("title_filter", "")), limit=40
                )
            },
        )
        self.register_tool(
            name="am_pc_observe",
            description="Capture Set-of-Mark desktop observation (UIA + OCR + 2048-bit visual dHash).",
            input_schema={
                "type": "object",
                "properties": {
                    "window_title": {"type": "string"},
                    "include_ocr": {"type": "boolean"},
                },
            },
            handler=lambda args: self.pc_engine.observe_desktop(
                window_title=args.get("window_title"),
                include_ocr=bool(args.get("include_ocr", True)),
            ),
        )
        self.register_tool(
            name="am_skill_list",
            description="List all forged and SHA-256 verified adaptive Python skills.",
            input_schema={"type": "object", "properties": {}},
            handler=lambda _: {"skills": self.skill_forge.list_skills()},
        )
        self.register_tool(
            name="am_skill_forge",
            description="Forge, AST-verify, test, and seal a new reusable Python skill.",
            input_schema={
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "description": {"type": "string"},
                    "code": {"type": "string"},
                },
                "required": ["name", "code"],
            },
            handler=lambda args: self.skill_forge.forge_skill(
                name=str(args["name"]),
                description=str(args.get("description", "")),
                code=str(args["code"]),
                tags=args.get("tags"),
                test_kwargs=args.get("test_kwargs"),
            ),
        )
        self.register_tool(
            name="am_skill_run",
            description="Verify SHA-256 integrity and run a registered adaptive skill.",
            input_schema={
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "kwargs": {"type": "object"},
                },
                "required": ["name"],
            },
            handler=lambda args: self.skill_forge.run_skill(
                name=str(args["name"]),
                kwargs=dict(args.get("kwargs") or {}),
            ),
        )

    def register_tool(
        self,
        *,
        name: str,
        description: str,
        input_schema: Dict[str, Any],
        handler: Callable[[Dict[str, Any]], Any],
    ) -> None:
        schema = {
            "name": name,
            "description": description,
            "inputSchema": input_schema,
        }
        self._tools[name] = (schema, handler)

    def handle_jsonrpc_message(self, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a single JSON-RPC 2.0 request/notification and return response dict (or None for notifications)."""
        method = str(msg.get("method", ""))
        req_id = msg.get("id")

        if req_id is None:
            # JSON-RPC Notification (e.g. notifications/initialized) -> no response required
            return None

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "aethermind-universal-agent-mcp",
                        "version": "3.4.0",
                    },
                },
            }

        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method == "tools/list":
            tools_list = [spec for spec, _ in self._tools.values()]
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": tools_list},
            }

        if method == "tools/call":
            params = msg.get("params") or {}
            tname = str(params.get("name", ""))
            targs = dict(params.get("arguments") or {})
            if tname not in self._tools:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Unknown tool: {tname}"},
                }
            _, fn = self._tools[tname]
            try:
                out = fn(targs)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(out, ensure_ascii=False, default=str),
                            }
                        ],
                        "isError": False,
                    },
                }
            except Exception as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False),
                            }
                        ],
                        "isError": True,
                    },
                }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    def serve_stdio(self) -> int:
        """Run the blocking JSON-RPC 2.0 stdio loop until EOF."""
        for raw_line in sys.stdin:
            line = raw_line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            resp = self.handle_jsonrpc_message(msg)
            if resp is not None:
                sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
                sys.stdout.flush()
        return 0
