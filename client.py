"""
Interactive Terminal MCP Client - Version 2 (Multi-Server Hub)
==============================================================
Orchestrates multiple Model Context Protocol (MCP) servers dynamically
configured via `servers_config.json`, bridging them with Groq LLMs
using a ReAct tool execution loop with intelligent routing and security guardrails.

Usage:
    uv run client.py
    python client.py
"""

import asyncio
from contextlib import AsyncExitStack
import json
import os
from pathlib import Path
import re
import shutil
import sys
from typing import Any

from dotenv import load_dotenv
from groq import Groq
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# ---------------------------------------------
# Configuration
# ---------------------------------------------

CONFIG_FILENAME = "servers_config.json"
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
FALLBACK_MODEL = os.getenv("GROQ_FALLBACK_MODEL", "openai/gpt-oss-120b")

# Maximum tool-call iterations per user prompt (loop-runaway guard)
MAX_TOOL_STEPS = 10

# Sliding context-window: keep the last 25 messages to prevent token overflow
MAX_HISTORY_LEN = 25

# File extensions blocked in write_file calls
BLOCKED_EXTENSIONS: frozenset[str] = frozenset({
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".reg", ".dll",
})

# Suspicious code signatures blocked in write_file content
MALWARE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"base64\.b64decode", re.IGNORECASE),
    re.compile(r"exec\s*\(", re.IGNORECASE),
    re.compile(r"eval\s*\(", re.IGNORECASE),
    re.compile(r"socket\.socket", re.IGNORECASE),
    re.compile(r"pty\.spawn", re.IGNORECASE),
    re.compile(r"ctypes\.windll", re.IGNORECASE),
    re.compile(r"win32api", re.IGNORECASE),
]

# ANSI colour codes for terminal output
RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
DIM    = "\033[2m"


# ---------------------------------------------
# UI Helpers & Banner
# ---------------------------------------------

def _strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences for accurate string width calculation."""
    return re.sub(r"\033\[[0-9;]*m", "", text)


def _banner(
    server_names: list[str],
    server_tools_map: dict[str, list[str]],
    total_tool_count: int,
    active_model: str,
) -> None:
    """Print the v2 Multi-Server Hub startup banner."""
    logo = [
        "  ███╗   ███╗  █████╗  ██╗  ██╗     ██████╗  ██████╗  ███████╗",
        "  ████╗ ████║ ██╔══██╗ ╚██╗██╔╝    ██╔═══██╗ ██╔══██╗ ██╔════╝",
        "  ██╔████╔██║ ███████║  ╚███╔╝     ██║   ██║ ██████╔╝ ███████╗",
        "  ██║╚██╔╝██║ ██╔══██║  ██╔██╗     ██║   ██║ ██╔═══╝  ╚════██║",
        "  ██║ ╚═╝ ██║ ██║  ██║ ██╔╝ ██╗    ╚██████╔╝ ██║      ███████║",
        "  ╚═╝     ╚═╝ ╚═╝  ╚═╝ ╚═╝  ╚═╝     ╚═════╝  ╚═╝      ╚══════╝",
    ]
    print()
    for line in logo:
        print(CYAN + BOLD + line + RESET)
    print()

    W = 62  # inner width
    def box_row(content: str) -> None:
        visible_len = len(_strip_ansi(content))
        pad = " " * max(0, W - visible_len)
        print(CYAN + "│" + RESET + content + pad + CYAN + "│" + RESET)

    header_left  = " MAx Ops  │  MCP Multi-Server Hub"
    header_right = "v2.0 "
    header_pad   = W - len(header_left) - len(header_right)
    header_content = header_left + " " * header_pad + header_right

    print(CYAN + "┌" + "─" * W + "┐" + RESET)
    box_row(BOLD + header_content + RESET)
    print(CYAN + "├" + "─" * W + "┤" + RESET)

    box_row(f" {BOLD}{'AI MODEL':<12}{RESET}  {active_model}")
    box_row(f" {BOLD}{'PROVIDER':<12}{RESET}  Groq")
    box_row(f" {BOLD}{'SERVERS':<12}{RESET}  {len(server_names)} connected")
    box_row(f" {BOLD}{'MCP TOOLS':<12}{RESET}  {total_tool_count} discovered across all servers")
    box_row(f" {BOLD}{'STATUS':<12}{RESET}  {GREEN}●{RESET} READY")
    print(CYAN + "├" + "─" * W + "┤" + RESET)

    for server_name in server_names:
        tools = server_tools_map.get(server_name, [])
        box_row(f" {BOLD}{CYAN}▶ {server_name}{RESET} ({len(tools)} tools)")
        for tool_name in tools:
            is_hitl = is_hitl_tool(tool_name)
            tag = "[write]" if is_hitl else "[read]"
            tag_col = YELLOW + tag + RESET if is_hitl else DIM + tag + RESET
            box_row(f"    • {tool_name:<30} {tag_col}")

    print(CYAN + "└" + "─" * W + "┘" + RESET)
    print(f"  {DIM}Type {RESET}{BOLD}exit{RESET}{DIM} or {RESET}{BOLD}quit{RESET}{DIM} to leave  ·  {RESET}{BOLD}Ctrl+C{RESET}{DIM} also works{RESET}")
    print()


# ---------------------------------------------
# Security & Safety Guardrails
# ---------------------------------------------

def is_hitl_tool(tool_name: str) -> bool:
    """Check if tool mutates state and requires human-in-the-loop approval."""
    name_lower = tool_name.lower()
    if tool_name in {"write_file", "execute_command"}:
        return True
    return any(keyword in name_lower for keyword in ("create", "delete", "update"))


def validate_tool_call(fn_name: str, fn_args: dict[str, Any]) -> tuple[bool, str]:
    """
    Client-side pre-flight security validator.
    Blocks dangerous file extensions and suspicious payload signatures in write_file.
    """
    if fn_name == "write_file":
        filename = str(fn_args.get("filename", fn_args.get("path", "")))
        _, ext = os.path.splitext(filename.lower())
        if ext in BLOCKED_EXTENSIONS:
            return (
                False,
                f"[Security Violation]: Tool call blocked by client guardrail "
                f"(Dangerous file extension '{ext}' is not allowed).",
            )

        file_content = str(fn_args.get("content", fn_args.get("text", "")))
        for pattern in MALWARE_PATTERNS:
            if pattern.search(file_content):
                return (
                    False,
                    f"[Security Violation]: Tool call blocked by client guardrail "
                    f"(Suspicious code pattern detected: '{pattern.pattern}').",
                )

    return True, ""


def hitl_confirm(fn_name: str, server_name: str) -> bool:
    """Prompt the operator for confirmation before running state-modifying tools."""
    try:
        prompt_msg = (
            f"  {YELLOW}⚠️  [Approval Required]{RESET} "
            f"Allow '{BOLD}{fn_name}{RESET}' on '{CYAN}{server_name}{RESET}'? (y/n): "
        )
        answer = input(prompt_msg).strip().lower()
        return answer == "y"
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def _extract_text(content: Any) -> str:
    """Extract plain text from an MCP tool response object."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if hasattr(block, "text"):
                parts.append(block.text)
            elif isinstance(block, dict) and "text" in block:
                parts.append(block["text"])
            else:
                parts.append(str(block))
        return "\n".join(parts) if parts else str(content)
    if hasattr(content, "text"):
        return content.text
    return str(content)


# ---------------------------------------------
# ReAct Execution Loop
# ---------------------------------------------

async def agent_loop(
    groq_client: Groq,
    tool_router: dict[str, tuple[str, ClientSession]],
    groq_tools: list[dict[str, Any]],
    server_names: list[str],
    server_tools_map: dict[str, list[str]],
) -> None:
    """
    Main interactive ReAct loop:
    User Prompt -> Groq LLM -> Dispatched MCP Tool Execution -> Synthesis -> Response.
    """
    active_model = GROQ_MODEL
    _banner(server_names, server_tools_map, len(groq_tools), active_model)

    messages: list[dict[str, Any]] = []

    while True:
        try:
            user_input = input(f"{GREEN}{BOLD}You:{RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{DIM}Goodbye!{RESET}")
            break

        if not user_input:
            continue

        if user_input.lower() in {"exit", "quit"}:
            print(f"{DIM}Closing connections... Goodbye!{RESET}")
            break

        messages.append({"role": "user", "content": user_input})

        # Context Window Protection: keep last MAX_HISTORY_LEN messages
        if len(messages) > MAX_HISTORY_LEN:
            messages = messages[-MAX_HISTORY_LEN:]
            # Ensure trimmed messages don't start with an orphaned tool response
            while messages and messages[0].get("role") == "tool":
                messages.pop(0)

        tool_steps = 0
        while True:
            # Call Groq chat completions with model fallback resilience
            try:
                response = groq_client.chat.completions.create(
                    model=active_model,
                    messages=messages,
                    tools=groq_tools if groq_tools else None,
                    tool_choice="auto" if groq_tools else None,
                )
            except Exception as exc:
                err_str = str(exc).lower()
                if ("model_not_found" in err_str or "404" in err_str) and active_model != FALLBACK_MODEL:
                    print(
                        f"  {YELLOW}[Notice]{RESET} Model '{active_model}' unavailable on this Groq account. "
                        f"Falling back to '{FALLBACK_MODEL}'."
                    )
                    active_model = FALLBACK_MODEL
                    response = groq_client.chat.completions.create(
                        model=active_model,
                        messages=messages,
                        tools=groq_tools if groq_tools else None,
                        tool_choice="auto" if groq_tools else None,
                    )
                else:
                    print(f"  {RED}[Groq Error]{RESET} {exc}")
                    break

            message = response.choices[0].message

            # Branch A: Model requested tool calls
            if message.tool_calls:
                if tool_steps >= MAX_TOOL_STEPS:
                    print(
                        f"  {RED}[Warning]{RESET} Maximum tool execution limit "
                        f"({MAX_TOOL_STEPS} steps) reached to prevent loop runaway."
                    )
                    break

                messages.append(message)

                for tool_call in message.tool_calls:
                    fn_name = tool_call.function.name
                    fn_args_raw = tool_call.function.arguments

                    try:
                        fn_args = (
                            json.loads(fn_args_raw)
                            if isinstance(fn_args_raw, str)
                            else (fn_args_raw or {})
                        )
                    except json.JSONDecodeError:
                        fn_args = {}

                    # Route tool to its registered MCP server
                    if fn_name not in tool_router:
                        print(f"  {RED}[Route Error]{RESET} No server registered for tool '{fn_name}'")
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "content": f"[Error]: Tool '{fn_name}' not found on any registered server.",
                        })
                        continue

                    server_name, session = tool_router[fn_name]
                    print(
                        f"  {YELLOW}⚡ [Tool]{RESET} {BOLD}{fn_name}{RESET} "
                        f"(via {CYAN}{server_name}{RESET}) | Args: {json.dumps(fn_args)}"
                    )

                    # Security Guardrail 1: Malicious Content & Dangerous Extension Filter
                    safe, block_reason = validate_tool_call(fn_name, fn_args)
                    if not safe:
                        print(f"  {RED}[Blocked]{RESET} {block_reason}")
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "content": block_reason,
                        })
                        continue

                    # Security Guardrail 2: Human-in-the-Loop (HITL) Prompt for state-modifying tools
                    if is_hitl_tool(fn_name):
                        approved = hitl_confirm(fn_name, server_name)
                        if not approved:
                            print(f"  {DIM}[Cancelled by user]{RESET}")
                            messages.append({
                                "role": "tool",
                                "tool_call_id": tool_call.id,
                                "content": "[Execution Cancelled by User]",
                            })
                            continue

                    # Dispatch execution to target MCP server session
                    try:
                        mcp_result = await session.call_tool(fn_name, fn_args)
                        tool_content = _extract_text(mcp_result.content)
                    except Exception as exc:
                        tool_content = f"[Tool Error on {server_name}]: {exc}"

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": tool_content,
                    })

                tool_steps += 1
                continue

            # Branch B: Final Assistant Response
            final_text = message.content or ""
            print(f"\n{CYAN}{BOLD}Assistant:{RESET} {final_text}\n")
            messages.append({"role": "assistant", "content": final_text})
            break


# ---------------------------------------------
# Multi-Server Lifecycle & Main Entrypoint
# ---------------------------------------------

def load_server_configurations() -> dict[str, Any]:
    """Locate and parse `servers_config.json`."""
    search_paths = [
        Path.cwd() / CONFIG_FILENAME,
        Path(__file__).resolve().parent / CONFIG_FILENAME,
    ]
    for p in search_paths:
        if p.is_file():
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data.get("mcpServers", {})
            except Exception as exc:
                print(f"{RED}[Error]{RESET} Failed to parse {p}: {exc}")
                sys.exit(1)

    print(f"{RED}[Error]{RESET} Configuration file '{CONFIG_FILENAME}' not found.")
    sys.exit(1)


async def main() -> None:
    load_dotenv()

    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        print(
            f"{RED}{BOLD}Error:{RESET} GROQ_API_KEY is not set.\n"
            "Add it to your .env file or export it as an environment variable.\n"
            "  Example: GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxxxxxxxxxx"
        )
        sys.exit(1)

    groq_client = Groq(api_key=api_key)
    servers_config = load_server_configurations()

    if not servers_config:
        print(f"{RED}[Error]{RESET} No servers configured under 'mcpServers' in {CONFIG_FILENAME}.")
        sys.exit(1)

    print(f"{DIM}Connecting to MCP servers from {CONFIG_FILENAME}...{RESET}")

    # Use AsyncExitStack to cleanly manage all server processes & sessions
    async with AsyncExitStack() as stack:
        tool_router: dict[str, tuple[str, ClientSession]] = {}
        groq_tools: list[dict[str, Any]] = []
        server_tools_map: dict[str, list[str]] = {}
        server_names: list[str] = []

        for server_name, s_cfg in servers_config.items():
            command = s_cfg.get("command", "uv")
            # Resolve executable or fallback to "uv"
            if not os.path.isfile(command):
                if not shutil.which(command):
                    command = "uv"

            args = s_cfg.get("args", [])
            custom_env = s_cfg.get("env") or {}
            server_env = {**os.environ, **custom_env}

            server_params = StdioServerParameters(
                command=command,
                args=args,
                env=server_env,
            )

            try:
                read, write = await stack.enter_async_context(stdio_client(server_params))
                session = await stack.enter_async_context(ClientSession(read, write))
                await session.initialize()

                tools_resp = await session.list_tools()
                discovered_tools = tools_resp.tools

                server_names.append(server_name)
                server_tools_map[server_name] = [t.name for t in discovered_tools]

                # Log connection status
                print(f"  [+] Connected: {server_name} ({len(discovered_tools)} tools)")

                # Register each tool into unified router and Groq tools schema
                for tool in discovered_tools:
                    tool_router[tool.name] = (server_name, session)
                    schema = getattr(tool, "inputSchema", None) or getattr(tool, "input_schema", {})
                    groq_tools.append({
                        "type": "function",
                        "function": {
                            "name": tool.name,
                            "description": f"[{server_name}] {tool.description or ''}",
                            "parameters": schema,
                        },
                    })

            except Exception as exc:
                print(f"  {RED}[-] Failed to connect to {server_name}:{RESET} {exc}")

        if not tool_router:
            print(f"{RED}[Error]{RESET} Could not connect to any MCP servers. Exiting.")
            sys.exit(1)

        # Run interactive ReAct loop
        await agent_loop(
            groq_client=groq_client,
            tool_router=tool_router,
            groq_tools=groq_tools,
            server_names=server_names,
            server_tools_map=server_tools_map,
        )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, asyncio.CancelledError):
        print(f"\n{DIM}Interrupted. Goodbye!{RESET}")
