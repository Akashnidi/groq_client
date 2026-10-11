"""
Interactive Terminal MCP Client
================================
Bridges the Model Context Protocol (MCP) with Groq LLMs using a
ReAct-style tool-execution loop.

Usage:
    uv run client.py
    python client.py
"""

import asyncio
import json
import os
import re
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

# Path to the uv executable (Windows-specific); falls back to PATH lookup
UV_EXECUTABLE = r"C:\Users\akash\AppData\Local\Programs\Python\Python313\Scripts\uv.exe"
if not os.path.isfile(UV_EXECUTABLE):
    UV_EXECUTABLE = "uv"

# MCP server to spawn
MCP_SERVER_PARAMS = StdioServerParameters(
    command=UV_EXECUTABLE,
    args=[
        "--directory",
        r"D:\mcp\servers\terminal_server",
        "run",
        "server.py",
    ],
    env=None,  # inherit current environment
)

# Groq model to use
GROQ_MODEL = "openai/gpt-oss-120b"  # fallback: "qwen/qwen3.8-27b" or "openai/gpt-oss-20b"

# ---------------------------------------------
# Security configuration
# ---------------------------------------------

# Maximum tool-call iterations per user prompt (loop-runaway guard)
MAX_TOOL_STEPS = 10

# Sliding context-window: trim messages list when it exceeds this length
MAX_HISTORY_LEN = 25

# File extensions blocked in write_file calls
BLOCKED_EXTENSIONS: frozenset[str] = frozenset({
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".reg", ".dll",
})

# Regex patterns that signal malicious payload in write_file content
MALWARE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"base64\.b64decode",        re.IGNORECASE),
    re.compile(r"exec\s*\(",                re.IGNORECASE),
    re.compile(r"eval\s*\(",                re.IGNORECASE),
    re.compile(r"socket\.socket",           re.IGNORECASE),
    re.compile(r"pty\.spawn",               re.IGNORECASE),
    re.compile(r"ctypes\.windll",           re.IGNORECASE),
    re.compile(r"win32api",                 re.IGNORECASE),
]

# Tools that silently execute (no HITL prompt needed)
READ_ONLY_TOOLS: frozenset[str] = frozenset({"list_workspace", "read_file"})

# Tools that mutate state and require explicit human approval before running
HITL_TOOLS: frozenset[str] = frozenset({"write_file", "execute_command"})

# ANSI colour codes for prettier terminal output
RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
DIM    = "\033[2m"


# ---------------------------------------------
# Helper utilities
# ---------------------------------------------

def _banner(tools: list[dict[str, Any]]) -> None:
    """Print a startup banner: big ASCII-art logo + structured info panel."""

    # ── Large block-letter logo ───────────────────────────────────────────
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

    # ── Info panel (box-drawing style) ────────────────────────────────────
    W = 58  # inner width
    provider = "Groq"
    tool_count = len(tools)

    def _strip_ansi(text: str) -> str:
        return re.sub(r"\033\[[0-9;]*m", "", text)

    def box_row(content: str) -> None:
        visible_len = len(_strip_ansi(content))
        pad = " " * max(0, W - visible_len)
        print(CYAN + "│" + RESET + content + pad + CYAN + "│" + RESET)

    # Header row
    header_left  = " MAx Ops  │  MCP Terminal Client"
    header_right = "v1.0 "
    header_pad   = W - len(header_left) - len(header_right)
    header_content = header_left + " " * header_pad + header_right

    print(CYAN + "┌" + "─" * W + "┐" + RESET)
    box_row(BOLD + header_content + RESET)
    print(CYAN + "├" + "─" * W + "┤" + RESET)

    # Key-value rows
    box_row(f" {BOLD}{'AI MODEL':<12}{RESET}  {GROQ_MODEL}")
    box_row(f" {BOLD}{'PROVIDER':<12}{RESET}  {provider}")
    box_row(f" {BOLD}{'MCP TOOLS':<12}{RESET}  {tool_count} discovered")
    box_row(f" {BOLD}{'STATUS':<12}{RESET}  {GREEN}●{RESET} READY")
    print(CYAN + "├" + "─" * W + "┤" + RESET)

    # Tool list
    for t in tools:
        fn   = t["function"]
        name = fn["name"]
        tag  = "[read]" if name in ("list_workspace", "read_file") else "[write]"
        tag_colored = (DIM + tag + RESET) if "read" in tag else (YELLOW + tag + RESET)
        box_row(f" {BOLD}{name}{RESET}  {tag_colored}")

    print(CYAN + "└" + "─" * W + "┘" + RESET)
    print(f"  {DIM}Type {RESET}{BOLD}exit{RESET}{DIM} or {RESET}{BOLD}quit{RESET}{DIM} to leave  ·  {RESET}{BOLD}Ctrl+C{RESET}{DIM} also works{RESET}")
    print()



def _extract_text(content: Any) -> str:
    """
    Safely pull plain text out of an MCP tool result.

    MCP returns a list of content blocks (TextContent, ImageContent, ...).
    We join all text blocks; if none exist we fall back to repr().
    """
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
                parts.append(repr(block))
        return "\n".join(parts) if parts else repr(content)

    if hasattr(content, "text"):
        return content.text

    return repr(content)


def validate_tool_call(fn_name: str, fn_args: dict[str, Any]) -> tuple[bool, str]:
    """
    Client-side pre-flight security validator.

    Returns (True, "") when the call is safe to dispatch.
    Returns (False, reason) when it should be blocked.

    Rules enforced
    --------------
    write_file:
      - Blocks dangerous executable file extensions.
      - Scans the file content for high-risk code patterns (malware signatures).
    """
    if fn_name == "write_file":
        # --- Extension check ---
        filename: str = str(fn_args.get("filename", fn_args.get("path", "")))
        _, ext = os.path.splitext(filename.lower())
        if ext in BLOCKED_EXTENSIONS:
            return (
                False,
                f"[Security Violation]: Tool call blocked by client guardrail "
                f"(Dangerous file extension '{ext}' is not allowed).",
            )

        # --- Malware signature scan ---
        file_content: str = str(fn_args.get("content", fn_args.get("text", "")))
        for pattern in MALWARE_PATTERNS:
            if pattern.search(file_content):
                return (
                    False,
                    "[Security Violation]: Tool call blocked by client guardrail "
                    "(Restricted code pattern detected).",
                )

    return True, ""


def hitl_confirm(fn_name: str) -> bool:
    """
    Human-in-the-Loop approval gate for state-modifying tools.

    Prompts the operator in the terminal and returns True only when they
    explicitly approve with 'y'. Any other input (including Ctrl+C) is
    treated as a denial.
    """
    try:
        answer = input(
            f"  {RED}Warning  Approval Required{RESET} "
            f"Allow '{BOLD}{fn_name}{RESET}'? (y/n): "
        ).strip().lower()
        return answer == "y"
    except (EOFError, KeyboardInterrupt):
        print()  # newline after ^C
        return False


# ---------------------------------------------
# Core agent loop
# ---------------------------------------------

async def agent_loop(session: ClientSession, groq_client: Groq) -> None:
    """
    Discover MCP tools, then run an interactive ReAct loop:
      user input -> Groq -> [tool calls -> MCP -> Groq synthesis] -> reply
    """

    # 1. Discover tools from the MCP server
    tools_result = await session.list_tools()
    groq_tools: list[dict[str, Any]] = [
        {
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.input_schema,
            },
        }
        for tool in tools_result.tools
    ]

    _banner(groq_tools)

    # 2. Maintain full conversation history
    messages: list[dict[str, Any]] = []

    # 3. Interactive loop
    while True:
        try:
            user_input = input(f"{GREEN}{BOLD}You:{RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{DIM}Goodbye!{RESET}")
            break

        if not user_input:
            continue

        if user_input.lower() in {"exit", "quit"}:
            print(f"{DIM}Closing connection... Goodbye!{RESET}")
            break

        messages.append({"role": "user", "content": user_input})

        # ── Sliding context-window: keep history bounded ─────────────────
        if len(messages) > MAX_HISTORY_LEN:
            messages = messages[-MAX_HISTORY_LEN:]

        # ReAct inner loop (may iterate if tools chain)
        tool_steps = 0
        while True:
            response = groq_client.chat.completions.create(
                model=GROQ_MODEL,
                messages=messages,
                tools=groq_tools if groq_tools else None,
                tool_choice="auto" if groq_tools else None,
            )

            message = response.choices[0].message

            # Branch A: Groq wants to call one or more tools
            if message.tool_calls:
                # ── Loop-runaway guard ────────────────────────────────────
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
                        fn_args: dict[str, Any] = (
                            json.loads(fn_args_raw)
                            if isinstance(fn_args_raw, str)
                            else fn_args_raw
                        )
                    except json.JSONDecodeError:
                        fn_args = {}

                    print(
                        f"  {YELLOW}[Tool]{RESET} {BOLD}{fn_name}{RESET}"
                        f" {DIM}| Args: {json.dumps(fn_args)}{RESET}"
                    )

                    # ── Security pre-flight ───────────────────────────────
                    safe, reason = validate_tool_call(fn_name, fn_args)
                    if not safe:
                        print(f"  {RED}[Blocked]{RESET} {reason}")
                        tool_content = reason
                        messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": tool_call.id,
                                "content": tool_content,
                            }
                        )
                        continue

                    # ── HITL confirmation for state-modifying tools ───────
                    if fn_name in HITL_TOOLS:
                        approved = hitl_confirm(fn_name)
                        if not approved:
                            print(f"  {DIM}[Cancelled by user]{RESET}")
                            tool_content = "[Execution Cancelled by User]"
                            messages.append(
                                {
                                    "role": "tool",
                                    "tool_call_id": tool_call.id,
                                    "content": tool_content,
                                }
                            )
                            continue

                    # ── Dispatch to MCP server ────────────────────────────
                    try:
                        mcp_result = await session.call_tool(fn_name, fn_args)
                        tool_content = _extract_text(mcp_result.content)
                    except Exception as exc:
                        tool_content = f"[Tool error] {exc}"

                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "content": tool_content,
                        }
                    )

                tool_steps += 1
                # Loop again so Groq can synthesise results
                continue

            # Branch B: Groq has a final answer
            final_text = message.content or ""
            print(f"\n{CYAN}{BOLD}Assistant:{RESET} {final_text}\n")
            messages.append({"role": "assistant", "content": final_text})
            break  # exit inner loop, prompt user again


# ---------------------------------------------
# Entry point
# ---------------------------------------------

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

    print(f"{DIM}Connecting to MCP server...{RESET}", end="", flush=True)
    try:
        async with stdio_client(MCP_SERVER_PARAMS) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                print(f" {GREEN}connected{RESET}")
                await agent_loop(session, groq_client)
    except FileNotFoundError as exc:
        print(
            f"\n{RED}{BOLD}Error:{RESET} Could not start the MCP server.\n"
            f"  Detail: {exc}\n"
            f"  Check that '{UV_EXECUTABLE}' exists and the server path is correct."
        )
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{DIM}Interrupted. Goodbye!{RESET}")


if __name__ == "__main__":
    asyncio.run(main())
