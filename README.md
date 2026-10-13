# MaxOps MCP Client v2 (Multi-Server Hub)

> An interactive terminal AI agent that orchestrates **multiple Model Context Protocol (MCP) servers** and connects them to **Groq LLMs** (`llama-3.3-70b-versatile`) with dynamic routing, ReAct synthesis, and strict security guardrails.

---

## What is Version 2?

**Version 2** upgrades the client from a single-server terminal runner to a **Multi-Server MCP Orchestrator Hub**.

Instead of hardcoded server configurations, Version 2 dynamically discovers and communicates with any number of MCP servers defined in `servers_config.json`:
- **Workspace Manager** (`terminal_server`) — inspects files, edits workspace files, and executes shell commands.
- **Jira MCP Server** (`jira-mcp-server`) — searches issues, inspects ticket details, creates and transitions Jira issues.

When you send a prompt, Groq automatically determines which server hosts the relevant tool, routes the request to that server's active session, and returns synthesized answers.

---

## Key Features

- **Multi-Server Lifecycle (`AsyncExitStack`)**: Connects to and initializes all configured MCP servers cleanly, closing subprocesses upon exit without orphan processes.
- **Dynamic Tool Routing**: Aggregates tools from all servers into a unified OpenAI/Groq function-calling palette tagged with server metadata (`[{server_name}] {description}`).
- **Interactive Terminal UI**: Styled ASCII art logo and box-drawing status dashboard displaying model, active servers, discovered tools, and read/write badges.
- **Security & Safety Guardrails**:
  - **Malicious Content & Extension Filter**: Blocks dangerous executable extensions (`.exe`, `.bat`, `.cmd`, `.ps1`, `.vbs`, `.reg`, `.dll`) and suspicious signatures (`base64.b64decode`, `exec(`, `eval(`, `socket.socket`, etc.) during file writing.
  - **Human-in-the-Loop (HITL) Gate**: Requires interactive operator confirmation `(y/n)` for state-modifying actions (`write_file`, `execute_command`, or any tool containing `create`, `delete`, or `update`).
  - **Loop Runaway Guard**: Caps chained tool calls at `MAX_TOOL_STEPS = 10` per user turn.
  - **Context Window Protection**: Automatically bounds history to the last 25 messages to prevent token limits from overflowing.

---

## Discovered Tools Matrix

| Server | Tool | Type | Requires Approval (HITL)? |
|---|---|---|---|
| **`workspace-manager`** | `list_workspace` | `[read]` | No (auto) |
| | `read_file` | `[read]` | No (auto) |
| | `write_file` | `[write]` | **Yes — asks before saving** |
| | `execute_command` | `[write]` | **Yes — asks before running** |
| **`jira-mcp-server`** | `search_issues` | `[read]` | No (auto) |
| | `get_issue` | `[read]` | No (auto) |
| | `create_issue` | `[write]` | **Yes — asks before creating** |
| | `update_issue` | `[write]` | **Yes — asks before updating** |
| | `transition_issue` | `[read/write]` | No / as configured |

---

## Project Structure

```
groq_client/
├── servers_config.json   ← Multi-server configuration file
├── client.py             ← v2 Multi-Server orchestrator & CLI
├── pyproject.toml        ← Python dependencies managed by uv
├── .env                  ← Groq API key and environment variables
└── README.md             ← Documentation
```

---

## Quickstart

### 1. Prerequisites
- **Python 3.13+**
- **uv** package manager (`pip install uv` or install via Astral docs)
- **Groq API Key** from [console.groq.com](https://console.groq.com)

### 2. Configure Environment
Create or edit your `.env` file in `d:\mcp\clients\groq_client`:

```env
GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
# Optional overrides:
GROQ_MODEL=llama-3.3-70b-versatile
GROQ_FALLBACK_MODEL=openai/gpt-oss-120b
```

### 3. Configure Servers (`servers_config.json`)
Define your MCP servers in `servers_config.json`:

```json
{
  "mcpServers": {
    "workspace-manager": {
      "command": "C:\\Users\\akash\\AppData\\Local\\Programs\\Python\\Python313\\Scripts\\uv.exe",
      "args": [
        "--directory",
        "D:\\mcp\\servers\\terminal_server",
        "run",
        "server.py"
      ]
    },
    "jira-mcp-server": {
      "command": "C:\\Users\\akash\\AppData\\Local\\Programs\\Python\\Python313\\Scripts\\uv.exe",
      "args": [
        "--directory",
        "D:\\mcp\\servers\\jira-mcp-server",
        "run",
        "main.py"
      ]
    }
  }
}
```

> **Note**: If the full path to `uv.exe` is not found, the client automatically falls back to system PATH `uv`.

### 4. Sync Dependencies
```bash
uv sync
```

### 5. Launch Client
```bash
uv run client.py
```

---

## Example Usage

Once launched, prompt the assistant naturally across any server domain:

```text
You: list all files in the current workspace
⚡ [Tool] list_workspace (via workspace-manager) | Args: {"subpath": "."}

You: search for Jira tickets in project DEV with status 'To Do'
⚡ [Tool] search_issues (via jira-mcp-server) | Args: {"jql": "project = DEV AND status = 'To Do'"}

You: create a Jira ticket with summary "Fix authentication timeout"
⚠️  [Approval Required] Allow 'create_issue' on 'jira-mcp-server'? (y/n): y
⚡ [Tool] create_issue (via jira-mcp-server) | Args: {...}

You: exit
Closing connections... Goodbye!
```

---

## Security Architecture

```
User Prompt
    │
    ▼
Groq LLM (llama-3.3-70b-versatile)
    │
    ▼ (Decides Tool Call)
Tool Router (Identifies owning server)
    │
    ├── 1. Malware & Dangerous Extension Filter
    │       (Blocks .exe, .bat, base64 eval, socket patterns)
    │
    ├── 2. Human-in-the-Loop (HITL) Gate
    │       (Prompts user confirmation for state-modifying actions)
    │
    ▼
Target MCP Server (`session.call_tool`)
    │
    ▼
Result Appended with role="tool"
    │
    ▼
Groq LLM Synthesizes Final Answer
```

---

## License

MIT — feel free to use, modify, and build upon.
