# MaxOps MCP Client v1

> An interactive terminal AI agent that connects **Groq LLMs** to your local machine through the **Model Context Protocol (MCP)**.

---

## What is this?

This is a command-line AI assistant that can actually **do things** on your computer — not just chat.

It works by connecting two systems together:

- **Groq** — a super-fast AI inference platform that runs large language models (like GPT-class models)
- **MCP (Model Context Protocol)** — a standard that lets AI models talk to tools running on your machine (read files, write files, run commands, etc.)

When you type a message, the AI decides whether it needs to use a tool (like reading a file or running a command), calls that tool through the MCP server, and then gives you a real answer based on the result.

---

## What can it do?

| Tool | What it does | Requires approval? |
|---|---|---|
| `list_workspace` | Lists files in your workspace folder | No (auto) |
| `read_file` | Reads the content of any file | No (auto) |
| `write_file` | Creates or overwrites a file | **Yes — asks you first** |
| `execute_command` | Runs a terminal command | **Yes — asks you first** |

The client also has **built-in security**:
- Blocks writing dangerous file types (`.exe`, `.bat`, `.ps1`, etc.)
- Detects and blocks malicious code patterns before writing files
- Asks for your approval before any state-changing action
- Stops automatically if the AI gets stuck in a loop (max 10 tool steps)
- Keeps conversation history trimmed to avoid token overflow

---

## Requirements

Before you start, make sure you have these installed:

- **Python 3.13+** — [Download here](https://www.python.org/downloads/)
- **uv** (Python package manager) — [Install here](https://docs.astral.sh/uv/getting-started/installation/)
- **A Groq API key** — [Get one free at console.groq.com](https://console.groq.com)

---

## Project Structure

```
groq_client/
├── client.py          ← Main client (this is what you run)
├── .env               ← Your secret API key goes here
├── pyproject.toml     ← Python dependencies
└── README.md          ← This file
```

The MCP server (the tool provider) lives separately at:
```
D:\mcp\servers\terminal_server\
└── server.py          ← MCP server exposing tools to the client
```

---

## Setup (Step by Step)

### 1. Clone or download the project

```bash
# If using git
git clone <your-repo-url>
cd groq_client
```

### 2. Add your Groq API key

Open the `.env` file (or create it) and add:

```
GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Get your key from [console.groq.com](https://console.groq.com) → API Keys → Create API Key.

### 3. Install dependencies

```bash
uv sync
```

This installs `groq`, `mcp`, and `python-dotenv` automatically.

### 4. Check your uv path (Windows only)

Open `client.py` and check line 28:

```python
UV_EXECUTABLE = r"C:\Users\akash\AppData\Local\Programs\Python\Python313\Scripts\uv.exe"
```

Change `akash` to your Windows username, or just set it to `"uv"` if uv is already on your PATH.

### 5. Check your MCP server path

On line 37, make sure this path points to your MCP server folder:

```python
r"D:\mcp\servers\terminal_server"
```

Update it to wherever your `server.py` lives.

### 6. Run the client

```bash
uv run client.py
```

You should see the MaxOps banner and a `You:` prompt.

---

## How to use it

Just type naturally. Some examples:

```
You: list all files in my workspace
You: read the file called notes.txt
You: create a file called hello.txt with the message "Hello World"
You: what is 2 + 2
You: run the command "echo hello"
You: exit
```

When the AI wants to write a file or run a command, it will **pause and ask you**:

```
⚠ Warning  Approval Required  Allow 'write_file'? (y/n): 
```

Type `y` to allow or `n` to cancel.

---

## Changing the AI model

Open `client.py` and edit line 45:

```python
GROQ_MODEL = "openai/gpt-oss-120b"   # change this to any model on your Groq account
```

To see what models are available on your account, log in to [console.groq.com](https://console.groq.com).

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `GROQ_API_KEY is not set` | Add your key to the `.env` file |
| `Could not start the MCP server` | Check the `uv.exe` path and server directory path in `client.py` |
| `Tool object has no attribute inputSchema` | Make sure your `mcp` package is version `>=2.3.0` (run `uv sync`) |
| Banner characters look broken | Use a terminal with UTF-8 support (Windows Terminal, VS Code terminal) |

---

## Security Model

```
User Input
    │
    ▼
Groq LLM decides tool to call
    │
    ▼
validate_tool_call()  ←── blocks bad file types & malware signatures
    │
    ▼
hitl_confirm()        ←── asks YOU before write/execute runs
    │
    ▼
MCP Server executes the tool
    │
    ▼
Result returned to Groq → Final answer to you
```

---

## License

MIT — use it, modify it, share it.
