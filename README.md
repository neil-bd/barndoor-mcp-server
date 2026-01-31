# Barndoor MCP Server

An **MCP (Model Context Protocol) server** for managing a Barndoor.ai account.

This server allows MCP-capable clients (Claude Desktop, MCP Inspector, custom agents, etc.) to manage:

- AI agent registrations
- MCP server registrations
- Access control policies (list, get, enable/disable, upsert)

It is **multi-tenant by design**: each request provides its own Barndoor credentials via HTTP headers.

---

## Architecture Overview

- **Protocol:** Model Context Protocol (MCP)
- **Transport:** Streamable HTTP
- **Framework:** FastMCP v3
- **Hosting:** DigitalOcean App Platform (or any ASGI-compatible host)
- **Auth model:** Per-request headers (no global credentials)

Client (Inspector / Claude / Agent)
        │
        │  MCP over Streamable HTTP
        │  + headers (token, org id)
        ▼
FastMCP Server (this repo)
        │
        │  REST API calls
        ▼
Barndoor Platform API

---

## Authentication & Multi-Tenancy

This server does **not** store credentials globally.

Each MCP request must include the following HTTP headers:

### Required Headers

| Header | Description |
|------|------------|
| X-Barndoor-Token | Barndoor bearer token or platform API key |
| X-Barndoor-Org-Id | Barndoor organization ID / slug |

### Optional Header

| Header | Description | Default |
|------|------------|---------|
| X-Barndoor-Base-Domain | Barndoor base domain | platform.barndoor.ai |

Because credentials are request-scoped:
- Multiple users can safely share one hosted MCP endpoint
- Different orgs and tokens remain fully isolated
- No session data leaks between users

---

## Project Structure

.
├── app.py        # ASGI entrypoint (CORS + MCP HTTP mounting)
├── server.py     # FastMCP server (tools + resources)
├── README.md

---

## Requirements

- Python 3.10+
- uv (recommended) or pip
- Barndoor account + API token

---

## Installation

Create a virtual environment:

uv venv
source .venv/bin/activate

Install dependencies:

uv pip install fastmcp httpx starlette uvicorn

---

## Running Locally

Start the MCP server:

uv run uvicorn app:app --host 0.0.0.0 --port 8000

Health check:

curl http://127.0.0.1:8000/health

The MCP endpoint is available at:

http://127.0.0.1:8000/mcp

---

## Using with MCP Inspector

Connect using Streamable HTTP to:

http://127.0.0.1:8000/mcp

Required headers:

X-Barndoor-Token: <your-barndoor-token>
X-Barndoor-Org-Id: <your-org-id>

Optional:

X-Barndoor-Base-Domain: platform.barndoor.ai

---

## Available Resources

- barndoor://org
- barndoor://agents
- barndoor://servers

---

## Available Tools

Agents:
- agents.list
- agents.get
- agents.register

Servers:
- servers.list
- servers.get

Policies:
- policies.list
- policies.list_all
- policies.get
- policies.upsert
- policies.enable
- policies.disable
- policies.validate_shape

---

## Deployment (DigitalOcean App Platform)

Run command:

uvicorn app:app --host 0.0.0.0 --port ${PORT}

---

## Security Notes

- Always use HTTPS in production
- Treat Barndoor tokens as secrets
- No persistent auth state is stored

---

## License

MIT
