# Barndoor MCP Server (Prototype)

[!WARNING]
This is a prototype example app and not intended for production use.

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

## Authentication 

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

## Adding this server to Barndoor (MCePtion)

If you deploy this MCP server app to the cloud, you can add it as a custom
server on your Barndoor account. Yes, very meta. However, because this
MCP server is using API tokens that are passed in the header, you'll
need to supply a Barndoor API token and your tenant/org server slug as variables
(see above).

When adding this server, you'd choose Remote, provided the endpoint URL
where you're hosting it, choose Generic for auth method, and then
add `X-Barndoor-Token` and `X-Barndoor-Org-Id` as credential fields.
On the final step of the server config, you'll need to provide the
values for the both of these fields. You can create an API token from
the User menu on Barndoor.

`TODO: Directions for getting the tenant/org slug.`

Caveat: Anyone user on your Barndoor tenant that Connects to this server
will automatically connect (because it's a statically set APi token). You
will need to update the policies on the Barndoor MCP server tools 
accordingly. At this point, if you're confused, reach out to the
customer support team.

---

## Project Structure
```
.
├── app.py        # ASGI entrypoint (CORS + MCP HTTP mounting)
├── server.py     # FastMCP server (tools + resources)
```

---

## Requirements

- Python 3.10+
- uv (recommended) or pip
- Barndoor account + API token

---

## Installation

Create a virtual environment:
```bash
uv venv
source .venv/bin/activate
```

Install dependencies:
```bash
uv pip install -r requirements.txt
```
---

## Running Locally

Start the MCP server:

```bash
uv run uvicorn app:app --host 0.0.0.0 --port 8000
```

Health check:

```bash
curl http://127.0.0.1:8000/health
```

If running on local machine, the MCP endpoint is available at:

```
http://127.0.0.1:8000/mcp
```

---

## Using with MCP Inspector

Connect using Streamable HTTP to:

```
http://127.0.0.1:8000/mcp
```

Required headers:

```
X-Barndoor-Token: <your-barndoor-token>
X-Barndoor-Org-Id: <your-org-id>
```

Optional:
```
X-Barndoor-Base-Domain: platform.barndoor.ai
```
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
