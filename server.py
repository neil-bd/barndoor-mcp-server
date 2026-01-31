# server.py
"""
FastMCP server: Barndoor Account Manager (multi-tenant via request headers)

Required headers (per MCP request):
  - X-Barndoor-Token: Bearer token for Barndoor API
  - X-Barndoor-Org-Id: Barndoor org slug/id used in hostname

Optional headers:
  - X-Barndoor-Base-Domain: defaults to platform.barndoor.ai

Notes:
- This file defines the MCP server (tools/resources).
- For hosting (DigitalOcean App Platform, MCP Inspector), use app.py + uvicorn.
"""

import json
import urllib.parse
from typing import Any, Dict, List, Optional

import httpx
from fastmcp import FastMCP
from fastmcp.server.dependencies import get_http_headers

mcp = FastMCP("Barndoor Account Manager")

DEFAULT_BASE_DOMAIN = "platform.barndoor.ai"


# -------------------------
# Helpers / Client
# -------------------------


class BarndoorClient:
    """
    Minimal REST client for Barndoor.
    Uses org-scoped hostnames like:
      https://{organization_id}.platform.barndoor.ai/api/...
    """

    def __init__(self, org_id: str, token: str, base_domain: str = DEFAULT_BASE_DOMAIN) -> None:
        self.base_url = f"https://{org_id}.{base_domain}"
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    async def request(self, method: str, path: str, json_body: Any = None) -> Any:
        url = f"{self.base_url}{path}"
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.request(method, url, headers=self.headers, json=json_body)

        if r.status_code >= 400:
            raise RuntimeError(f"Barndoor API error {r.status_code}: {r.text}")

        ct = r.headers.get("content-type", "")
        return r.json() if ct.startswith("application/json") else r.text


def _get_required_header(headers: Dict[str, str], name: str) -> str:
    """
    Read a required header with a little tolerance for casing.
    FastMCP typically normalizes keys to lowercase, but we handle both.
    """
    v = headers.get(name.lower()) or headers.get(name)
    if not v:
        raise RuntimeError(f"Missing required header: {name}")
    return v


def bd_from_request() -> BarndoorClient:
    """
    Build a BarndoorClient from incoming MCP HTTP request headers.
    """
    headers = get_http_headers()

    token = _get_required_header(headers, "X-Barndoor-Token")
    org_id = _get_required_header(headers, "X-Barndoor-Org-Id")
    base_domain = headers.get("x-barndoor-base-domain") or headers.get("X-Barndoor-Base-Domain") or DEFAULT_BASE_DOMAIN

    return BarndoorClient(org_id=org_id, token=token, base_domain=base_domain)


# ============================================================
# Resources (sorted alphabetically)
# ============================================================


@mcp.resource("barndoor://agents")
async def resource_agents() -> str:
    data = await bd_from_request().request("GET", "/api/agents")
    return json.dumps(data, indent=2)


@mcp.resource("barndoor://org")
async def resource_org() -> str:
    headers = get_http_headers()
    org_id = _get_required_header(headers, "X-Barndoor-Org-Id")
    base_domain = headers.get("x-barndoor-base-domain") or headers.get("X-Barndoor-Base-Domain") or DEFAULT_BASE_DOMAIN
    return json.dumps({"organization_id": org_id, "base_domain": base_domain}, indent=2)


@mcp.resource("barndoor://servers")
async def resource_servers() -> str:
    data = await bd_from_request().request("GET", "/api/servers")
    return json.dumps(data, indent=2)


# ============================================================
# Tools
#   - grouped by resource domain
#   - sorted alphabetically within each group
# ============================================================

# -------------------------
# Agents tools (alphabetical)
# -------------------------


@mcp.tool(name="agents.get")
async def agents_get(agent_id: str) -> Dict[str, Any]:
    """Fetch an agent by ID."""
    return await bd_from_request().request("GET", f"/api/agents/{agent_id}")


@mcp.tool(name="agents.list")
async def agents_list() -> Dict[str, Any]:
    """List agents registered in the specified Barndoor org."""
    return await bd_from_request().request("GET", "/api/agents")


@mcp.tool(name="agents.register")
async def agents_register(
    name: str,
    application_directory_id: Optional[str] = None,
    description: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Register a new agent in Barndoor."""
    body: Dict[str, Any] = {"name": name}
    if application_directory_id:
        body["applicationDirectoryId"] = application_directory_id
    if description:
        body["description"] = description
    if metadata:
        body["metadata"] = metadata
    return await bd_from_request().request("POST", "/api/agents", json_body=body)


# -------------------------
# Policies tools (alphabetical)
# -------------------------


@mcp.tool(name="policies.disable")
async def policies_disable(policy_id: str) -> Dict[str, Any]:
    """
    Disable a policy by ID.
    Endpoint: PUT /api/policy/disable?id=ENCODED_ID
    """
    encoded = urllib.parse.quote(policy_id, safe="")
    return await bd_from_request().request("PUT", f"/api/policy/disable?id={encoded}")


@mcp.tool(name="policies.enable")
async def policies_enable(policy_id: str) -> Dict[str, Any]:
    """
    Enable a policy by ID.
    Endpoint: PUT /api/policy/enable?id=ENCODED_ID
    """
    encoded = urllib.parse.quote(policy_id, safe="")
    return await bd_from_request().request("PUT", f"/api/policy/enable?id={encoded}")


@mcp.tool(name="policies.get")
async def policies_get(policy_id: str) -> Dict[str, Any]:
    """
    Get a policy by its ID.
    IMPORTANT: policy_id often contains '/', so we URL-encode it.
    Endpoint: GET /api/policy?id=ENCODED_ID
    """
    encoded = urllib.parse.quote(policy_id, safe="")
    return await bd_from_request().request("GET", f"/api/policy?id={encoded}")


@mcp.tool(name="policies.list")
async def policies_list(
    server_id: Optional[str] = None,
    agent_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    List policies filtered by server_id or agent_id.
    Endpoints:
      GET /api/policies?server_id=...
      GET /api/policies?agent_id=...
    """
    if bool(server_id) == bool(agent_id):
        raise ValueError("Provide exactly one of server_id or agent_id")

    if server_id:
        qs = f"server_id={urllib.parse.quote(server_id, safe='')}"
    else:
        qs = f"agent_id={urllib.parse.quote(agent_id or '', safe='')}"
    return await bd_from_request().request("GET", f"/api/policies?{qs}")


@mcp.tool(name="policies.list_all")
async def policies_list_all() -> Dict[str, Any]:
    """
    Best-effort: list policies with no filter.
    If Barndoor requires server_id/agent_id, this will error and you should use policies.list.
    """
    return await bd_from_request().request("GET", "/api/policies")


@mcp.tool(name="policies.upsert")
async def policies_upsert(policy_document: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create or update a policy document (raw).
    Endpoint: POST /api/policy
    """
    return await bd_from_request().request("POST", "/api/policy", json_body=policy_document)


@mcp.tool(name="policies.validate_shape")
async def policies_validate_shape(policy_document: Dict[str, Any]) -> Dict[str, Any]:
    """
    Lightweight safety checks so the LLM doesn’t accidentally send nonsense.
    This does NOT guarantee the policy is correct; it just catches obvious issues.
    """
    errors: List[str] = []

    if not isinstance(policy_document, dict):
        errors.append("policy_document must be an object")
        return {"ok": False, "errors": errors}

    # Barndoor policy docs: targets a specific server (resource) and optionally an agent (scope).
    if "resource" not in policy_document:
        errors.append("Missing required field: resource (server id)")

    if "scope" in policy_document and not policy_document["scope"]:
        errors.append("scope is present but empty")

    return {"ok": len(errors) == 0, "errors": errors}


# -------------------------
# Servers tools (alphabetical)
# -------------------------


@mcp.tool(name="servers.get")
async def servers_get(server_id: str) -> Dict[str, Any]:
    """Fetch a server registration by id."""
    return await bd_from_request().request("GET", f"/api/servers/{server_id}")


@mcp.tool(name="servers.list")
async def servers_list() -> Dict[str, Any]:
    """List all registered MCP servers in the specified Barndoor org."""
    return await bd_from_request().request("GET", "/api/servers")