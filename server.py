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


@mcp.resource("barndoor://org")
async def resource_org() -> str:
    """
    Organization metadata: org ID and base domain.
    """
    headers = get_http_headers()
    org_id = _get_required_header(headers, "X-Barndoor-Org-Id")
    base_domain = headers.get("x-barndoor-base-domain") or headers.get("X-Barndoor-Base-Domain") or DEFAULT_BASE_DOMAIN
    return json.dumps({"organization_id": org_id, "base_domain": base_domain}, indent=2)


# ============================================================
# Prompts for common admin workflows
# ============================================================


@mcp.prompt()
async def audit_account_setup() -> str:
    """Audit the complete Barndoor account setup including servers, agents, and policies."""
    return """Please audit my Barndoor account setup and provide a comprehensive report:

1. List all registered MCP servers with their connection status
2. List all registered agents
3. For each server, show:
   - Server details (name, slug, URL, status)
   - All policies (server-level and agent-level)
   - Connection status
4. Identify any issues or recommendations:
   - Servers without policies
   - Disconnected servers
   - Agents without associated policies

Please format the report clearly with sections for each area."""


@mcp.prompt()
async def inspect_server_policies() -> List[Dict[str, str]]:
    """View all policies for a specific MCP server."""
    return [
        {
            "role": "user",
            "content": {
                "type": "text",
                "text": "Show me all policies for {{server_name}}",
                "annotations": {
                    "server_name": {
                        "type": "string",
                        "description": "Server name or slug (e.g., 'notion', 'salesforce')"
                    }
                }
            }
        }
    ]


@mcp.prompt()
async def create_server_policy() -> List[Dict[str, str]]:
    """Create a new server-level policy for an MCP server."""
    return [
        {
            "role": "user",
            "content": {
                "type": "text",
                "text": "I want to create a server-level policy for {{server_name}}",
                "annotations": {
                    "server_name": {
                        "type": "string",
                        "description": "Server name or slug (e.g., 'notion', 'salesforce')"
                    }
                }
            }
        }
    ]


@mcp.prompt()
async def create_agent_policy() -> List[Dict[str, str]]:
    """Create a new agent-level policy for a specific agent using an MCP server."""
    return [
        {
            "role": "user",
            "content": {
                "type": "text",
                "text": "I want to create an agent-level policy for {{agent_name}} using {{server_name}}",
                "annotations": {
                    "agent_name": {
                        "type": "string",
                        "description": "Agent name (e.g., 'Claude', 'MCP Inspector')"
                    },
                    "server_name": {
                        "type": "string",
                        "description": "Server name or slug (e.g., 'notion', 'salesforce')"
                    }
                }
            }
        }
    ]


@mcp.prompt()
async def troubleshoot_server_connection() -> List[Dict[str, str]]:
    """Troubleshoot connection issues with an MCP server."""
    return [
        {
            "role": "user",
            "content": {
                "type": "text",
                "text": "Help me troubleshoot connection issues with {{server_name}}",
                "annotations": {
                    "server_name": {
                        "type": "string",
                        "description": "Server name or slug having connection issues"
                    }
                }
            }
        }
    ]


@mcp.prompt()
async def compare_policies() -> List[Dict[str, str]]:
    """Compare policies across different servers or agents."""
    return [
        {
            "role": "user",
            "content": {
                "type": "text",
                "text": """Compare the policies for these servers/agents and highlight differences:
1. {{item1}}
2. {{item2}}

Show me what access controls differ between them.""",
                "annotations": {
                    "item1": {
                        "type": "string",
                        "description": "First server or agent name"
                    },
                    "item2": {
                        "type": "string",
                        "description": "Second server or agent name"
                    }
                }
            }
        }
    ]


# ============================================================
# Tools
#   - grouped by resource domain
#   - sorted alphabetically within each group
# ============================================================

# -------------------------
# Agents tools (alphabetical)
# -------------------------


@mcp.tool(name="agents-get")
async def agents_get(agent_id: str) -> Dict[str, Any]:
    """
    Fetch an agent by ID.
    
    Args:
        agent_id: Agent UUID (not name). Get this from agents-list tool.
    
    Example:
        agent = await agents_get(agent_id="8b38e2fb-aae3-4b73-ad64-c1eb6cf2fc3c")
    """
    return await bd_from_request().request("GET", f"/api/agents/{agent_id}")


@mcp.tool(name="agents-list")
async def agents_list() -> Dict[str, Any]:
    """
    List all agents registered in the Barndoor organization.
    
    Returns a list of agents with their IDs, names, descriptions, and metadata.
    Use the 'id' field (UUID) when referencing agents in other API calls.
    
    Example:
        agents = await agents_list()
        # agents['data'] contains the list of agent objects
    """
    return await bd_from_request().request("GET", "/api/agents")


# -------------------------
# Policies tools (alphabetical)
# -------------------------


@mcp.tool(name="policies-disable")
async def policies_disable(policy_id: str) -> Dict[str, Any]:
    """
    Disable a policy by ID without deleting it.
    
    Args:
        policy_id: Full policy ID (e.g., "resource.{server_id}.vdefault" or 
                   "resource.{server_id}.vdefault/{agent_id}")
    
    The policy will remain in the system but won't be enforced.
    Use policies-enable to re-activate it.
    
    Example:
        await policies_disable(
            policy_id="resource.4be99eff-7a6c-4bf2-93ac-ba35c80a8397.vdefault"
        )
    
    Endpoint: PUT /api/policy/disable?id=ENCODED_ID
    """
    encoded = urllib.parse.quote(policy_id, safe="")
    return await bd_from_request().request("PUT", f"/api/policy/disable?id={encoded}")


@mcp.tool(name="policies-enable")
async def policies_enable(policy_id: str) -> Dict[str, Any]:
    """
    Enable a previously disabled policy by ID.
    
    Args:
        policy_id: Full policy ID (e.g., "resource.{server_id}.vdefault" or 
                   "resource.{server_id}.vdefault/{agent_id}")
    
    Example:
        await policies_enable(
            policy_id="resource.4be99eff-7a6c-4bf2-93ac-ba35c80a8397.vdefault"
        )
    
    Endpoint: PUT /api/policy/enable?id=ENCODED_ID
    """
    encoded = urllib.parse.quote(policy_id, safe="")
    return await bd_from_request().request("PUT", f"/api/policy/enable?id={encoded}")


@mcp.tool(name="policies-get")
async def policies_get(policy_id: str) -> Dict[str, Any]:
    """
    Get a policy by its ID with human-readable metadata.
    
    This tool automatically enriches the policy response with server and agent names,
    making it easy to understand which servers and agents are involved without
    manually cross-referencing UUIDs.
    
    Policy IDs follow the pattern:
    - Server-level: "resource.{server_id}.v{version}"
    - Agent-level: "resource.{server_id}.v{version}/{agent_id}"
    
    Where:
    - {server_id} = Server UUID (from servers-list)
    - {version} = Typically "default"
    - {agent_id} = Agent UUID (from agents-list)
    
    Args:
        policy_id: Full policy ID. The tool handles URL encoding automatically.
    
    Returns:
        Dictionary with two keys:
        - "policy": The raw policy document from the Barndoor API
        - "metadata": Human-readable information including:
            - "server": {"id": "...", "name": "...", "slug": "..."}
            - "agents": {"agent-uuid": {"name": "...", "description": "..."}, ...}
    
    Example:
        # Get a server-level policy
        result = await policies_get(
            policy_id="resource.4be99eff-7a6c-4bf2-93ac-ba35c80a8397.vdefault"
        )
        # result["metadata"]["server"]["name"] == "Notion"
        
        # Get an agent-level policy
        result = await policies_get(
            policy_id="resource.4be99eff-7a6c-4bf2-93ac-ba35c80a8397.vdefault/8b38e2fb-aae3-4b73-ad64-c1eb6cf2fc3c"
        )
        # result["metadata"]["agents"]["8b38e2fb..."]["name"] == "Production Claude"
    
    Endpoint: GET /api/policy?id=ENCODED_ID (plus enrichment from /api/servers and /api/agents)
    """
    bd = bd_from_request()
    
    # 1. Fetch the raw policy document
    encoded = urllib.parse.quote(policy_id, safe="")
    policy_data = await bd.request("GET", f"/api/policy?id={encoded}")
    
    # 2. Parse policy_id to extract server UUID and optional agent UUID
    # Format: "resource.{server_uuid}.vdefault" or "resource.{server_uuid}.vdefault/{agent_uuid}"
    policy_id_clean = policy_id.replace("resource.", "")
    parts = policy_id_clean.split("/")
    
    # Extract server UUID from first part (e.g., "4be99eff-7a6c-4bf2-93ac-ba35c80a8397.vdefault")
    server_part = parts[0]
    server_uuid = server_part.split(".")[0]
    
    # 3. Collect all agent UUIDs we need to look up
    agent_uuids = set()
    
    # Check if policy_id contains an agent UUID (agent-level policy)
    if len(parts) > 1:
        agent_uuids.add(parts[1])
    
    # Also check the policy document for scope fields (agent-level policies)
    for policy in policy_data.get("policies", []):
        scope = policy.get("resourcePolicy", {}).get("scope")
        if scope:
            agent_uuids.add(scope)
    
    # 4. Fetch server and agent data in parallel for efficiency
    servers_response = await bd.request("GET", "/api/servers")
    agents_response = await bd.request("GET", "/api/agents")
    
    # 5. Build metadata with human-readable names
    metadata = {
        "server": None,
        "agents": {}
    }
    
    # Find the matching server
    for server in servers_response.get("data", []):
        if server["id"] == server_uuid:
            metadata["server"] = {
                "id": server["id"],
                "name": server["name"],
                "slug": server["slug"]
            }
            break
    
    # Find all matching agents
    for agent in agents_response.get("data", []):
        if agent["id"] in agent_uuids:
            app_dir = agent.get("application_directory", {})
            metadata["agents"][agent["id"]] = {
                "name": app_dir.get("name", "Unknown Agent"),
                "description": app_dir.get("description"),
                "application_directory_id": agent.get("application_directory_id"),
                "agent_type": agent.get("agent_type")
            }
    
    return {
        "policy": policy_data,
        "metadata": metadata
    }


@mcp.tool(name="policies-list")
async def policies_list(
    server_id: Optional[str] = None,
    agent_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    List policies filtered by server_id OR agent_id (provide exactly one).
    
    CRITICAL: server_id and agent_id must be UUIDs, NOT names/slugs!
    
    To get the correct server_id:
    1. Call servers-list first
    2. Find your server by name/slug in the results
    3. Use the 'id' field (UUID) from that server object
    
    Args:
        server_id: Server UUID (e.g., "4be99eff-7a6c-4bf2-93ac-ba35c80a8397")
                   NOT the server name/slug like "notion"
        agent_id: Agent UUID (e.g., "8b38e2fb-aae3-4b73-ad64-c1eb6cf2fc3c")
                  NOT the agent name
    
    Returns:
        Object with 'policyIds' array containing policy IDs for this server/agent
    
    Example - CORRECT usage:
        # Step 1: Get servers
        servers = await servers_list()
        
        # Step 2: Find Notion server and extract UUID
        notion_server = next(s for s in servers['data'] if s['slug'] == 'notion')
        server_uuid = notion_server['id']  # "4be99eff-7a6c-4bf2-93ac-ba35c80a8397"
        
        # Step 3: Use the UUID
        policies = await policies_list(server_id=server_uuid)
    
    Example - WRONG usage:
        # ❌ This will fail - "notion" is a name, not a UUID
        policies = await policies_list(server_id="notion")
    
    Endpoints:
      GET /api/policies?server_id=<UUID>
      GET /api/policies?agent_id=<UUID>
    """
    if bool(server_id) == bool(agent_id):
        raise ValueError("Provide exactly one of server_id or agent_id")

    if server_id:
        qs = f"server_id={urllib.parse.quote(server_id, safe='')}"
    else:
        qs = f"agent_id={urllib.parse.quote(agent_id or '', safe='')}"
    return await bd_from_request().request("GET", f"/api/policies?{qs}")

@mcp.tool(name="policies-upsert")
async def policies_upsert(policy_document: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create or update a policy document.
    
    Policies define what actions agents can perform on MCP servers.
    Each policy targets a specific server (resource) and optionally a specific agent (scope).
    
    CRITICAL STRUCTURE REQUIREMENTS:
    1. Top-level MUST have "policies" array
    2. Each policy MUST have "apiVersion": "api.cerbos.dev/v1"
    3. Each policy MUST have "resourcePolicy" object with:
       - "resource": server UUID (REQUIRED)
       - "version": typically "default" (REQUIRED)
       - "scope": agent UUID (OPTIONAL - omit for server-level policy)
       - "rules": array of access rules (OPTIONAL - omit for default deny)
    
    POLICY TYPES:
    - Server-level policy: Applies to ALL agents (no "scope" field)
    - Agent-scoped policy: Applies only to specific agent (includes "scope" field)
    
    ACTION FORMAT (MCP Convention):
    - Use "tools/call:{tool_name}" for tool permissions
    - Examples:
      * "*" = all actions (wildcard)
      * "tools/call:notion-search" = specific tool
      * "tools/call:chat_postMessage" = Slack message tool
    
    COMMON PATTERNS:
    
    1. Allow All (Main Toggle ON):
       {
         "name": "allow_all",
         "effect": "EFFECT_ALLOW",
         "actions": ["*"],
         "roles": ["*"]
       }
    
    2. Deny Specific Tool (after allow_all):
       {
         "name": "block_delete",
         "effect": "EFFECT_DENY",
         "actions": ["tools/call:delete_data"],
         "roles": ["*"]
       }
    
    3. Allow Only Specific Tools (Least Privilege):
       [
         {
           "name": "read_only",
           "effect": "EFFECT_ALLOW",
           "actions": ["tools/call:search", "tools/call:fetch"],
           "roles": ["*"]
         }
       ]
    
    Args:
        policy_document: Complete policy document as a dictionary with "policies" array
    
    Example 1 - Server-level policy (applies to ALL agents):
        policy_doc = {
            "policies": [{
                "apiVersion": "api.cerbos.dev/v1",  # REQUIRED
                "description": "Server-level access control",  # OPTIONAL
                "resourcePolicy": {
                    "resource": "4be99eff-7a6c-4bf2-93ac-ba35c80a8397",  # Server UUID - REQUIRED
                    "version": "default",  # REQUIRED
                    "rules": [  # OPTIONAL (omit for default deny)
                        {
                            "name": "allow_all",
                            "roles": ["*"],
                            "effect": "EFFECT_ALLOW",
                            "actions": ["*"]
                        }
                    ]
                }
            }]
        }
        result = await policies_upsert(policy_document=policy_doc)
    
    Example 2 - Agent-level policy (least privilege, read-only):
        policy_doc = {
            "policies": [{
                "apiVersion": "api.cerbos.dev/v1",  # REQUIRED
                "description": "Read-only Notion access for Claude",  # OPTIONAL
                "resourcePolicy": {
                    "resource": "4be99eff-7a6c-4bf2-93ac-ba35c80a8397",  # Server UUID - REQUIRED
                    "version": "default",  # REQUIRED
                    "scope": "8b38e2fb-aae3-4b73-ad64-c1eb6cf2fc3c",  # Agent UUID - makes it agent-specific
                    "rules": [
                        {
                            "name": "notion-search",
                            "roles": ["*"],
                            "effect": "EFFECT_ALLOW",
                            "actions": ["tools/call:notion-search"]
                        },
                        {
                            "name": "notion-fetch",
                            "roles": ["*"],
                            "effect": "EFFECT_ALLOW",
                            "actions": ["tools/call:notion-fetch"]
                        }
                    ]
                }
            }]
        }
        result = await policies_upsert(policy_document=policy_doc)
    
    Example 3 - Allow all except specific tools:
        policy_doc = {
            "policies": [{
                "apiVersion": "api.cerbos.dev/v1",
                "resourcePolicy": {
                    "resource": "4be99eff-7a6c-4bf2-93ac-ba35c80a8397",
                    "version": "default",
                    "scope": "8b38e2fb-aae3-4b73-ad64-c1eb6cf2fc3c",
                    "rules": [
                        {
                            "name": "allow_all",
                            "effect": "EFFECT_ALLOW",
                            "actions": ["*"],
                            "roles": ["*"]
                        },
                        {
                            "name": "block_delete",
                            "effect": "EFFECT_DENY",  # Deny takes precedence
                            "actions": ["tools/call:delete_page", "tools/call:delete_database"],
                            "roles": ["*"]
                        }
                    ]
                }
            }]
        }
    
    Example 4 - Default deny (no rules = no access):
        policy_doc = {
            "policies": [{
                "apiVersion": "api.cerbos.dev/v1",
                "resourcePolicy": {
                    "resource": "4be99eff-7a6c-4bf2-93ac-ba35c80a8397",
                    "version": "default"
                    # No rules = deny all access
                }
            }]
        }
    
    POLICY HIERARCHY:
    - Agent-scoped policies inherit from and override their parent server-level policy
    - If server-level allows all but agent policy has no rules, agent has no access
    - Evaluation order: agent-specific rules evaluated first, then server-level
    
    TIPS:
    - Use policies-validate-shape first to catch structural errors
    - Always retrieve existing policy with policies-get before modifying
    - Test changes with less critical agents first
    - Remember: apiVersion is REQUIRED (easy to forget!)
    
    Endpoint: POST /api/policy
    API Reference: https://docs.barndoor.ai/api-reference/policies/createPolicy
    """
    return await bd_from_request().request("POST", "/api/policy", json_body=policy_document)


@mcp.tool(name="policies-validate-shape")
async def policies_validate_shape(policy_document: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate a policy document structure before upserting.
    
    This performs lightweight safety checks to catch obvious issues like:
    - Missing "policies" array wrapper
    - Missing required fields (apiVersion, resource, version, resourcePolicy)
    - Empty or invalid field values
    - Incorrect data types
    
    NOTE: This does NOT validate Cerbos policy syntax or semantics.
    It only checks the outer document structure and required fields.
    
    Args:
        policy_document: The policy document to validate
    
    Returns:
        {"ok": True, "errors": []} if valid
        {"ok": False, "errors": ["error1", "error2"]} if invalid
    
    Example:
        validation = await policies_validate_shape(policy_document=my_policy)
        if validation['ok']:
            await policies_upsert(policy_document=my_policy)
        else:
            print(f"Errors: {validation['errors']}")
    """
    errors: List[str] = []

    if not isinstance(policy_document, dict):
        errors.append("policy_document must be an object")
        return {"ok": False, "errors": errors}

    # Check for top-level "policies" array
    if "policies" not in policy_document:
        errors.append("Missing required top-level field: 'policies' (must be an array)")
        return {"ok": False, "errors": errors}
    
    if not isinstance(policy_document["policies"], list):
        errors.append("'policies' must be an array")
        return {"ok": False, "errors": errors}
    
    if len(policy_document["policies"]) == 0:
        errors.append("'policies' array cannot be empty")
        return {"ok": False, "errors": errors}

    # Validate each policy in the array
    for idx, policy in enumerate(policy_document["policies"]):
        if not isinstance(policy, dict):
            errors.append(f"policies[{idx}] must be an object")
            continue
        
        # Check for required apiVersion field
        if "apiVersion" not in policy:
            errors.append(f"policies[{idx}] missing required field: apiVersion (must be 'api.cerbos.dev/v1')")
        elif policy["apiVersion"] != "api.cerbos.dev/v1":
            errors.append(f"policies[{idx}].apiVersion must be 'api.cerbos.dev/v1', got '{policy['apiVersion']}'")
            
        # Check for required resourcePolicy object
        if "resourcePolicy" not in policy:
            errors.append(f"policies[{idx}] missing required field: resourcePolicy")
        else:
            rp = policy["resourcePolicy"]
            if not isinstance(rp, dict):
                errors.append(f"policies[{idx}].resourcePolicy must be an object")
                continue
                
            # Check required fields in resourcePolicy
            if "resource" not in rp:
                errors.append(f"policies[{idx}].resourcePolicy missing required field: resource (server UUID)")
            elif not isinstance(rp["resource"], str) or not rp["resource"].strip():
                errors.append(f"policies[{idx}].resourcePolicy.resource must be a non-empty string (server UUID)")
                
            if "version" not in rp:
                errors.append(f"policies[{idx}].resourcePolicy missing required field: version (typically 'default')")
            elif not isinstance(rp["version"], str) or not rp["version"].strip():
                errors.append(f"policies[{idx}].resourcePolicy.version must be a non-empty string")

    return {"ok": len(errors) == 0, "errors": errors}


# -------------------------
# Servers tools (alphabetical)
# -------------------------


@mcp.tool(name="servers-get")
async def servers_get(server_id: str) -> Dict[str, Any]:
    """
    Fetch a server registration by ID.
    
    Args:
        server_id: Server UUID (not name/slug). Get this from servers-list tool.
    
    Example:
        server = await servers_get(server_id="4be99eff-7a6c-4bf2-93ac-ba35c80a8397")
    """
    return await bd_from_request().request("GET", f"/api/servers/{server_id}")


@mcp.tool(name="servers-list")
async def servers_list() -> Dict[str, Any]:
    """
    List all registered MCP servers in the Barndoor organization.
    
    Returns server details including:
    - id: Server UUID (use this for policy operations!)
    - name: Human-readable name
    - slug: Short identifier (e.g., "notion", "salesforce")
    - url: MCP server endpoint
    - connection_status: "connected", "error", "available"
    - And more...
    
    IMPORTANT: When working with policies, always use the 'id' field (UUID),
    never the 'name' or 'slug' field.
    
    Example:
        servers = await servers_list()
        for server in servers['data']:
            print(f"Server: {server['name']}")
            print(f"  UUID: {server['id']}")  # Use this for policies!
            print(f"  Slug: {server['slug']}")
            print(f"  Status: {server['connection_status']}")
    """
    return await bd_from_request().request("GET", "/api/servers")