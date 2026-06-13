"""
Delegation layer on top of joe-clickhouse's UserPassthroughMiddleware sketch
(ClickHouse/mcp-clickhouse#155).

The middleware shape is unchanged from the maintainer's example. The function
he flagged as deployment-specific, the credential lookup, is where the APS
delegation layer slots in. On every tool call we:

  1. resolve the authenticated principal (same as the pass-through),
  2. resolve that principal's APS delegation and check the tool against its
     scope: out of scope is denied before the call runs,
  3. derive the ClickHouse client overrides from the delegation,
  4. record a signed artifact for the decision. A permit produces a signed
     action receipt (the agent did something it was authorized to do). A deny
     produces a signed decision recording the refusal. The protocol will not
     manufacture an authorization receipt for an action it denied.

The artifact is what makes the call auditable: it lives in a receipts table
next to query_log and verifies offline.
"""

from __future__ import annotations
import agent_passport as ap

# In the real server these come from:
#   from fastmcp.server.dependencies import get_context, get_access_token
#   from fastmcp.server.middleware import Middleware, MiddlewareContext, CallNext
#   from mcp_clickhouse.mcp_server import CLIENT_CONFIG_OVERRIDES_KEY
# The example provides a runnable harness in examples/run_demo.py that does
# not need a live server, so the decision logic can be exercised directly.

READ_TOOLS = {"list_databases", "list_tables", "run_select_query"}


def tool_to_scope(tool_name: str) -> str:
    """Map an MCP tool to the APS scope token it requires."""
    if tool_name in READ_TOOLS:
        return "clickhouse:read"
    return f"clickhouse:{tool_name}"


def decide(delegation: dict, tool_name: str):
    """
    The authorization decision. The delegation is the policy: a tool is
    permitted only if the delegation's scope authorizes it and the delegation
    has not expired. Returns (permitted: bool, required_scope: str, reason).
    """
    required = tool_to_scope(tool_name)
    in_scope = ap.scope_authorizes(delegation.get("scope", []), required)
    expired = ap.is_expired(delegation)
    permitted = in_scope and not expired
    if permitted:
        reason = "in_scope"
    elif expired:
        reason = "delegation_expired"
    else:
        reason = "scope_not_authorized"
    return permitted, required, reason


def clickhouse_overrides_from_delegation(delegation: dict, base_user: str) -> dict:
    """
    Derive ClickHouse client config overrides from the delegation. The
    pass-through sets username and password; we additionally constrain a
    read-scoped delegation with readonly and a statement timeout, so the
    database enforces the same narrowing the receipt records.
    """
    scope = delegation.get("scope", [])
    read_only = bool(scope) and all(s == "clickhouse:read" for s in scope)
    overrides = {"username": base_user}
    if read_only:
        overrides["settings"] = {"readonly": 1, "max_execution_time": 30}
    return overrides
