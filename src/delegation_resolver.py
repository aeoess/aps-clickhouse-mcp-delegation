"""
Delegation-aware credential resolution for the mcp-clickhouse pass-through.

This is the delegation layer that sits in the slot joe-clickhouse flagged as
"specific to your setup" in the UserPassthroughMiddleware sketch: the
lookup_clickhouse_credentials function.

The pass-through maps an authenticated principal to a static ClickHouse
username and password. That gives per-user identity, which native RBAC then
enforces. This layer adds two things the static mapping cannot:

1. A narrowed, time-bound grant. An agent acting for a user is not the user.
   Instead of handing the agent the user's full RBAC identity, we resolve an
   APS delegation: a signed grant scoped to specific tools, with an expiry,
   that the agent cannot exceed. The ClickHouse settings we return are derived
   from that delegation, not from the user's full account.

2. A signed receipt per tool call. query_log records what ran, attributed to
   whoever connected. A policy receipt records what was authorized: who
   delegated, what scope, what was decided, signed at decision time and
   verifiable by a third party that does not trust the server.

Nothing here replaces the pass-through. It composes with it: the pass-through
answers "who is connecting", this answers "what were they allowed to do, and
can someone prove it later."
"""

from __future__ import annotations
from typing import Optional
import agent_passport as ap


class DelegationStore:
    """
    Minimal in-memory delegation store for the example. In a real deployment
    this is your existing system of record: delegations issued when an agent
    is dispatched on a user's behalf, keyed by the principal in the token.
    """

    def __init__(self) -> None:
        self._by_principal: dict[str, dict] = {}
        self._keys: dict[str, str] = {}
        self._registry: dict = {"agents": {}}

    def issue(
        self,
        principal_id: str,
        principal_private_key: str,
        agent_id: str,
        agent_public_key: str,
        scope: list[str],
        expires_in_days: int = 1,
    ) -> dict:
        """Issue a scoped, time-bound delegation from a principal to an agent."""
        self._registry = ap.register_agent(
            self._registry,
            {"id": agent_id, "public_key": agent_public_key},
        )
        delegation = ap.create_delegation(
            delegated_by=principal_id,
            delegated_to=agent_id,
            scope=scope,
            private_key=principal_private_key,
            expires_in_days=expires_in_days,
        )
        self._by_principal[principal_id] = delegation
        return delegation

    def resolve(self, principal_id: str) -> Optional[dict]:
        return self._by_principal.get(principal_id)
