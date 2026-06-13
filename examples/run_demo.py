"""
Runnable demo: the delegation layer on the mcp-clickhouse pass-through.

Maps to ClickHouse/mcp-clickhouse#155. The pass-through middleware answers
"who is connecting". This layer answers "what was the agent allowed to do,
and can a third party prove it later".

Each simulated MCP tool call is checked against the agent's APS delegation.
The decision is recorded as an AuthorityBoundaryReceipt: result 'inside' for
an authorized tool, 'outside' for one the delegation never granted. Every
receipt is signed, written to ClickHouse next to where query_log lives, and
re-verified straight out of the store.

Run:
    pip install agent-passport-system clickhouse-connect
    python examples/run_demo.py

ClickHouse connection from env (CLICKHOUSE_URL / CLICKHOUSE_USER /
CLICKHOUSE_PASSWORD), defaults to http://localhost:8123.
"""

from __future__ import annotations
import os, sys, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import agent_passport as ap
from agent_passport.v2.accountability.types import ScopeOfClaim
import clickhouse_connect
from clickhouse_connect.driver.exceptions import DatabaseError

from delegation_resolver import DelegationStore
from middleware import decide, clickhouse_overrides_from_delegation


def ch_client():
    url = os.environ.get("CLICKHOUSE_URL", "http://localhost:8123")
    secure = url.startswith("https")
    rest = url.split("://", 1)[1]
    host = rest.split(":")[0]
    port = int(rest.rsplit(":", 1)[1]) if ":" in rest else (8443 if secure else 8123)
    try:
        return clickhouse_connect.get_client(
            host=host, port=port, secure=secure,
            username=os.environ.get("CLICKHOUSE_USER", "default"),
            password=os.environ.get("CLICKHOUSE_PASSWORD", ""),
        )
    except DatabaseError as e:
        msg = str(e)
        if "REQUIRED_PASSWORD" in msg or "Authentication failed" in msg or "code: 194" in msg:
            print(
                "[error] ClickHouse rejected the connection: authentication failed. "
                "Set CLICKHOUSE_PASSWORD (and CLICKHOUSE_USER if your server needs it) "
                "to match your server, then rerun. See the README 'Run it' section for "
                "the exact docker and env setup.",
                file=sys.stderr,
            )
            raise SystemExit(1)
        raise


def setup_schema(client):
    client.command("DROP TABLE IF EXISTS aps_mcp_receipts")
    client.command("""
        CREATE TABLE aps_mcp_receipts (
            receipt_id String,
            action_id String,
            tool String,
            result Enum('inside'=1,'outside'=2,'indeterminate'=3),
            delegation_chain_root String,
            evaluator_did String,
            timestamp String,
            receipt_json String
        ) ENGINE = MergeTree ORDER BY (tool, timestamp)
    """)


def make_boundary_receipt(tool, result, detail, root, evaluator_did, evaluator_priv):
    scope_claim = ScopeOfClaim(
        asserts=f"tool '{tool}' was checked against the agent's delegation scope",
        does_not_assert=[
            "that the tool's runtime effect matched the request",
            "anything about data the tool returned",
        ],
        capture_mode="self_attested",
        completeness="complete",
        self_attested=True,
    )
    return ap.create_authority_boundary_receipt(
        scope_of_claim=scope_claim,
        action_id=f"act_{tool}",
        evaluator_did=evaluator_did,
        delegation_chain_root=root,
        result=result,
        result_detail=detail,
        evaluator_private_key=evaluator_priv,
    )


def main():
    # The human principal and the agent acting on their behalf.
    principal = ap.create_principal_identity(display_name="data-analyst-user")
    p_priv = principal["keyPair"]["privateKey"]
    p_pub = principal["keyPair"]["publicKey"]
    agent = ap.generate_key_pair()
    agent_id = "agent:mcp-clickhouse-worker"

    # The evaluator (the middleware) signs the boundary decisions.
    evaluator = ap.generate_key_pair()
    evaluator_did = "did:key:z" + evaluator["publicKey"][:24]

    # Issue a read-only, one-day delegation. The agent is not the user; it
    # holds a narrowed, time-bound grant it cannot exceed.
    store = DelegationStore()
    delegation = store.issue(
        principal_id=p_pub,            # delegatedBy is the signing public key
        principal_private_key=p_priv,
        agent_id=agent_id,
        agent_public_key=agent["publicKey"],
        scope=["clickhouse:read"],
        expires_in_days=1,
    )
    root = delegation["delegationId"]
    print(f"[setup] agent {agent_id} holds delegation {root}")
    print(f"[setup] scope={delegation['scope']} (read only), expires in 1 day\n")

    # The same delegation derives the ClickHouse session settings the agent
    # would run its own queries under. A read-only delegation narrows the
    # session to readonly=1, so the database enforces the same limit the
    # receipt records.
    agent_overrides = clickhouse_overrides_from_delegation(delegation, base_user="default")
    print(f"[derive] agent ClickHouse session from delegation: {agent_overrides.get('settings', {})}\n")

    client = ch_client()
    setup_schema(client)

    # A dispatch sequence: three read tools the agent may use, then a
    # destructive tool it was never delegated.
    calls = [
        ("list_databases", None),
        ("list_tables", None),
        ("run_select_query", "SELECT count() FROM system.tables"),
        ("drop_table", "DROP TABLE important_data"),
    ]

    print("[dispatch] agent runs four MCP tool calls:")
    for tool, query in calls:
        permitted, required, reason = decide(delegation, tool)
        result = "inside" if permitted else "outside"
        detail = (
            f"authorized: {required} in delegation scope"
            if permitted
            else f"denied: {required} not in {delegation['scope']} ({reason})"
        )
        receipt = make_boundary_receipt(
            tool, result, detail, root, evaluator_did, evaluator["privateKey"]
        )
        rc = receipt.to_canonical_dict()
        client.insert(
            "aps_mcp_receipts",
            [[
                receipt.receipt_id,
                receipt.action_id,
                tool,
                result,
                root,
                evaluator_did,
                receipt.timestamp,
                json.dumps(rc),
            ]],
            column_names=[
                "receipt_id", "action_id", "tool", "result",
                "delegation_chain_root", "evaluator_did", "timestamp", "receipt_json",
            ],
        )
        mark = "INSIDE " if permitted else "OUTSIDE"
        print(f"  {mark} {tool:18s} receipt={receipt.receipt_id[:20]}")
        if not permitted:
            print(f"          not run: {detail}")

    # Re-verify every receipt straight out of ClickHouse.
    print("\n[verify] reading receipts back from ClickHouse and checking signatures:")
    rows = client.query(
        "SELECT receipt_id, tool, result, receipt_json FROM aps_mcp_receipts ORDER BY timestamp"
    ).result_rows
    ok = 0
    for rid, tool, result, rjson in rows:
        rc = json.loads(rjson)
        sc = rc["scope_of_claim"]
        rebuilt = ap.AuthorityBoundaryReceipt(
            claim_type=rc["claim_type"],
            receipt_id=rc["receipt_id"],
            timestamp=rc["timestamp"],
            signer_did=rc["signer_did"],
            scope_of_claim=ScopeOfClaim(
                asserts=sc["asserts"],
                does_not_assert=sc["does_not_assert"],
                capture_mode=sc["capture_mode"],
                completeness=sc["completeness"],
                self_attested=sc["self_attested"],
            ),
            action_id=rc["action_id"],
            evaluator_did=rc["evaluator_did"],
            delegation_chain_root=rc["delegation_chain_root"],
            result=rc["result"],
            signature=rc["signature"],
            result_detail=rc.get("result_detail"),
        )
        verdict = ap.verify_authority_boundary_receipt(rebuilt)
        valid = verdict.get("valid")
        ok += 1 if valid else 0
        print(f"  {'PASS' if valid else 'FAIL'} {tool:18s} result={result}")
    print(f"\n[verify] {ok}/{len(rows)} receipts verified against the store")
    print("[done] every tool call left a signed boundary receipt; the denied call is as auditable as the permitted ones")


if __name__ == "__main__":
    main()
