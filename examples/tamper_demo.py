"""
Tamper demo: the receipts store does not need to be trusted.

Run examples/run_demo.py first so the table has receipts. This script edits a
receipt row inside ClickHouse (the kind of change a compromised database or a
malicious insider could make), then re-verifies. The signature no longer
matches the altered row, and verification catches it.

    python examples/tamper_demo.py
"""

from __future__ import annotations
import os, sys, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import agent_passport as ap
from agent_passport.v2.accountability.types import ScopeOfClaim
import clickhouse_connect
from clickhouse_connect.driver.exceptions import DatabaseError


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


def rebuild(rc):
    sc = rc["scope_of_claim"]
    return ap.AuthorityBoundaryReceipt(
        claim_type=rc["claim_type"], receipt_id=rc["receipt_id"],
        timestamp=rc["timestamp"], signer_did=rc["signer_did"],
        scope_of_claim=ScopeOfClaim(
            asserts=sc["asserts"], does_not_assert=sc["does_not_assert"],
            capture_mode=sc["capture_mode"], completeness=sc["completeness"],
            self_attested=sc["self_attested"]),
        action_id=rc["action_id"], evaluator_did=rc["evaluator_did"],
        delegation_chain_root=rc["delegation_chain_root"], result=rc["result"],
        signature=rc["signature"], result_detail=rc.get("result_detail"))


def main():
    client = ch_client()
    rows = client.query(
        "SELECT receipt_id, tool, result, receipt_json FROM aps_mcp_receipts WHERE result='outside' LIMIT 1"
    ).result_rows
    if not rows:
        print("No receipts found. Run examples/run_demo.py first.")
        return
    rid, tool, result, rjson = rows[0]
    rc = json.loads(rjson)

    print(f"[target] receipt {rid[:20]} for tool '{tool}', result '{result}'")
    print("[before] verifies:", ap.verify_authority_boundary_receipt(rebuild(rc))["valid"])

    # Flip the denied call to look authorized, the way an attacker would.
    print("\n[tamper] rewriting result 'outside' -> 'inside' inside ClickHouse")
    tampered = dict(rc)
    tampered["result"] = "inside"
    client.command(
        "ALTER TABLE aps_mcp_receipts UPDATE result='inside', receipt_json=%(j)s WHERE receipt_id=%(r)s",
        parameters={"j": json.dumps(tampered), "r": rid},
    )
    # ClickHouse mutations are async; wait for it to land.
    import time
    for _ in range(20):
        again = client.query(
            "SELECT receipt_json FROM aps_mcp_receipts WHERE receipt_id=%(r)s",
            parameters={"r": rid},
        ).result_rows
        if again and json.loads(again[0][0])["result"] == "inside":
            break
        time.sleep(0.3)

    stored = json.loads(client.query(
        "SELECT receipt_json FROM aps_mcp_receipts WHERE receipt_id=%(r)s",
        parameters={"r": rid}).result_rows[0][0])
    verdict = ap.verify_authority_boundary_receipt(rebuild(stored))
    print("[after]  stored row now says result:", stored["result"])
    print("[after]  verifies:", verdict["valid"], "| reason:", verdict.get("reason"))
    print("\n[done] the altered row fails verification. The signature is over the")
    print("       original decision, so changing the stored result breaks it.")


if __name__ == "__main__":
    main()
