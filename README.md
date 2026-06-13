# APS delegation layer for mcp-clickhouse

A runnable example of the delegation layer on top of the
`UserPassthroughMiddleware` sketch from
[ClickHouse/mcp-clickhouse#155](https://github.com/ClickHouse/mcp-clickhouse/issues/155).

The pass-through answers one question: who is connecting. It maps an
authenticated principal to a ClickHouse user, and native RBAC takes over from
there. That is the right answer for the case in the issue: humans with
accounts.

This adds the layer for the case the issue raises next: agents. An agent
acting for a user is not the user. Running it as the user hands it the user's
full grant. What an agent needs is a narrowed, time-bound subset, and a record
of what it was allowed to do that someone else can check later.

## What it adds

1. A scoped, time-bound delegation. The agent holds a signed grant for
   specific tools with an expiry. It cannot exceed that grant, and the
   ClickHouse session settings are derived from it (a read-only delegation
   runs with `readonly=1`).

2. A signed receipt per tool call. `query_log` records what ran, attributed
   to whoever connected. A receipt records what was authorized: the decision,
   the delegation it came from, signed at decision time and verifiable by a
   third party that does not trust the server. A denied call is recorded too:
   the refusal is as auditable as the approval.

These compose with the pass-through. They do not replace it.

## Run it

```
pip install agent-passport-system clickhouse-connect
```

A local ClickHouse is enough. Start one and point the demo at it with the
same password on both sides:

```
docker run -d --name ch -p 8123:8123 -e CLICKHOUSE_PASSWORD=demo clickhouse/clickhouse-server
export CLICKHOUSE_URL=http://localhost:8123 CLICKHOUSE_PASSWORD=demo
python examples/run_demo.py
python examples/tamper_demo.py
```

Connection is read from `CLICKHOUSE_URL`, `CLICKHOUSE_USER`, and
`CLICKHOUSE_PASSWORD`.

The demo issues a read-only delegation to an agent, dispatches four tool
calls, and writes one signed boundary receipt per call into ClickHouse:

```
[dispatch] agent runs four MCP tool calls:
  INSIDE  list_databases     receipt=...
  INSIDE  list_tables        receipt=...
  INSIDE  run_select_query   receipt=...
  OUTSIDE drop_table         receipt=...
          not run: denied: clickhouse:drop_table not in ['clickhouse:read']

[verify] 4/4 receipts verified against the store
```

The receipts live in a `aps_mcp_receipts` table next to `query_log`. They
verify by reading them back out of ClickHouse, so the store does not need to
be trusted: tamper a row and the signature stops matching.

## How it maps to the middleware

The middleware shape is unchanged from the maintainer's example. The function
flagged as deployment-specific, `lookup_clickhouse_credentials`, is where this
layer slots in:

- `src/delegation_resolver.py` resolves the principal's delegation (in a real
  deployment, from your system of record).
- `src/middleware.py` checks the tool against the delegation scope and derives
  the ClickHouse client overrides.
- The decision is recorded as an `AuthorityBoundaryReceipt`: `inside` for an
  authorized tool, `outside` for one the delegation never granted.

## What a receipt proves, and what it does not

A boundary receipt proves the tool was checked against the agent's delegated
authority, and that the record is intact and recomputable. It does not prove
the tool's runtime effect matched the request, and it asserts nothing about
the data the tool returned. That limit is written into every receipt's
`does_not_assert` field, on purpose.

Built on the [Agent Passport System](https://github.com/aeoess/agent-passport-system),
an open Apache 2.0 protocol for agent identity, scoped delegation, and signed
receipts.
