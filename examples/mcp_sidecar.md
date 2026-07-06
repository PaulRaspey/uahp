# Give an MCP-based agent a UAHP identity without rewriting it

Do not rewrite your agent. Run the sidecar.

If your agent already lives in an MCP client (Claude Desktop, Claude Code,
or any MCP-compatible runtime), UAHP ships as an MCP server you add to the
client's configuration. Your agent gains identity, handshakes, signed
receipts, trust scoring, and death certificates as tools it can call. No
changes to the agent itself.

## One command

```bash
uahp run
```

That starts the UAHP MCP server on stdio, speaking JSON-RPC 2.0. Register
it in your MCP client configuration:

```json
{
  "mcpServers": {
    "uahp": {
      "command": "uahp",
      "args": ["run"]
    }
  }
}
```

## The 10 tools your agent gets

| Tool | What it does |
|---|---|
| `uahp_create_identity` | Create an Ed25519 identity. `agent_id = sha256(public key)` |
| `uahp_handshake` | Mutual 3-message authentication between two agents |
| `uahp_liveness_check` | Is this agent alive (exists and not revoked)? |
| `uahp_declare_death` | Issue an irreversible death certificate |
| `uahp_create_receipt` | Sign a chain-hashed completion receipt |
| `uahp_get_receipts` | Fetch an agent's receipt history |
| `uahp_trust_score` | Compute a trust profile from receipts |
| `uahp_compliance_report` | Generate an EU AI Act style compliance report |
| `uahp_agent_card` | Emit a UAHP-enriched A2A Agent Card |
| `uahp_list_agents` | List agents created through this server, with liveness |

## Typical flow inside the agent

1. `uahp_create_identity` once, at startup. Keep the returned `agent_id`.
2. `uahp_create_receipt` after each unit of work. Receipts are signed and
   chain-hashed, so the history is tamper-evident.
3. `uahp_trust_score` or `uahp_compliance_report` whenever a counterparty
   asks for proof.
4. `uahp_declare_death` when the agent retires. After that, every UAHP
   peer refuses its signatures, receipts, and handshakes.

## HTTP agents instead

If your agent is reachable over HTTP rather than MCP, use the HTTP sidecar
in this same directory. It wraps any HTTP endpoint with the full UAHP
surface (identity, handshake, encrypted record channel, signed receipts)
in five lines:

```python
from http_sidecar import UAHPSidecar

sidecar = UAHPSidecar(upstream="http://127.0.0.1:8131", name="my-agent")
sidecar.serve(port=8130)
```

See `examples/http_sidecar.py`. Run it directly for a full end-to-end
demonstration against a dummy upstream agent:

```bash
python3 examples/http_sidecar.py
```
