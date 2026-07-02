# UAHP

UAHP is the identity, trust, and accountability layer for autonomous agents.

One repo, one command:

```bash
pip install -e .
uahp init      # create a local agent identity (Ed25519)
uahp status    # show the identity and key health
uahp verify    # prove the identity signs and verifies
uahp run       # start the UAHP MCP server on stdio
```

## What is in here

- `uahp/` core package: identity, mutual handshake, receipts, death
  certificates, reputation, EU AI Act compliance reports, A2A agent
  cards, MCP server, PQC session layer, tiered signing policy
- `uahp/schemas/` Pydantic v2 models for the whole stack
- `uahp/registry/` agent discovery and liveness (requires the
  `registry` extra)
- `uahp/transport/` protocol agnostic byte movement
- `polis/` civil standing and legal identity extension
- `csp/` portable semantic state extension (requires the `csp` extra)
- `tests/` the contract: crypto reality, cross process handshake,
  stack integration, extended edge cases, KEM flow

## Honest crypto status

Identity, handshake, receipts, and death certificates run on real
Ed25519 and X25519 today. ML-KEM-768 and ML-DSA-65 hybrid support is
implemented behind a tested feature flag and activates when liboqs and
liboqs-python are installed (`pip install -e ".[pqc]"`). No
quantum resistance claim is made for the classical path.

## Run the tests

```bash
python3 tests/test_crypto.py
python3 tests/test_two_process.py
python3 tests/test_stack.py
python3 tests/test_extended.py
python3 tests/test_kem_flow.py
```

License: MIT
