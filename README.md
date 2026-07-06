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

## Run the reference demo

```bash
pip install -e ".[registry]"
python3 demos/run_demo.py
```

Three real OS processes: a registry and two agents. Alice discovers
Bob, they complete a mutual Ed25519 handshake, exchange signed
receipts, then Bob issues his own death certificate and every later
signature from him is rejected live.

Verify any running agent's compliance:

```bash
uahp verify http://127.0.0.1:8100
```

## Run the tests

```bash
python3 tests/test_crypto.py
python3 tests/test_two_process.py
python3 tests/test_stack.py
python3 tests/test_extended.py
python3 tests/test_kem_flow.py
```

## Reproducibility

What has actually executed on a development machine, end to end: the
editable pip install, the CLI (`uahp init/status/verify/run`), all
five test suites, the three process reference demo above, and the
compliance verifier against both a compliant and a deliberately broken
agent. The ML-KEM-768 hybrid path has run for real with liboqs
installed (13 of 13 passing, equal shared secrets).

`docker-compose.yml` and the `Dockerfile` describe the same topology
as the reference demo (registry plus two agent nodes) and use the same
entrypoint, but they have not yet been executed here because Docker is
not installed on this machine. The validated path is `pip install`
plus `python3 demos/run_demo.py`; compose is provided as a
topology-matched convenience.

License: MIT
