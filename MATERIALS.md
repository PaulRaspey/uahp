# MATERIALS for the flagship README

Raw material only. Every claim below has executed on the development
machine (macOS 12 Intel, Python 3.9) unless marked otherwise. The
final README prose gets drafted in chat and placed afterward.

## One-line positioning

UAHP is the identity, trust, and accountability layer for autonomous
agents: verifiable identity, mutual authentication, signed proof of
work, and irreversible retirement, all on real cryptography.

## Package layout

```
uahp/                the core package
  core.py            identity, handshake, receipts, death certificates
  reputation.py      trust scoring from receipt history
  compliance.py      EU AI Act style compliance reports
  a2a.py             A2A agent cards and death events
  mcp_server.py      MCP server (10 tools, JSON-RPC 2.0 over stdio)
  verifier.py        live compliance verifier behind `uahp verify`
  cli.py             uahp init / status / verify / run
  pqc.py             hybrid PQC session layer (ML-KEM-768, ML-DSA)
  signing_policy.py  tiered signing policy
  schemas/           Pydantic v2 models (registry, pqc)
  registry/          FastAPI discovery and liveness service
  transport/         protocol agnostic byte movement
polis/               civil standing and legal identity extension
csp/                 portable semantic state extension
demos/               agent_node.py, run_demo.py, broken_agent.py, compose entrypoints
tests/               five suites, all green
```

## Protocol message flow (the mutual handshake)

Three messages, both sides authenticated, works across processes:

```
A: m1 = handshake_init(alice, bob_public)      Ed25519 signed, fresh nonce,
                                               ephemeral X25519 public key
        --- m1 --->
B: m2 = handshake_respond(bob, m1)             verifies A's signature, answers
                                               with its own nonce and ephemeral
                                               key, signs the transcript hash
        <--- m2 ---
A: m3 = handshake_finalize(alice, m2)          verifies B's signature, derives
                                               the shared secret
        --- m3 --->
B: handshake_complete(bob, m3)                 both sides now hold the same
                                               session token and secret
```

Shared secret: ephemeral X25519 exchange, HKDF-SHA256 keyed by the
transcript hash. Replay protection: nonce cache, timestamps with a
clock skew window, sequence numbered receipts. Revocation: a death
certificate is the agent's final signature; afterward the private key
is destroyed, new handshakes with that agent_id are refused, and any
signature timestamped after the certificate is rejected by verifiers.

## Identity model

An agent identity is an Ed25519 keypair. agent_id is canonical
everywhere (core, schemas, wire formats, MCP tools). Public identity
is `{agent_id, public_key, created_at, protocol_version, metadata}`.
The CLI identity at ~/.uahp/identity.json uses
agent_id = sha256(public key bytes).

## Quickstart commands (all verified working)

```bash
pip install -e .
uahp init      # create a local agent identity (Ed25519)
uahp status    # show the identity and key health
uahp verify    # prove the identity signs and verifies
uahp run       # start the UAHP MCP server on stdio
```

## The reference demo (verified working, 2.2s full speed)

```bash
pip install -e ".[registry]"
python3 demos/run_demo.py           # DEMO_PACE=8 to slow it for video
```

Three real OS processes: registry, bob (responder), alice (initiator).
Four acts: mutual handshake (signatures verified both directions,
shared secret digests match), signed receipt exchange (each side
verifies the other), bob issues his own death certificate and destroys
his key, then the live rejection: bob refuses to sign, alice rejects
post-death material and refuses a new handshake with the dead agent.
Captured output: demos/demo_output.txt.

## The compliance verifier (verified working)

```bash
uahp verify http://127.0.0.1:8100
```

Probes a running agent and prints PASS or FAIL per requirement:
real Ed25519 identity (challenge signatures that verify and bind),
mutual handshake, receipts verified both directions with tampered
receipts rejected, replay refusal, honest crypto_mode declaration,
revocation honored post death. Reference agent: 6 of 6 PASS.
demos/broken_agent.py (HMAC pseudo-signatures, accepts everything,
claims hybrid PQC, ignores its own death): 6 of 6 correct FAILs.
The revocation check is destructive by design.

## Test evidence (all green on this machine)

```
tests/test_crypto.py        33 passed   includes test_revocation_rejects_post_death
tests/test_two_process.py   mutual handshake across two OS processes, same secret
tests/test_stack.py         identity -> receipts -> reputation -> compliance -> A2A -> death -> MCP
tests/test_extended.py      edge cases, reputation consistency window, death blocks trust
tests/test_kem_flow.py      13 passed with REAL ML-KEM-768 (liboqs installed)
```

## Honest security status

- Ed25519 signatures and X25519+HKDF key agreement run everywhere
  today. This is the classical path and it makes no quantum claim.
- ML-KEM-768 and ML-DSA hybrid support is implemented behind a tested
  feature flag and activates when liboqs and liboqs-python are
  installed. On this machine the real hybrid path has run: equal
  shared secrets, 13 of 13 tests passing.
- crypto_mode is declared explicitly in packets and identities. The
  verifier fails any agent that claims hybrid while serving a
  classical handshake.
- Python cannot guarantee memory zeroization; revocation drops the
  only key reference and relies on protocol level enforcement.
- Not yet done: external security audit, formal RFC suite.

## Docker status (do not overclaim)

Dockerfile and docker-compose.yml (registry plus two agent nodes)
match the reference demo topology and entrypoint exactly, but Docker
is not installed on the development machine, so the compose path has
not executed here. The validated path is pip install plus
demos/run_demo.py.

## Extension packages

- polis: civil standing and legal identity (employment certificates,
  standing scores). polis/demo.py runs unmodified from its source repo.
- csp: portable semantic state (requires the csp extra).
- registry: FastAPI discovery service with liveness, heartbeats, death
  certificates, and thermodynamic load hints (requires the registry extra).

## Repo facts

- github.com/PaulRaspey/uahp (public), MIT license, version 0.7.0
- requires-python >= 3.9; deps: cryptography, pydantic v2
- extras: registry (fastapi, sqlalchemy, uvicorn), csp (groq), pqc (liboqs-python)
- source repos uahp-stack and UAHP-v0.6.0 are tagged phase1-complete
