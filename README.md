# UAHP

[![CI](https://github.com/PaulRaspey/uahp/actions/workflows/ci.yml/badge.svg)](https://github.com/PaulRaspey/uahp/actions/workflows/ci.yml)

**The identity, trust, and accountability layer for autonomous agents.**

MCP standardized how agents use tools. A2A standardized how agents exchange tasks. UAHP standardizes who an agent is, who vouches for it, whether it is alive, and how it ends.

Verifiable Ed25519 identity. Mutual authentication in three messages. Signed proof of work over an encrypted channel. Irreversible retirement. All on real cryptography, all verifiable with one command.

Protocol specification: [SPEC.md](SPEC.md). The code in this repository is the reference implementation.

```
pip install -e ".[registry]"
uahp init
python3 demos/run_demo.py
```

## Sixty seconds to a live handshake

The reference demo runs three real OS processes (a registry, a responder, an initiator) through four acts and finishes in about two seconds:

```
[alice] ────── ACT 1: MUTUAL HANDSHAKE (Ed25519 + X25519/HKDF) ──────
[bob  ] m1 received, initiator signature VERIFIED; sent m2
[alice] m2 received, responder signature VERIFIED; sent m3
[alice] MUTUAL HANDSHAKE COMPLETE, shared secret sha256 matches on both nodes
[alice] ────── ACT 2: ENCRYPTED RECEIPT EXCHANGE (ChaCha20-Poly1305 record layer) ──────
[alice] receipt sealed into AEAD record frame (seq 0, ciphertext a35ddfcf...)
[bob  ] decrypted receipt, signature VERIFIED
[alice] peer receipt signature VERIFIED; receipts traveled ENCRYPTED in both directions
[alice] ────── ACT 3: DEATH CERTIFICATE ──────
[bob  ] death certificate ISSUED; private key DESTROYED
[alice] ────── ACT 4: POST-DEATH REJECTION, LIVE ──────
[bob  ] sign request REFUSED: Identity 4679aafe is revoked; its private key is destroyed.
[alice] REJECTED post-death-timestamped receipt from bob: identity is revoked
[alice] REFUSED new handshake with dead agent
demo PASSED (initiator exit 0)
```

That last act is the point. Every agent framework can create agents. UAHP is about what happens when one must end: a death certificate is the agent's final signature, the private key is destroyed, and from that moment every peer refuses its signatures, its receipts, and its handshakes. Retirement you can prove, not a row flipped in someone's database.

The quickstart and the full demo have been verified on a fresh clone in a clean virtualenv on macOS 12 (Python 3.9) and Ubuntu 24.04 (Python 3.12.3).

## Quickstart

```bash
git clone https://github.com/PaulRaspey/uahp.git
cd uahp
python3 -m pip install --upgrade pip   # editable installs need pip >= 21.3
pip install -e ".[registry]"

uahp init      # create a local agent identity (Ed25519)
uahp status    # show the identity and key health
uahp verify    # prove the identity signs and verifies
uahp run       # start the UAHP MCP server on stdio

python3 demos/run_demo.py    # the four-act reference demo
```

## Prove any agent is UAHP-compatible

The compliance verifier probes a live agent over HTTP and prints PASS or FAIL per protocol requirement:

```bash
uahp verify http://127.0.0.1:8100
```

It checks seven things: a real Ed25519 identity (challenge signatures that verify and bind), a completed mutual handshake, receipts signed and verified in both directions through the encrypted record channel with tampered receipts rejected, plaintext receipts refused outside that channel, replay refusal, an honest crypto_mode declaration, and revocation honored after death. The reference agent scores 7 of 7 PASS. The included `demos/broken_agent.py`, which uses HMAC pseudo-signatures, accepts everything, claims hybrid PQC it does not have, and ignores its own death certificate, scores 7 of 7 correct FAILs and a nonzero exit code. Note that the revocation check is destructive by design: it asks the agent to die and then confirms the death sticks.

## Wrap an existing agent

You do not rewrite your agent to adopt UAHP. You wrap it.

If your agent is reachable over HTTP, the sidecar puts the full UAHP surface in front of it in five lines. Callers get a verifiable identity, a mutual handshake, an encrypted record channel, and a signed receipt for every task; your agent stays untouched:

```python
from http_sidecar import UAHPSidecar

sidecar = UAHPSidecar(upstream="http://127.0.0.1:8131", name="my-agent")
sidecar.serve(port=8130)
```

`python3 examples/http_sidecar.py` runs the whole loop against a dummy upstream agent: handshake, one encrypted task, one encrypted signed receipt, receipt signature verified by the client.

If your agent lives in an MCP client instead, add the UAHP MCP server (`uahp run`) to the client configuration and the agent gains all ten protocol tools without code changes: see [examples/mcp_sidecar.md](examples/mcp_sidecar.md). Framework-specific adapters (LangChain, CrewAI) are on the roadmap.

## The handshake

Three messages, both sides authenticated, works across processes and hosts:

```
A: m1 = handshake_init(alice, bob_public)     Ed25519 signed, fresh nonce,
                                              ephemeral X25519 public key
        --- m1 --->
B: m2 = handshake_respond(bob, m1)            verifies A's signature, answers with
                                              its own nonce and ephemeral key,
                                              signs the transcript hash
        <--- m2 ---
A: m3 = handshake_finalize(alice, m2)         verifies B's signature, derives
                                              the shared secret
        --- m3 --->
B: handshake_complete(bob, m3)                both sides hold the same session
                                              token and secret
```

The shared secret comes from an ephemeral X25519 exchange, run through HKDF-SHA256 keyed by the transcript hash. Replay protection uses a nonce cache, timestamps with a clock skew window, and sequence numbered receipts.

The secret is not decorative: a ChaCha20-Poly1305 record layer derives per-direction keys from it (HKDF with distinct labels, so the two directions never share a nonce space) and moves receipts as AEAD frames with counter nonces and strict sequence checks. Receipts are refused outside this encrypted channel, and the compliance verifier tests exactly that.

## Identity model

An agent identity is an Ed25519 keypair. `agent_id` is canonical everywhere: core, schemas, wire formats, and MCP tools. A public identity is `{agent_id, public_key, created_at, protocol_version, metadata}`. The CLI stores its identity at `~/.uahp/identity.json` with `agent_id = sha256(public key bytes)`.

## Honest security status

- **Ed25519 signatures and X25519+HKDF key agreement run everywhere today.** This is the classical path and it makes no quantum claim.
- **ML-KEM-768 and ML-DSA hybrid support is implemented behind a tested feature flag** and activates when liboqs and liboqs-python are installed. The real hybrid path has run: encap/decap roles correct, equal shared secrets on both sides, 13 of 13 tests passing against real liboqs.
- **crypto_mode is declared explicitly** in packets and identities. The verifier fails any agent that claims hybrid while serving a classical handshake. There is no silent fallback: requesting hybrid without liboqs raises `PQCUnavailableError` with install instructions.
- **Python cannot guarantee memory zeroization.** Revocation drops the only key reference and relies on protocol level enforcement, which is exactly what the verifier tests.
- **Not yet done:** external security audit, formal RFC specification suite. Planned, not blocking, and nothing here claims otherwise.

## Architecture

```
uahp/                the core package
  core.py            identity, handshake, receipts, death certificates
  record.py          AEAD record layer (ChaCha20-Poly1305 over the session secret)
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
demos/               run_demo.py, agent_node.py, broken_agent.py
tests/               five suites, all green
```

UAHP speaks to the ecosystem it completes: it ships an MCP server exposing the protocol as tools, and publishes A2A agent cards with death events, so identity and retirement travel with the agent into both worlds.

## Extensions

- **polis**: civil standing and legal identity (employment certificates, standing scores).
- **csp**: portable semantic state between agents (requires the `csp` extra).
- **registry**: FastAPI discovery service with liveness, heartbeats, death certificates, and thermodynamic load hints (requires the `registry` extra).

## Tests

```
tests/test_crypto.py        42 passed, includes post-death rejection and the AEAD record layer
tests/test_two_process.py   mutual handshake across two OS processes, same secret
tests/test_stack.py         identity -> receipts -> reputation -> compliance -> A2A -> death -> MCP
tests/test_extended.py      edge cases, reputation consistency, death blocks trust
tests/test_kem_flow.py      13 passed with real ML-KEM-768 (liboqs installed)
```

Micro-benchmark (`python3 demos/benchmark.py`): about 350 full 3-message mutual handshakes/sec and 1,150 encrypted signed receipts/sec (create, seal, open, verify), in-process on a single core of a 2.2 GHz Intel Core i7-5650U (a 2015 laptop).

## Docker

`Dockerfile` and `docker-compose.yml` (a registry plus two agent nodes) match the reference demo topology and entrypoint exactly, but the compose path has not been executed by the maintainer yet. The validated path is `pip install -e ".[registry]"` plus `demos/run_demo.py`. If you run the compose path, an issue confirming or correcting it is welcome.

## Requirements

Python 3.9 or later. Core dependencies: `cryptography`, `pydantic` v2. Extras: `registry` (FastAPI, SQLAlchemy, uvicorn), `csp`, `pqc` (liboqs-python).

## Contributing and security

Contributions welcome: see [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately per [SECURITY.md](SECURITY.md), not in public issues.

## License

MIT. Version 0.7.1.
