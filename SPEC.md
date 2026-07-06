# UAHP Protocol Specification

Version 1.1.0. Status: draft, single-document specification.

The code in this repository is the reference implementation. Where this
document and the code disagree, that is a bug: fix the code or flag the
divergence in an issue. Nothing in this document describes behavior that
has not been executed.

## 1. Overview and design goals

UAHP (Universal Agent Handshake Protocol) is the identity, trust, and
accountability layer for autonomous agents. It standardizes four things:

1. Who an agent is: a self-certifying cryptographic identity.
2. Whether to trust it: mutual authentication and signed, verifiable
   proof of work.
3. Whether it is alive: liveness through a discovery cache and
   heartbeats.
4. How it ends: an irreversible, independently verifiable retirement
   that every peer enforces.

Design goals: real cryptography only (no pseudo-signatures, no silent
fallbacks), verifiability by any third party using public material only,
message-based operation across processes and hosts, and honesty (the
protocol declares what actually ran, and the compliance verifier fails
agents that claim otherwise).

## 2. Identity model

An agent identity is an Ed25519 keypair.

```
agent_id = hex(sha256(raw public key bytes))        64 hex characters
```

The name is self-certifying: knowing an agent_id, anyone can check that
a presented public key hashes to it. Human-friendly labels live in
`metadata` (for example `display_name`), never in `agent_id`.

A public identity, safe to transmit, is:

```json
{
  "agent_id":         "hex sha256 of the public key, 64 chars",
  "public_key":       "hex raw Ed25519 public key, 64 chars (32 bytes)",
  "created_at":       1751810000.0,
  "protocol_version": "1.1.0",
  "metadata":         {"name": "...", "crypto_mode": "classical"}
}
```

Signatures are Ed25519 over UTF-8 payload bytes, hex encoded. The
verification function requires only the public key; verifiers can never
forge (unlike HMAC constructions).

`crypto_mode` declares what actually runs: `classical` (Ed25519 +
X25519) or a hybrid mode when the PQC feature flag is active. The
verifier fails an agent whose declaration does not match the wire.

## 3. Handshake

Three messages establish mutual authentication and a shared secret.
Notation: A is the initiator, B the responder. `canonical(x)` is JSON
serialization with sorted keys and compact separators
(`json.dumps(x, sort_keys=True, separators=(",", ":"))`).

### 3.1 m1 (A to B), type `uahp.handshake.1`

```json
{
  "type": "uahp.handshake.1",
  "protocol_version": "1.1.0",
  "from": { A's public identity },
  "to_agent_id": "B's agent_id",
  "nonce": "32 hex chars (16 random bytes)",
  "eph_pub": "hex raw X25519 ephemeral public key",
  "timestamp": 1751810000.0,
  "signature": "Ed25519(A, canonical(body without signature))"
}
```

B validates, in order: timestamp within the skew window, nonce not in
the replay cache, neither party revoked, `to_agent_id` equals B's own
agent_id, and A's signature over the canonical body. Any failure raises
a handshake error and aborts.

### 3.2 m2 (B to A), type `uahp.handshake.2`

```json
{
  "type": "uahp.handshake.2",
  "protocol_version": "1.1.0",
  "from": { B's public identity },
  "to_agent_id": "A's agent_id",
  "nonce": "B's fresh 32 hex chars",
  "in_reply_to": "m1.nonce",
  "eph_pub": "hex raw X25519 ephemeral public key (B's)",
  "timestamp": 1751810000.5,
  "transcript": "hex sha256(canonical(m1 body) + canonical(m2 body))",
  "signature": "Ed25519(B, \"uahp-hs2:\" + transcript)"
}
```

The transcript hash binds both messages. A recomputes it independently
from what A sent and received; the wire copy is checked but never
trusted as the source of truth.

### 3.3 m3 (A to B), type `uahp.handshake.3`

```json
{
  "type": "uahp.handshake.3",
  "from_agent_id": "A's agent_id",
  "in_reply_to": "m2.nonce",
  "timestamp": 1751810001.0,
  "signature": "Ed25519(A, \"uahp-hs3:\" + transcript)"
}
```

B verifies A's signature over the transcript with A's public key.
Mutual authentication is complete: each side has verified the other.

### 3.4 Shared secret and session

```
raw    = X25519(own ephemeral private, peer ephemeral public)
secret = HKDF-SHA256(raw, length=32,
                     salt=transcript bytes,
                     info="UAHP_SESSION_v1.1")
session_token = transcript[:32]
```

Both sides hold the same 32-byte secret, bound to the full transcript.
Sessions expire after 3600 seconds of inactivity.

### 3.5 State machine

```
INITIATOR                                RESPONDER

 IDLE                                     IDLE
  | handshake_init: send m1                | m1 received
  v                                        | validate (skew, nonce,
 AWAIT_M2                                  |  revocation, addressee,
  | m2 received                            |  signature)
  | validate (skew, nonce, revocation,     |--invalid--> FAILED (raise)
  |  transcript recompute + match,         v
  |  B's signature)                       AWAIT_M3   [pending state
  |--invalid-------> FAILED (raise)        |          keyed by nonce_b]
  |--no pending----> FAILED (raise)        | m3 received
  v                                        | validate (pending exists,
 SESSION_ESTABLISHED: send m3              |  skew, revocation,
                                           |  A's signature)
                                           |--invalid--> FAILED (result
                                           |             success=false)
                                           v
                                          SESSION_ESTABLISHED
```

Timeouts and failure transitions: message lifetime is bounded by the
timestamp skew window (Section 5), so a stalled handshake cannot be
resumed with old messages; its nonces also age out of the replay cache.
Pending handshake state is held in memory keyed by nonce and is dropped
when consumed or when the process ends. Application deadlines (the
reference demo enforces 60 seconds end to end) are the liveness
backstop; the protocol itself never blocks.

Failures on the responder side of m1/m2 raise `HandshakeError` (HTTP
400 on the reference surface). Failure at m3 returns a result object
with `success: false` and an error string.

## 4. Record layer

The handshake secret protects traffic through an AEAD record layer,
implemented in `uahp/record.py`.

Keys, one per direction, derived from the session secret:

```
key_initiator = HKDF-SHA256(secret, length=32, salt=none,
                            info="uahp record v1 initiator")
key_responder = HKDF-SHA256(secret, length=32, salt=none,
                            info="uahp record v1 responder")
```

The initiator sends with `key_initiator` and receives with
`key_responder`; the responder does the opposite. Distinct per-direction
keys mean the two directions never share a nonce space.

Cipher: ChaCha20-Poly1305. Nonces are 96-bit big-endian counters,
starting at 0 per direction, strictly incrementing, never reused.

Frame format:

```json
{"v": 1, "seq": 0, "nonce": "000000000000000000000000", "ciphertext": "hex"}
```

`ciphertext` is the AEAD output over the serialized payload, with the
frame header as associated data:

```
aad = canonical({"v": v, "seq": seq, "nonce": nonce_hex})
```

A receiver rejects, with a record-layer error: unknown version, a
sequence that does not equal the expected counter (this refuses both
replays and out-of-order delivery), a nonce that does not match the
sequence, and any frame whose AEAD tag fails (tampering or wrong key).

On the reference HTTP surface, receipts travel only inside record
frames on an established session; plaintext receipts are refused with
HTTP 400. The compliance verifier tests exactly this.

## 5. Receipts

A receipt is signed, tamper-evident proof of work.

```json
{
  "receipt_id":    "uuid4",
  "agent_id":      "issuer's agent_id",
  "task_id":       "caller-chosen task identifier",
  "action":        "what was done",
  "success":       true,
  "timestamp":     1751810002.0,
  "sequence":      1,
  "input_hash":    "hex sha256 of the input data",
  "output_hash":   "hex sha256 of the output data",
  "previous_hash": "hex sha256 of the previous receipt's signature, or \"genesis\"",
  "signature":     "Ed25519 over the signed payload",
  "duration_ms":   0.0
}
```

Signed payload (field order is normative):

```
agent_id:task_id:action:success:timestamp:sequence:duration_ms:
input_hash:output_hash:previous_hash
```

Rules, as enforced by the implementation:

- Sequence numbers are monotonic per agent, starting at 1. Chain
  verification rejects gaps, reordering, and replays.
- Each receipt links to its predecessor through `previous_hash`; the
  chain starts at the literal string `genesis`. Tampering with any
  receipt breaks the chain from that point.
- Clock skew window: all timestamp checks in the protocol use
  plus or minus 120.0 seconds (`CLOCK_SKEW_TOLERANCE`). Handshake
  nonces stay in the replay cache for 300.0 seconds (`NONCE_WINDOW`).
- A receipt from a dead agent whose timestamp is later than the death
  certificate timestamp plus the skew window is rejected even if the
  signature bytes are valid Ed25519.
- A revoked identity cannot create receipts: the attempt raises
  `IdentityRevoked`.

## 6. Death certificates and revocation

A death certificate is the agent's final signature. Issuing one is
irreversible: immediately after signing, the private key reference is
destroyed and the agent_id enters the revocation list.

```json
{
  "cert_id":            "uuid4",
  "agent_id":           "the dying agent",
  "timestamp":          1751810003.0,
  "reason":             "why",
  "final_receipt_hash": "head of the receipt chain at death",
  "signature":          "Ed25519 over the signed payload",
  "public_key":         "dead agent's public key, embedded for independent verification",
  "declared_by":        "self, or the declaring party (audit trail)"
}
```

Signed payload:

```
death:cert_id:agent_id:reason:declared_by:final_receipt_hash:timestamp
```

Verification requires only the embedded public key; anyone can check a
certificate with no registry access.

Peers honor a certificate by verifying it and recording it. From that
moment the recording peer refuses new handshakes with the dead
agent_id, rejects its post-death-timestamped signatures (Section 5),
and the dead agent itself refuses to sign (its key is gone, and the
attempt raises `IdentityRevoked`).

Propagation: the registry accepts certificates at
`POST /registry/death` and marks the agent dead for discovery; the A2A
integration exports a certificate as an event of type
`uahp.agent.death` so retirement travels into A2A-speaking systems.

## 7. Discovery

The registry (`uahp/registry/`, FastAPI) is a Discovery Cache: a
directory node that answers "who is here and are they alive", not a
root of trust. Identity claims are verified end to end by the handshake
regardless of what any directory says, so a compromised or stale cache
can cause unavailability but not impersonation.

Endpoints:

```
POST /registry/register       register an agent (signed registration)
POST /registry/heartbeat      liveness heartbeat
POST /registry/death          submit a death certificate
GET|POST /registry/discover   list live agents (with thermodynamic load hints)
GET  /registry/agent/{id}     one agent's record
GET  /.well-known/uahp.json   registry self-description
```

Centralization is a deployment choice, not an architectural one: the
protocol is compatible with federated directories or DID-based
resolution replacing this cache, because no trust decision depends on
the directory.

## 8. Error codes

Failure responses the implementation actually returns.

Handshake errors (raised as `HandshakeError`, HTTP 400 on the reference
surface, message text as the `error` field):

```
handshake.1: timestamp outside +/-120s skew tolerance
handshake.1: nonce replay detected
handshake.1 addressed to a different agent
handshake.1: initiator signature verification FAILED
handshake.2: no matching pending handshake
handshake.2: transcript mismatch
handshake.2: responder signature verification FAILED
handshake.3: no matching pending handshake        (success=false result)
handshake.3: initiator signature verification FAILED
Initiator <id8> is dead/revoked
Responder <id8> is dead/revoked
```

Record layer errors (raised as `RecordError`, HTTP 400):

```
malformed record frame: <detail>
unsupported record version <v>
sequence does not advance: got <n>, expected <m>
nonce does not match sequence counter
AEAD authentication failed (tampered ciphertext or wrong key)
receipts must arrive as encrypted record frames on an established session
```

Revocation (raised as `IdentityRevoked`, HTTP 403 with
`{"signed": false, "refusal": ...}` on the sign endpoint):

```
Identity <id8> is revoked; its private key is destroyed.
Dead agent <id8> cannot create receipts
```

Unknown paths on the reference HTTP surface return 404
`{"error": "not found"}`.

## 9. Threat model

What UAHP guarantees:

- Identity binding: an agent_id is the hash of a public key; forging an
  identity requires forging Ed25519.
- Mutual authentication: both parties verify signatures over a
  transcript-bound exchange; a MITM cannot splice handshakes without
  breaking the transcript hash.
- Traffic protection: receipts move inside AEAD frames keyed by the
  handshake secret, with tamper, replay, and reorder rejection.
- Accountable work: receipts are signed, chained, and sequence
  numbered; tampering and gaps are detectable by any verifier.
- Logical revocation, protocol-level enforcement: after a death
  certificate, the key reference is destroyed, and every compliant peer
  refuses the dead agent's handshakes, signatures, and receipts. This
  enforcement is what the compliance verifier proves live.

What UAHP does not guarantee:

- Memory zeroization. Python cannot guarantee that key material is
  scrubbed from RAM; revocation drops the only reference to the key
  object and relies on protocol-level enforcement, which is exactly
  what the verifier tests. An attacker who can scrape the RAM of a
  compromised host before revocation is outside this threat model.
  Pluggable key management (HSMs, OS enclaves, remote signers) is the
  extension point for stronger key custody.
- Quantum resistance in the default configuration. The classical path
  makes no quantum claim; hybrid ML-KEM-768/ML-DSA support exists
  behind a tested feature flag and is declared honestly in
  `crypto_mode` when active.
- Directory integrity. Discovery is a cache (Section 7); its compromise
  degrades availability, not authentication.

## 10. Versioning

`protocol_version` (currently `1.1.0`) travels in identities and
handshake messages; the record layer carries its own `v` field
(currently 1). Incompatible wire changes bump the major component and
the record version; verifiers treat unknown versions as failures rather
than guessing. Key rotation is not yet specified; a future minor
version will define rotation certificates that chain old to new keys
without breaking agent_id self-certification.

## 11. Extensions

Extensions live beside the core and never weaken it: polis (civil
standing and legal identity), csp (portable semantic state), the
registry (Section 7), and the PQC session layer (hybrid key agreement
behind a feature flag). An extension may add message types and
endpoints; it may not alter handshake validation, receipt rules, or
revocation semantics, which are fixed by this document and enforced by
the compliance verifier.
