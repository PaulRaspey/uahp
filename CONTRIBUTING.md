# Contributing to UAHP

Thanks for your interest. UAHP is early and moving fast, so this guide is short and practical.

## Ground rules

- The protocol specification is [SPEC.md](SPEC.md). The code in this repository is the reference implementation. If you change protocol behavior, change SPEC.md in the same pull request, and vice versa. Claims in the spec must match executed behavior.
- Every claim in the README must be true of the code as merged. If your change makes a README sentence false, fix the sentence in the same commit.
- No new runtime dependencies for the core package without prior discussion in an issue. Core depends on `cryptography` and `pydantic` only.

## Setup

```bash
git clone https://github.com/PaulRaspey/uahp.git
cd uahp
python3 -m pip install --upgrade pip
pip install -e ".[registry]"
```

Python 3.9 or later.

## Tests

All five suites must pass before and after your change:

```bash
python3 tests/test_crypto.py
python3 tests/test_two_process.py
python3 tests/test_stack.py
python3 tests/test_extended.py
python3 tests/test_kem_flow.py
```

`test_kem_flow.py` skips the hybrid path cleanly when liboqs is not installed. CI runs all suites on Python 3.9 and 3.12 plus the docker compose topology.

New behavior needs a test in the suite closest to it. Crypto-adjacent changes (handshake, record layer, receipts, death certificates) need both a positive test and a rejection test: show the good path works and the bad path is refused.

## Pull requests

- One logical change per pull request.
- Explain what changed and why in the description. If the change is protocol-visible, point at the SPEC.md section it touches.
- The reference demo (`python3 demos/run_demo.py`) must still pass.

## Security issues

Do not open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md).
