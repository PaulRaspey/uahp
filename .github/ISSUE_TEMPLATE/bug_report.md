---
name: Bug report
about: Something behaves differently than the README or SPEC.md says it should
labels: bug
---

**What happened**

A clear description of the behavior you saw.

**What you expected**

What the README, SPEC.md, or the code's own docs led you to expect.

**Reproduction**

Exact commands, starting from a fresh clone if possible:

```bash
git clone https://github.com/PaulRaspey/uahp.git
cd uahp
pip install -e ".[registry]"
# your steps here
```

**Environment**

- OS:
- Python version (`python3 --version`):
- uahp version or commit:
- liboqs installed (hybrid PQC path): yes / no

**Output**

Paste the relevant output or traceback.

If you believe this is a security vulnerability, do not file it here. See [SECURITY.md](../../SECURITY.md).
