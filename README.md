# ListGuard

[![CI Status](https://github.com/knarayanareddy/listguard/actions/workflows/ci.yml/badge.svg)](https://github.com/knarayanareddy/listguard/actions)
![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)
![Python](https://img.shields.io/badge/Python-3.12-blue.svg)

> **Constitutional Rule**: Moderates *listing content*, NEVER auto-bans human *persons*. Action is strictly `allow | queue | block`.

Online marketplace Trust & Safety ingestion control plane built for EU Digital Services Act (DSA Article 16) compliance. ListGuard provides sub-80ms listing scanning, strict closed-set policy categorization (`weapon`, `animal`, `counterfeit`, `pii`, etc.), adversarial prompt injection intercept, and signed SQLite audit receipts with reviewer Accept/Override controls.

---

## Quickstart

```bash
# Clone the repository
git clone https://github.com/knarayanareddy/listguard.git
cd listguard

# Install dependencies
pip install -e .

# Run demo
python main.py demo

# Start API server
python main.py serve --port 8000
```

See [SPEC.md](SPEC.md) for full architectural specifications, closed-set policy buckets, and the implementation checklist.
