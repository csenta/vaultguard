# Contributing to VaultGuard

We welcome community contributions.

## Development Setup

1. Clone repository:
   ```bash
   git clone https://github.com/csenta/vaultguard.git
   cd vaultguard
   ```
2. Run test suite before submitting pull requests:
   ```bash
   PYTHONPATH=. python3 -m unittest discover -s tests -v
   ```
3. Follow PEP 8 guidelines and write comprehensive unit tests for all new secret patterns and verification probes.
