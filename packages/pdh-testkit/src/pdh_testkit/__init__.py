"""Test vaults for cprima-pdh.

- **synthetic** (`synthetic_vault`): written by pykeepass with the key derivation lowered so that it opens in
  milliseconds. Allowed for unit and integration tests only.
- **genuine**: vault files made by hand in a real client (KeePassXC desktop app, KeePassDX) and committed as
  fixtures. Required for end-to-end tests (marker `e2e`). No client is scripted or wrapped.
"""
from .vault import DEFAULT_PASSWORD, Entry, synthetic_vault

__all__ = ["DEFAULT_PASSWORD", "Entry", "synthetic_vault"]
