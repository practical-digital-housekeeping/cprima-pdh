"""Test vaults for cprima-pdh.

Two provenances, never mixed up:

- **synthetic** (`synthetic_vault`): written by pykeepass with the key derivation lowered so that it opens in
  milliseconds. Allowed for unit and integration tests only.
- **genuine** (`KeePassXC`): written by KeePassXC's own `keepassxc-cli`, with no tweaks beyond its official
  options. Required for end-to-end tests (marker `e2e`), and read back with keepassxc-cli, not with the code
  under test.
"""
from .keepassxc import KeePassXC, KeePassXCMissing, find_keepassxc_cli
from .vault import DEFAULT_PASSWORD, Entry, synthetic_vault

__all__ = ["DEFAULT_PASSWORD", "Entry", "KeePassXC", "KeePassXCMissing", "find_keepassxc_cli", "synthetic_vault"]
