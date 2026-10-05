# cprima-pdh-vault

The vault interface of [cprima-pdh](../cprima-pdh): what the engine may ask of any store of entries.

- `cprima_pdh_vault.vault`: `Vault`, `VaultBase`, `EntryData`, `GroupData`, `Unsupported`, `WriteError`.
- `cprima_pdh_vault.transaction`: the one write path. A command describes a `Plan`; `execute` writes once to a temporary file,
  reopens it, verifies that nothing else changed, and only then replaces the vault. Without `apply` nothing is written.
- `cprima_pdh_vault.memory`: a vault of plain Python objects. It changes entries and groups like the other backends and is
  held to the same results by the shared contract tests.

A file format is its own package and depends on this one: `cprima-pdh-kdbxkit` (KeePass), `cprima-pdh-sopskit` (sops).
No dependencies. Hobby project, 0.x, no stability promised. Apache-2.0.
