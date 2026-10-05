"""sops files (JSON or YAML, encrypted to age recipients) read as a vault: `sops_vault.SopsVault` is a `cprima_pdh_vault` Vault,
`sops_format` reads and verifies the document, `age` opens the data key. Read-only. It depends on no program that uses it."""
