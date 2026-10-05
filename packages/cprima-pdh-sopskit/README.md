# cprima-pdh-sopskit

sops files (JSON or YAML) encrypted to [age](https://age-encryption.org) recipients, read as a vault for [cprima-pdh](../cprima-pdh).

- `cprima_pdh_sopskit.sops_vault`: `SopsVault`, a read-only `cprima_pdh_vault` Vault.
- `cprima_pdh_sopskit.sops_format`: reads the document, checks its MAC, decrypts values.
- `cprima_pdh_sopskit.age`: opens the data key with an age identity.

Depends on `cprima-pdh-vault` and `cryptography`. The real `sops` and `age` programs are only ever used as test oracles.
Hobby project, 0.x, no stability promised. Apache-2.0.
