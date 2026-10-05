"""KeePass (KDBX) vaults: `kdbx_vault.KdbxVault` is a `cprima_pdh_vault` Vault on top of pykeepass, `kdbx_format` is what the
format says (standard fields, secret attributes, the OTP plugin, key derivation names). Its choices (what it writes into
`Meta/Generator`, which formats it writes) are a `kdbx_vault.KdbxPolicy` the caller passes, with defaults. It depends on no
program that uses it."""
