# cprima-pdh

**Practical Digital Housekeeping.** Keep your digital life in order, starting with your password database.
Keep it tidy. Keep it trustworthy.

`pdh` is the companion tool of the methodology. This release (0.0.1) is a placeholder: it has the final
command and install shape but does nothing yet. It never opens, reads or writes a vault.

```powershell
uvx --from "cprima-pdh[kdbx]" pdh --version
uvx --from "cprima-pdh[kdbx]" pdh backends
uvx --from "cprima-pdh[kdbx]" pdh check vault.kdbx
```

Always use `--from`: plain `uvx pdh` runs an unrelated tool of the same command name.

Licence: Apache-2.0.
