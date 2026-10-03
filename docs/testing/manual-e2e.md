# Manual end-to-end checks

Licensed under CC-BY-4.0.

The automated tests run pdh against synthetic vaults and against copies of two genuine, hand-made templates
(`just test-genuine`: KDBX 3.1 and 4.0 written by KeePassXC). What they cannot show is how a **real client** presents
what pdh wrote. That is a human check, done once per release and after any change to a write command.

Never use your real vault for this. Work on a copy of a template (`packages/pdh-testkit/vaults/template-kdbx4.kdbx`,
password in its sidecar `.toml`) and delete the copy afterwards. Quit the client fully before running pdh on the file
and re-open it afterwards (a client that still holds the file fails saves or shows stale data).

Set up once:

```
copy packages\pdh-testkit\vaults\template-kdbx4.kdbx work.kdbx
set KDBX_FILE=work.kdbx
set PDH_NEW_PASSWORD=pw-example
pdh edit new-group / Money --apply
pdh edit new-entry Money "Example login" alex --url https://example.org --tag one --tag two --expires 2031-02-03 ^
    --field account_no=4711 --apply
```

Then, per group of commands: run it, open the file in the client, look for the result in the right-hand column.

| Command (all with `--apply`) | In KeePassXC / KeePassDX you should see |
|---|---|
| `new-entry` as above | the entry in `Money`, tags `one` and `two`, the expiry date, a custom attribute `account_no` |
| `edit set Money/"Example login" Notes hello --overwrite` | the notes; the entry's *History* tab lists the previous state |
| `edit set ... token abc --protect` (custom field) | the attribute is hidden until you reveal it |
| `edit tags`, `expiry`, `icon 12`, `color --fg #112233 --bg #AABBCC`, `autotype --disabled` | tags changed, the entry shows the icon and colours, auto-type is off for it |
| `edit clone` | a second entry with the same content and a different title |
| `edit attach`, then `detach` | the attachment appears with its name and size, opens and has the right content; after `detach` it is gone |
| `edit history-restore 0`, `history-prune --keep 0` | the entry has its older content again; the History tab is empty after the prune |
| `edit delete`, `restore --to Money`, `purge` | the entry is in the *Recycle Bin*, back in `Money`, gone for good |
| `edit rename-group`, `group-notes`, `group-icon`, `move-group`, `delete-group` | the group's new name, notes and icon; the group below another one; in the recycle bin |
| `db settings --name "Example" --history-max-items 5` | the database name in the title bar; the history limit in the database settings |
| `db password` | the vault opens with the new password only |
| `db kdf --iterations 3 --memory 8192` | still opens (slightly faster); the database security settings show the new values |
| `io export-csv --out e.csv` | opens in a spreadsheet; no password column unless `--with-secrets` |
| `io export-kdbx --out copy.kdbx` | opens with its own password and has the same entries |
| `io import-kdbx other.kdbx --group Imported` | the other vault's entries below `Imported`, with attachments and protected fields |
| `io merge copy.kdbx` after editing the same entry in both | the newer state wins; the replaced one is in the History |
| `inspect otp "Money/Example login"` with a TOTP set up in the client | the same six digits the client shows right now (within one 30-second step) |
| `pdh generate` | nothing to check in a client; look at the output |

Record what differs (client, version, command, what you saw) in `docs/ideas-and-backlog.md` section 2c.

## Please add: a KDBX 4.1 template

KeePassXC does not offer a choice between KDBX 4.0 and 4.1: it writes 4.1 on its own as soon as the file uses a 4.1
feature, for example the record of where an entry was moved from (`PreviousParentGroup`). So make it like this, with
throwaway content only (never a copy of a real vault):

1. KeePassXC > Database > New Database, format KDBX 4, password `test123`, save as `template-kdbx41.kdbx`.
2. Create two groups `A` and `B`, an entry `x` in `A`, then drag `x` into `B` (or delete it into the recycle bin and
   restore it). Delete nothing else. Save and close.
3. Check the format: `pdh doctor` with `KDBX_FILE` set to the file must say `KDBX 4.1`. If it still says 4.0, do one
   more move.
4. Empty it again (delete `x`, empty the recycle bin) if you want an empty template, keep the groups out of it if you
   prefer a bare one, and save.
5. Put the file into `packages/pdh-testkit/vaults/` with a sidecar `template-kdbx41.toml`:
   `password = "test123"`, `client = "KeePassXC"`, `format = "KDBX 4.1"`, `description = "..."`.

The parametrised genuine-template and client tests pick it up by name (`template-*`). Until then pdh writes
`PreviousParentGroup` (so `restore` needs no `--to`) only for vaults that already report KDBX 4.1, and that is tested
with a faked version, not a real file.
