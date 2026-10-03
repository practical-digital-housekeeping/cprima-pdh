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

## Please add

A **KDBX 4.1** template made by hand in KeePassXC 2.7 or later (save the database with "KDBX 4.1" via
*Database settings, Security*, or create a group move so the file gets `PreviousParentGroup`). Put it into
`packages/pdh-testkit/vaults/` as `template-kdbx41.kdbx` with a sidecar `.toml` like the other two; the
parametrised genuine-template tests pick it up. Until then pdh writes `PreviousParentGroup` (so `restore` needs no
`--to`) only for vaults that already report KDBX 4.1, and this is tested with a faked version, not a real file.
