# KDBX: the structure of the XML

Knowledge-base entry, 2026-10-05. Licensed under CC-BY-4.0.

The structure of the XML document inside a KDBX (KeePass) file, as pdh meets it through pykeepass. Not covered: the outer file
(signature, header, encryption), and how any element behaves.

Marks: **seen** = printed from a real file here (tag names, ids and time texts only, never values). **format** = from the KDBX
format, not shown by a file here.

## The tree

```
KeePassFile
├── Meta                          settings of the whole vault
│   ├── Generator
│   ├── DatabaseName, DatabaseNameChanged
│   ├── DatabaseDescription, DatabaseDescriptionChanged
│   ├── DefaultUserName, DefaultUserNameChanged
│   ├── MaintenanceHistoryDays
│   ├── Color
│   ├── MasterKeyChanged, MasterKeyChangeRec, MasterKeyChangeForce
│   ├── MemoryProtection
│   │   └── ProtectTitle, ProtectUserName, ProtectPassword, ProtectURL, ProtectNotes
│   ├── CustomIcons
│   ├── RecycleBinEnabled, RecycleBinUUID, RecycleBinChanged
│   ├── EntryTemplatesGroup, EntryTemplatesGroupChanged
│   ├── LastSelectedGroup, LastTopVisibleGroup
│   ├── HistoryMaxItems, HistoryMaxSize
│   ├── SettingsChanged
│   ├── CustomData
│   │   └── Item (several): Key, Value
│   ├── HeaderHash                KDBX 3.x only
│   └── Binaries                  KDBX 3.x only: the attachment contents
│
└── Root
    ├── Group                     the top group
    │   ├── UUID, Name, Notes, IconID
    │   ├── Times
    │   ├── IsExpanded, DefaultAutoTypeSequence, EnableAutoType, EnableSearching
    │   ├── LastTopVisibleEntry
    │   ├── Group (several)       sub-groups, same shape, nested to any depth
    │   └── Entry (several)       the entries of this group
    │
    └── DeletedObjects
        └── DeletedObject (several, often none)
            ├── UUID
            └── DeletionTime
```

An `Entry`:

```
Entry
├── UUID
├── IconID
├── ForegroundColor, BackgroundColor, OverrideURL    only when set
├── Tags                                             only when set
├── PreviousParentGroup                              KDBX 4.1: where a trashed entry came from
├── Times
├── String (several)         one per field: Key, Value
├── Binary (several)         one per attachment: Key, Value
├── AutoType
│   └── Enabled, DataTransferObfuscation, DefaultSequence, Association
└── History
    └── Entry (several)      earlier states, each with the same parts as an Entry
```

`Times`, on every group and every entry (and on every history `Entry`):

```
Times
└── CreationTime, LastModificationTime, LastAccessTime, ExpiryTime, Expires, UsageCount, LocationChanged
```

## What each part holds

- **Meta**: settings of the vault, not of any entry. Which group is the recycle bin (`RecycleBinUUID`), whether there is one
  (`RecycleBinEnabled`), how much history is kept (`HistoryMaxItems`, `HistoryMaxSize`), which standard fields the client hides
  (`MemoryProtection`), and free key/value extras of clients (`CustomData`).
- **Root**: holds exactly one `Group` (the top group, which has no parent) and `DeletedObjects`. The recycle bin is an ordinary
  `Group` somewhere below, found through `Meta/RecycleBinUUID`.
- **Group**: a folder. A group holds sub-groups and entries; the path of a group is the chain of `Name` values from the top group.
- **Entry**: one record. Everything the user sees on it, the standard fields included, is a `String` element.
- **String**: `Key` is the field's name, `Value` its text. The standard fields use the keys `Title`, `UserName`, `Password`,
  `URL`, `Notes`; any other key is a custom field. A protected field's `Value` carries the attribute `Protected="True"`.
  **Seen:** the attribute `Protected` on `Value`; the keys `Title`, `UserName`, `Password` and custom keys.
- **Binary**: an attachment: `Key` is the file name. **Seen (KDBX 4.0):** `Value` is empty and carries the attribute `Ref`, a
  number that points at the content kept in the file's inner header. **Format (KDBX 3.x):** the content is in `Meta/Binaries`.
- **History**: copies of the entry as it was before each edit, oldest first. **Seen:** `History` holds `Entry` children.
- **AutoType**: the keystroke settings for typing a login into a window; `Association` pairs a window title with a sequence.
- **DeletedObjects**: **format:** one `DeletedObject` per entry or group removed for good, with its `UUID` and the
  `DeletionTime`. **Seen:** the element exists in every file looked at, empty in all of them.

## How values are written

- **UUID** (on groups, entries, `RecycleBinUUID`, `PreviousParentGroup`, `DeletedObject`): the 16 bytes as base64 text, for
  example `naRFN3f8QfqHpa5ooyUTEQ==` (**seen**). This is not the 36-character form with hyphens that pdh shows, and not the
  32-hex form of a `{REF:...}`; all three are the same 16 bytes.
- **Times**: **seen, KDBX 3.1:** ISO 8601 text in UTC, `2026-10-02T21:02:50Z`. **Seen, KDBX 4.0:** base64 text of 8 bytes,
  `wghS4g4AAAA=`; **format:** a count of seconds since year 1.
- **Booleans** (`Expires`, `Enabled`, `IsExpanded`, ...): the text `True` or `False`. **Seen:** `Expires` as `False`.
- **Entries without a value** are not written: an unset color, tag list or override URL has no element at all.

## What differs between KDBX 3.x and 4.x

| Part | KDBX 3.1 | KDBX 4.0 / 4.1 |
|---|---|---|
| Header hash | `Meta/HeaderHash` (**seen**) | none in the XML (**seen**) |
| Attachment contents | `Meta/Binaries` (**seen**) | in the inner header; `Binary/Value` has `Ref` (**seen**) |
| Times | ISO 8601 text (**seen**) | base64 of a number (**seen**) |
| Where a trashed entry came from | not recorded | `PreviousParentGroup`, 4.1 (**format**; **seen** once in a vault pdh made) |

## Where it is read in pdh

`cprima_pdh_kdbxkit/kdbx_vault.py` turns an `Entry` or `Group` element into the plain snapshots `EntryData` and `GroupData`
(`_data`, `groups`) and is the only code that touches the XML. Anything below pykeepass, such as `Meta` settings or the
`DeletedObjects` section, is reached there through the element tree and nowhere else.

## To print it yourself

```
uv run --all-packages --all-extras python -c "
from pdh_testkit import vaults
from cprima_pdh_kdbxkit.kdbx_vault import KdbxVault, _root
t = vaults.load('canonical-kdbx4')
root = _root(KdbxVault.open(t.path, t.password).kp)
print([c.tag for c in root.find('Meta')]); print([c.tag for c in root.find('Root')])
print([c.tag for c in root.find('.//Entry')])   # names of the parts only, never a value
"
```

Use a test vault; do not point it at a real one.
