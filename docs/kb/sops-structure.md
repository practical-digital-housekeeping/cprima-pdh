# sops: the structure of a file

Knowledge-base entry, 2026-10-05. Licensed under CC-BY-4.0.

The structure of a [sops](https://github.com/getsops/sops) file encrypted to age recipients, as pdh reads it. Not covered: how sops
is run, or how the other key types work.

Marks: **seen** = printed from the real fixture here (`packages/pdh-testkit/vaults/sops/sops-json-basic.json`, made by sops 3.13.3),
keys and patterns only, never a ciphertext. **format** = from pdh's reader (`cprima_pdh_sopskit/sops_format.py`, which is checked
against the real `sops` binary in the tests) or from sops itself, not shown by that file.

## The shape

A sops file is an ordinary document (here JSON) in which every value is replaced by an encrypted token, plus one extra top-level
key, `sops`, with the facts needed to decrypt and check it. **Seen:**

```
{
  "Money": {                          keys stay readable: groups, titles, field names
    "Cards": {
      "login": {
        "UserName": "ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]",
        "Password": "ENC[AES256_GCM,...,type:str]",
        "Tags":     [ "ENC[...]", "ENC[...]" ],
        "visible_unencrypted": "public"        a key ending in _unencrypted stays plain
      }
    }
  },
  "sops": {
    "age": [ { "recipient": "age1...", "enc": "-----BEGIN AGE ENCRYPTED FILE-----..." },
             { "recipient": "age1...", "enc": "..." } ],
    "lastmodified": "2026-10-03T12:30:37Z",
    "mac": "ENC[AES256_GCM,...]",
    "unencrypted_suffix": "_unencrypted",
    "version": "3.13.3"
  }
}
```

## An encrypted value

`ENC[AES256_GCM,data:<b64>,iv:<b64>,tag:<b64>,type:<kind>]`: the value, a random start value, an authentication tag, and the kind
of value. **Seen:** `type:str`. **Format (the reader accepts):** `str`, `int`, `float`, `bool`, `bytes`, `comment`.

- **Bound to its place.** The check includes the value's key path as extra data: the keys from the top joined with `:`, plus a
  trailing `:` (`Money:Cards:login:Password:`). A value moved to another key stops decrypting. Items of a list use the key of the
  list.
- **Plain exceptions.** A key ending in `unencrypted_suffix` keeps a plain value (**seen:** `visible_unencrypted`).

## The `sops` block

| Key | Holds | Marked |
|---|---|---|
| `age` | one item per recipient: `recipient` (the public key) and `enc` (the data key, encrypted to that recipient, an age file) | seen |
| `lastmodified` | when sops last wrote the file, UTC | seen |
| `mac` | the file's check value, itself encrypted (below) | seen |
| `unencrypted_suffix` | the key ending that leaves a value plain | seen |
| `version` | the sops version that wrote it | seen |
| `mac_only_encrypted` | present when the check covers only encrypted values | format |
| other recipient types (`kms`, `gcp_kms`, `azure_kv`, `hc_vault`, `pgp`) | the same idea for other key services; pdh supports `age` only | format |

## How it hangs together

1. One random **data key** encrypts every value. It is stored once per recipient, encrypted to that recipient's public key (`age`
   items, `enc`). Anyone holding one matching age identity can open the file; adding a recipient adds an item.
2. The **MAC** is SHA-512 over the plaintext of all values in document order, upper-case hex. It is stored encrypted with the data
   key, with `lastmodified` as extra data. Change a value, reorder keys, or edit `lastmodified`, and the check fails. pdh verifies it
   before showing anything. With `mac_only_encrypted` the hash starts with the SHA-256 of `sops` and covers only encrypted values.
3. **Syntax is separate.** **Seen:** JSON. **Format:** sops also handles YAML, dotenv, INI and binary; pdh reads JSON today, and
   the reader works on the parsed document, so another syntax only needs a parser.

## What anyone can read without a key

- Every key name: the whole tree of groups, titles and field names.
- How many values there are, the kind of each (`type:`), and, from the length of `data`, about how long each is.
- The recipients' public keys, `lastmodified` and the sops version.

Values are protected; the structure is not. Put nothing in a key name that should be secret.

## How pdh reads it as a vault (a pdh convention, not part of sops)

- A mapping of mappings is a **group**; a mapping of scalars is an **entry**; a leaf is a **field**.
- Titles, group names and field names are the plaintext keys; a value sops encrypted is a protected field.
- `lastmodified` is the only time a file has. sops has no ids, so pdh derives an id from the path. The file has no recycle bin,
  history, attachments or expiry. A scalar beside groups belongs to no entry and is only counted.

## To print the shape yourself

```
uv run --all-packages python -c "
import json, re
d = json.load(open('packages/pdh-testkit/vaults/sops/sops-json-basic.json', encoding='utf-8'))
def shape(v):
    if isinstance(v, dict): return {k: shape(x) for k, x in v.items()}
    if isinstance(v, list): return [shape(v[0])] if v else []
    return re.sub(r'ENC\[AES256_GCM,.*,type:(\w+)\]', r'ENC[...,type:\1]', v) if isinstance(v, str) and v.startswith('ENC[') else '...'
print(json.dumps(shape(d), indent=1))"
```

It prints names and kinds, never a value. Use a test file, not a real one.
