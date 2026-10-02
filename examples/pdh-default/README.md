# Sample vault for the profile `pdh-default`

A fictional KeePass vault organised the way Practical Digital Housekeeping prescribes. Everything in it is made up
(`example.org`, `192.0.2.x`, invented numbers); it exists so you can see what a tidy vault looks like and try `pdh` on
it without touching your own.

`sample.kdbx` is a normal KDBX 4 file: open it in KeePassXC or KeePassDX (password `sample-test`), or run `pdh` on it.
`pdh` reads the password from the sidecar `sample.toml`, so it never prompts.

## What is in it

| Axis of the method | In this vault |
|---|---|
| **Owner**: the top-level group | three owners: `Alex`, `Sam` and `Shared` (the records both rely on) |
| **Area**: the sub-group | the ten areas of the profile (`Money`, `Shopping`, `Home & Utilities`, ...) below each owner |
| **Record type**: `_schema` and/or the fields | all 17 record types of the profile, written in `_schema`, derived from the fields, or both (see below) |
| **Vocabulary**: field names | only canonical terms (`customer_no`, `card_number`, `api_key`, ...); secrets are protected |
| **Relations** | the guest login of the router links to the router entry |
| **Hygiene** | cards carry an expiry date, URLs are `https://` (the router pages are local `http://`, which is valid), one-time passwords are set up where the service offers them |

35 entries, all conforming: no finding of any level.

## Record types: `_schema` and/or the fields

An entry's record types are the union of two sources, and both work in this vault:

- **Written**: the entry names them in its custom field `_schema` (`website`, `onlineshop, website`, ...).
- **Derived from the fields**: the profile's *match rules* bind a type to fields that belong to that type alone
  (`IBAN` means `bank-account`, `PUK` means `sim-card`, `SSID` means `wifi-access-point`, see
  [the profile](../../method/taxonomy/profiles/pdh-default.md)). An entry with such a field is typed without any `_schema`.

| What it shows | Entry |
|---|---|
| written only | `Example Mail`: `_schema = website` |
| derived only, no `_schema` at all | `Example Bank Account` (its `IBAN`), `Example Mobile Plan` (its `PUK`), `Office Access Point` (its `SSID`), `Home Router: guest login` (its `device` link) and five more; 9 in all |
| written **and** derived, both apply | `Example Airline Miles`: written `website`, and its `member_no` adds `membership` |
| written and matched: counts once | `Example Rail Card`: `_schema = membership`, and its `member_no` would match too |
| two written types whose requirements add up | `Home Router`: `_schema = wifi-access-point, openwrt-device`: the Wi-Fi fields and the SSH key together |

Types that look alike are never guessed: a debit card (`bank-card`) and a credit card (`credit-card`, which only adds a
`CVV`), a plain `website` or a shop are named with `_schema`. A `CVV` is deliberately not a rule: it would turn a
`CVV` wrongly found on a debit card into a second type instead of reporting it as a mismatch.

## Try it

`pdh` 0.0.2 or newer, with the KeePass backend:

```
pdh --db examples/pdh-default/sample.kdbx doctor
pdh --db examples/pdh-default/sample.kdbx inspect tree --entries
pdh --db examples/pdh-default/sample.kdbx check conform --status all
pdh --db examples/pdh-default/sample.kdbx inspect read --schema bank-account
pdh --db examples/pdh-default/sample.kdbx inspect links
```

`pdh inspect tree --entries` shows, for every entry, the types it wrote and the types that follow from its fields:

```
Example Airline Miles  [website; by fields: membership]
Example Bank Account   [by fields: bank-account]
Home Router            [wifi-access-point, openwrt-device]
```

The `method` section of `pdh doctor` is the vault seen through the method:

<!-- doctor:method -->
```
method
  [ok  ] owners       3: Alex 23, Shared 7, Sam 5
  [ok  ] areas        35 of 35 (100 %) in starter areas; 0 other sub-groups
  [ok  ] record types 35 of 35 (100 %) typed: website 13, membership 4, onlineshop 3, utility-contract 3, bank-account 2; 9 only by field rules
  [ok  ] vocabulary   41 field names: 35 terms, 6 caught by a name pattern, 0 not terms; 0 unprotected secrets
  [ok  ] conformance  35 conform, 0 nonconform, 0 unclassified; no findings
  [ok  ] hygiene      0 logins without a password, 3 http:// URLs (valid; a hint), 0 duplicate titles in a group
  [ok  ] relations    1 link, 0 broken
```
<!-- /doctor:method -->

Break something and look again: remove an expiry date from a card, rename `customer_no` to `Customer No`, or clear the
`IBAN` of the bank account (it loses its type and shows up as unclassified). `pdh check` and `pdh doctor` say what
changed and what to do about it.

## How it was made

The file is a copy of a genuine KeePassXC vault template, filled by code (`pdh-testkit`, with pykeepass) from the
profile, so it always matches the taxonomy: a test fails when the profile changes and this vault does not. After
changing a profile, regenerate it with `just example`. Because code filled it, it is a sample to read, not a vault made
by a client for end-to-end tests.

Licence: CC-BY-4.0.
