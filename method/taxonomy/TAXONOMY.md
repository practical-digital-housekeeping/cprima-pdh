# Taxonomy of schemas and fields

> Generated from `schemas.toml` by `pdh method show`. Do not edit by hand: change `schemas.toml`, then run `just taxonomy`.

KeePass entries are untyped bags of fields, and KeePassDX has no typed fields. Practical Digital
Housekeeping emulates the typing that 1Password offers (field types and item categories) with explicit
`_schema` fields and a controlled field vocabulary. This document describes that model. It is generated
from `schemas.toml`, so it cannot contradict the rules that `pdh` applies.

## Principles

- A record has exactly one owner (top-level group) and one area (sub-group), but one or more record types: `_schema` may name several schemas.
- Multiple rules are the norm. A record type is composed from facets, an entry may carry several schemas, and the field vocabulary applies on top. Requirements are the union, so a rule is written once and never repeated.
- Typing is explicit and lives on the entry (`_schema`), not in folder names or tags.
- The taxonomy is dogma: one concept, one canonical term. A field name outside the vocabulary is unsupported and reported as a WARN.
- Protection follows the kind of a field: secrets, keys and card numbers must be protected.
- pdh reports findings and never blocks editing. KeePass stays the source of truth.
- No secret value is ever printed by pdh.
- Entries may relate to each other through a link field (a UUID). pdh checks that a link resolves and points at an allowed record type, never what it says.
- pdh checks structure and hygiene: which fields exist, their names, their protection, whether an expiry date is set. It does not judge whether a value is correct (no checksums, no lookups); data quality is the owner's responsibility.
- Folders are for browsing; day-to-day finding is done by search.

## Axes

| Axis | Meaning | Where it lives | Status |
|---|---|---|---|
| Owner | Whose record it is | Top-level group, one per person, plus one for shared records | decided |
| Area | Which part of life it belongs to | Sub-group below the owner | implemented |
| Record type | What kind(s) of record it is; one or more per entry | `_schema` custom field with one or more schema names, emulating 1Password item categories | implemented |
| Sensitivity | How bad a leak would be | Tags (for example FinancialRisk, IdentityTheft, SecurityCritical, PrivacySensitive); never used for binding | open |

## Naming rules

- Field labels contain no spaces (decided).
- Abbreviations are written in capitals (PIN, PUK, CVV, IBAN, BIC, ICCID, IMEI, MAC, SSID); snake_case is not applied mechanically (decided).
- Other multi-word terms currently use `_` as separator (`customer_no`, `serial_number`); the style for ordinary words and for compounds that contain an abbreviation is still open.
- Schema names are kebab-case, singular, named after the record type and never after a folder.
- Only canonical terms are supported; other spellings (case, language, spacing) are renamed to the term. `mobile` and `phone` are two different terms.
- A field name that is not in the vocabulary is unsupported (WARN): rename it to a term, or remove it.
- Area names are Title Case, one to three words.

## Binding rules (`_schema`)

- An entry names its schemas in the custom field `_schema`, comma-separated.
- Every named schema applies; the requirements are the union.
- `closed` is checked against the union of all applied schemas.
- An unknown schema name is reported (`schema:unknown`); names are case-sensitive.
- No `_schema` means unclassified: only the field vocabulary applies.
- Facets are internal building blocks; `_schema` accepts schema names only.

## Areas

| Area | Meaning |
|---|---|
| Work & Tech | Professional and technical accounts: development, cloud, SaaS, AI, RPA, device vendors. |
| Shopping | Shops, marketplaces and parcel services. |
| Leisure & Interests | Creative software and media, sport, forums, culture and hobbies. |
| Online & Communication | Social networks, e-mail, messaging, domains and hosting. |
| Home & Utilities | Telecom, energy, housing, home network and devices. |
| Money | Banks, brokers, insurance and payment accounts. |
| Learning | Courses, certifications and standards bodies. |
| Identity & Authorities | Public bodies, tax and identity documents. |
| Travel & Mobility | Travel, transport and vehicles. |
| Health | Health insurance, doctors and pharmacy. |

## Record types (schemas)

### access

Accounts you log in to: websites, shops, e-mail, servers, APIs.

| Schema | Status | Description | Required | Optional | Links | Flags |
|---|---|---|---|---|---|---|
| `website` | implemented | Account at a website | `Title`, `UserName`, `Password`, `URL` | — | — | https_only |
| `onlineshop` | implemented | Online shop login | `Title`, `UserName`, `Password`, `URL` | `address`, `tel`, `customer_no`, `license_key` | — | https_only |
| `device-account` | implemented | An additional login on a device, linked to the device entry | `Title`, `UserName`, `Password`, `device` | `URL` | `device` → `wifi-access-point`, `openwrt-device` | — |

### finance

Money: payment cards, bank and broker accounts.

| Schema | Status | Description | Required | Optional | Flags |
|---|---|---|---|---|---|
| `credit-card` | implemented | Credit card: a card core plus an optional CVV | `Title` | `card_number`, `PIN`, `cardholder`, `issuer`, `issuer_phone`, `CVV` | closed, expires |
| `bank-card` | implemented | Bank card (debit, Girocard): a card core, no CVV | `Title` | `card_number`, `PIN`, `cardholder`, `issuer`, `issuer_phone` | closed, expires |
| `bank-account` | proposed | Bank or broker account | `Title`, `UserName`, `Password`, `URL`, `IBAN` | `BIC`, `account_number` | https_only |

### identity

Who you are to others: ID documents, memberships, reward programmes.

| Schema | Status | Description | Required | Optional | Flags |
|---|---|---|---|---|---|
| `identity-document` | proposed | ID card, passport, certificate and similar | `Title` | `valid_until`, `PIN` | — |
| `membership` | proposed | Membership or reward programme | `Title`, `member_no` | `valid_until` | — |

### telecom

Mobile and fixed-line subscriptions and SIM cards.

| Schema | Status | Description | Required | Optional | Flags |
|---|---|---|---|---|---|
| `sim-card` | implemented | SIM card | `Title`, `phone_number`, `PIN`, `PUK` | `ICCID`, `carrier`, `contract_no` | closed |

### contract

Customer relationships with utilities and service providers.

| Schema | Status | Description | Required | Optional | Flags |
|---|---|---|---|---|---|
| `utility-contract` | proposed | Customer account with a utility or service provider | `Title`, `customer_no` | `contract_no`, `phone`, `email` | — |

### device

Hardware and its identifiers: routers, phones, HSMs, serial numbers.

| Schema | Status | Description | Required | Recommended | Optional | Flags |
|---|---|---|---|---|---|---|
| `wifi-access-point` | implemented | Wi-Fi access point or router with Wi-Fi | `SSID`, `Title` | `wifi_key`, `URL`, `UserName`, `Password` | `serial_number`, `MAC` | — |
| `openwrt-device` | implemented | OpenWrt device: root login over the web interface and SSH | `Title` | `URL`, `UserName`, `Password` | `serial_number`, `MAC`, `ssh_key` | — |
| `hardware` | proposed | A piece of hardware with its identifiers | `Title` | — | `serial_number`, `part_number`, `MAC`, `IMEI`, `SSID`, `wifi_key` | — |
| `hsm` | proposed | Hardware security module with its PINs | `Title` | — | `serial_number`, `so_pin`, `user_pin` | — |

### keys

Cryptographic keys, licenses and recovery material.

| Schema | Status | Description | Required | Optional | Flags |
|---|---|---|---|---|---|
| `keypair` | implemented | Public/private key (SSH, GPG, ...) | `Title` | `fingerprint` | — |
| `software-license` | proposed | Software licence | `Title`, `license_key` | `serial_number` | — |
| `api-credential` | proposed | API or OAuth credential | `Title` | `api_key`, `api_secret`, `client_id`, `client_secret` | — |

## Facets (reusable bundles)

| Facet | Description | Required | Recommended | Optional | Flags |
|---|---|---|---|---|---|
| `login` | Account at a website: needs a URL, https preferred | `Title`, `UserName`, `Password`, `URL` | — | — | https_only |
| `contact` | Postal and phone contact data | — | — | `address`, `tel` | — |
| `device-core` | A piece of hardware: its identifiers | — | — | `serial_number`, `MAC` | — |
| `admin-login` | Admin login of a device: the web interface and its account | — | `URL`, `UserName`, `Password` | — | — |
| `ssh-access` | SSH access to a device: the private key | — | — | `ssh_key` | — |
| `wifi-network` | A Wi-Fi network: its name and key | `SSID` | `wifi_key` | — | — |
| `card-core` | Physical card: number, PIN, issuer, and a validity (the entry's expiry date) | `Title` | — | `card_number`, `PIN`, `cardholder`, `issuer`, `issuer_phone` | closed, expires |

## Field kinds

| Kind | Meaning | 1Password type | Normal protection |
|---|---|---|---|
| `text` | Free text. | STRING | — |
| `secret` | A secret the owner must not shoulder-surf: PIN, PUK, password, token, recovery code. | CONCEALED | protected |
| `key` | Private key material (SSH, GPG, signing keys, seeds). | SSHKEY | protected |
| `identifier` | A number or ID that is not secret: customer number, serial number, ICCID, MAC. | STRING | not protected |
| `card` | A payment card number or security code. | CREDIT_CARD_NUMBER | protected |
| `phone` | A phone number. | PHONE | not protected |
| `email` | An e-mail address. | EMAIL | not protected |
| `address` | A postal address. | ADDRESS | not protected |
| `url` | A web address. | — | not protected |
| `date` | A calendar date, such as a validity end. | DATE | not protected |
| `otp` | A one-time-password secret (TOTP/HOTP). | OTP | protected |
| `link` | A reference to another entry by UUID (a KeePass `{REF:T@I:...}` reference or the bare UUID). pdh checks that it resolves and that the target has an allowed schema; it never reads what is linked. | — | not protected |

## Field vocabulary

### text

| Term | Status | Description | Aliases | Protection | Value pattern | Families |
|---|---|---|---|---|---|---|
| `SSID` | implemented | Wi-Fi network name. | — | not checked | — | `device` |
| `public_key` | proposed | Public key; not secret. | — | must not be protected | — | `keys` |

### secret

| Term | Status | Description | Aliases | Protection | Value pattern | Families |
|---|---|---|---|---|---|---|
| `secret` | implemented | Secrets, recognised by name. Recognised by a name pattern. | — | must be protected | — | — |
| `PIN` | implemented | Numeric PIN or PUK. | — | must be protected | `[0-9]{4,8}` | `telecom`, `finance`, `identity` |
| `license_key` | implemented | Software licence key. | — | must be protected | — | `keys` |
| `wifi_key` | implemented | Wi-Fi password. | — | must be protected | — | `device` |
| `PUK` | proposed | SIM unlock code (PUK). | — | must be protected | `[0-9]{8}` | `telecom` |
| `api_key` | proposed | API key. | — | must be protected | — | `keys`, `access` |
| `api_secret` | proposed | API secret. | — | must be protected | — | `keys`, `access` |
| `client_secret` | proposed | OAuth/API client secret. | — | must be protected | — | `keys`, `access` |
| `recovery_code` | proposed | Account recovery or 2FA backup code. | — | must be protected | — | `keys` |

### key

| Term | Status | Description | Aliases | Protection | Value pattern | Families |
|---|---|---|---|---|---|---|
| `key_material` | implemented | Private key material, recognised by name. Recognised by a name pattern. | — | must be protected | — | `keys` |

### identifier

| Term | Status | Description | Aliases | Protection | Value pattern | Families |
|---|---|---|---|---|---|---|
| `serial_number` | implemented | Manufacturer serial number of a device or product. | — | must not be protected | — | `device` |
| `customer_no` | implemented | Customer or account number at a company. | — | must not be protected | — | `access`, `contract` |
| `MAC` | implemented | Network hardware (MAC) address. | — | must not be protected | — | `device` |
| `IBAN` | proposed | International bank account number. | — | must not be protected | — | `finance` |
| `BIC` | proposed | Bank identifier code (SWIFT). | — | must not be protected | — | `finance` |
| `account_number` | proposed | Account number at a bank or broker. | — | must not be protected | — | `finance` |
| `ICCID` | proposed | SIM card serial number (ICCID). | — | must not be protected | — | `telecom` |
| `IMEI` | proposed | Phone hardware identifier (IMEI). | — | must not be protected | — | `device` |
| `part_number` | proposed | Manufacturer part number. | — | must not be protected | — | `device` |
| `contract_no` | proposed | Contract or contract account number. | — | must not be protected | — | `contract` |
| `member_no` | proposed | Membership number. | — | must not be protected | — | `identity` |
| `client_id` | proposed | OAuth/API client identifier (not secret). | — | must not be protected | — | `keys`, `access` |
| `fingerprint` | proposed | Key fingerprint; not secret. | — | must not be protected | — | `keys` |

### card

| Term | Status | Description | Aliases | Protection | Value pattern | Families |
|---|---|---|---|---|---|---|
| `CVV` | implemented | Card security code. | — | must be protected | `[0-9]{3,4}` | `finance` |
| `card_number` | implemented | Card number, digits with optional spaces. | — | must be protected | `[0-9 ]{13,23}` | `finance` |

### phone

| Term | Status | Description | Aliases | Protection | Value pattern | Families |
|---|---|---|---|---|---|---|
| `phone` | implemented | Phone number (landline or general): digits with common separators or a tel: URI. | — | must not be protected | `(tel:)?\+?[0-9 ()./-]{5,}` | `contract`, `telecom` |
| `mobile` | implemented | Mobile phone number. | — | must not be protected | `(tel:)?\+?[0-9 ()./-]{5,}` | `contract`, `telecom` |

### email

| Term | Status | Description | Aliases | Protection | Value pattern | Families |
|---|---|---|---|---|---|---|
| `email` | proposed | An e-mail address. | — | must not be protected | — | `access`, `contract` |

### address

| Term | Status | Description | Aliases | Protection | Value pattern | Families |
|---|---|---|---|---|---|---|
| `address` | proposed | A postal address, one line per line. | — | must not be protected | — | `contract`, `identity` |

### date

| Term | Status | Description | Aliases | Protection | Value pattern | Families |
|---|---|---|---|---|---|---|
| `valid_until` | proposed | End of validity (card expiry, certificate, contract). | — | must not be protected | — | — |

### link

| Term | Status | Description | Aliases | Protection | Value pattern | Families |
|---|---|---|---|---|---|---|
| `device` | implemented | The device an account belongs to: a link to the device entry. | — | not checked | — | `device` |

## Sources

- [1Password CLI: item field types](https://www.1password.dev/cli/item-template-json/)
- [1Password: item categories](https://support.1password.com/item-categories/)
- [Bitwarden: custom field types](https://bitwarden.com/help/custom-fields/)
- [Bitwarden: item types](https://bitwarden.com/help/managing-items/)
- [PARA method (Forte): areas of responsibility](https://fortelabs.com/blog/para/)
- [Johnny.Decimal: areas and categories](https://johnnydecimal.com/10-19-concepts/11-core/11.01-the-system/)
- [Getting Things Done: horizons of focus](https://en.wikipedia.org/wiki/Getting_Things_Done)

## Decision log (newest first)

- 2026-10-02 **DECIDED** (user): The proposed generic schema `device` is renamed `hardware`, so that `device` only means the link field and the family; `wifi-access-point` and `openwrt-device` stay the implemented device schemas.
- 2026-10-02 **DECIDED** (user): A website account is an entry that has a URL; the `website` schema is the base and `onlineshop` is a specialisation.
- 2026-10-02 **DECIDED** (user): `Password` stays required for `website`; entries without one are findings.
- 2026-10-02 **DECIDED** (user): Folders are irrelevant for usability (search is used); area sub-groups exist for browsing only.
- 2026-10-02 **DECIDED** (user): The taxonomy is dogma: one public taxonomy, no private overlays. Field names outside the vocabulary are unsupported and reported as WARN; the taxonomy defines no aliases.
- 2026-10-02 **DECIDED** (user): Typing is by an explicit `_schema` field, comma-separated, with several schemas allowed (union). Implicit matching rules and group globs were dropped.
- 2026-10-02 **DECIDED** (user): Reusable rule bundles are called 'facets' ('sub-schema' was rejected).
- 2026-10-02 **DECIDED** (user): `phone` and `mobile` are separate vocabulary terms; 'landline' was rejected as a term.
- 2026-10-02 **DECIDED** (user): 1Password is the model for field types and item categories. KeePassDX has no typed fields, so they are emulated with `_schema` files.
- 2026-10-02 **DECIDED** (user): No spaces in field labels.
- 2026-10-02 **DECIDED** (user): No batch write command (`set-many` was rejected); the scope is the tool itself, the `linkify()` / `tel:` idea was dropped.
- 2026-10-02 **DECIDED** (user): Abbreviations such as PIN are written in capitals; snake_case is not applied mechanically. The vocabulary terms `PIN`, `CVV` and `MAC` are written that way.
- 2026-10-02 **DECIDED** (user): pdh does not validate whether values are correct (no Luhn or IBAN checksums, no lookups): the user alone is responsible for data quality.
- 2026-10-02 **DECIDED** (user): One device, many users: the device is one entry; every additional user is its own entry with the standard login fields (KeePass clients give custom fields no autofill or auto-type), linked to the device by UUID, written as a KeePass reference. The device's main login stays in its own standard fields.
- 2026-10-02 **DECIDED** (user): `credit-card` (CVV allowed, not required) and `bank-card` (no CVV) replace `payment-card`; the shared part is the facet `card-core`; a card's validity is the entry's own expiry date.
- 2026-10-02 **DECIDED** (user): `http://` is a valid URI: pdh never treats it as an error; at most it is a WARN-level hint. Nothing may present it as a problem of its own invention.
- 2026-10-02 **OPEN** (user): Open question left from the log-level discussion: do the existing value-based checks (`pattern`) stay at all? They are INFO-level hints for now.
- 2026-10-02 **DECIDED** (user): Findings carry a level taken 1:1 from log levels: ERROR (broken structure, a `required` field missing, an unknown schema), WARN (hygiene such as `http://`, an unprotected secret, a missing `recommended` field or expiry date), INFO (format hints such as `pattern`). `validate --level` filters the display, `--fail-on` (default ERROR) decides the exit code. On the schema side the matching tiers are `required` (MUST), `recommended` (SHOULD) and `optional` (MAY).
- 2026-10-02 **OPEN** (user): Label style for the rest: separator and case of ordinary multi-word terms (`customer_no` versus `CustomerNo`) and of compounds that contain an abbreviation (`SO_PIN`, `API_key`, `User_PIN`).
- 2026-10-02 **OPEN** (user): Final list of kinds and families (the ones here are a first proposal).
- 2026-10-01 **DECIDED** (user): `URL` is required for online shops and websites; entries without a URL are findings, not exceptions.
- 2026-10-01 **DECIDED** (user): Tags are not used to bind schemas to entries.
- 2026-10-01 **DECIDED** (user): Backups are the user's job. pdh never copies or backs up the database file, and writes are dry runs unless `--apply`.
