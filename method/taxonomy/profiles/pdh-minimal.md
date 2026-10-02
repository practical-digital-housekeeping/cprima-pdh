# pdh-minimal: profile pdh-minimal

> Generated from the profile `pdh-minimal` (version 0.1) by `pdh method show`. Do not edit by hand: change the profile file, then run `just taxonomy`.

**Profile `pdh-minimal` 0.1** (profile `minimal` of the taxonomy `pdh`). A tiny complete profile: three areas, three record types, its own binding field. Proof that the profile drives everything.

The smallest complete profile: it shows what a profile has to state and that the engine reads nothing else.

## Areas

| Area | Meaning |
|---|---|
| Accounts | Logins. |
| Money | Accounts and cards. |
| Other | Everything else. |

## Record types (schemas)

### (no family)

| Schema | Status | Description |
|---|---|---|
| `login` | implemented | A login at a website. |
| `account` | implemented | A bank account. |
| `card` | implemented | A payment card. |

## Field-based matching

A record type can also follow from the fields an entry has, with or without a `_schema`: the types of an entry are the union of both. A rule fires when an entry has every listed field (non-empty).

| Record type | Bound when an entry has |
|---|---|
| `account` | `iban` |

## Facets (reusable bundles)

| Facet | Description | Required | Optional | Flags |
|---|---|---|---|---|
| `login` | — | `Title`, `UserName`, `Password`, `URL` | — | https_only |

## Finding levels

Findings carry a level, like log levels. An exact rule id wins over its kind (the part before the colon), which wins over the default (`WARN`).

| Rule or kind | Level |
|---|---|
| `required` | ERROR |
| `pattern` | INFO |
| `schema:unknown` | ERROR |

## Advice

What `pdh check conform` suggests per finding; the most specific key wins. `auto` = an agent may run the command without asking the owner.

| Rule or kind | Action | Auto | Command | Note |
|---|---|---|---|---|
| `default` | review | no | — | the finding's message |
| `required` | supply-value | no | `pdh edit set {entry} {term} <value> --apply` | ask the owner for the value; never invent one |
| `schema:unknown` | fix-schema | no | `pdh edit set {entry} {binding} <type> --overwrite --apply` | name a record type from `pdh method schemas`, or drop the field |
| `pattern` | review-value | no | — | format hint only |

## Standard fields

What every entry has. How a store keeps them is the backend's business.

| Field | Kind | Meaning |
|---|---|---|
| `Title` | text | The entry's title. |
| `UserName` | text | The user name of a login. |
| `Password` | secret | The password of a login. |
| `URL` | url | The web address of a login. |
| `Notes` | text | Free-form notes. |
| `otp` | otp | The one-time-password secret of an entry. |

## Field kinds

| Kind | Meaning | 1Password type | Normal protection |
|---|---|---|---|
| `text` | Free text. | — | — |
| `secret` | A secret. | — | protected |
| `identifier` | A number or ID that is not secret. | — | not protected |
| `url` | A web address. | — | not protected |
| `otp` | A one-time-password secret. | — | protected |

## Field vocabulary

### secret

| Term | Status | Description | Aliases | Protection | Value pattern | Families |
|---|---|---|---|---|---|---|
| `pin` | implemented | A numeric PIN. | — | must be protected | `[0-9]{4,8}` | — |

### identifier

| Term | Status | Description | Aliases | Protection | Value pattern | Families |
|---|---|---|---|---|---|---|
| `customer_id` | implemented | An identifier a provider gave you. | — | not checked | — | — |
| `iban` | implemented | An international bank account number. | — | not checked | — | — |

## Decision log (newest first)

- 2026-10-03 **DECIDED** (user): A second, tiny profile exists to prove that nothing outside a profile file is tied to pdh-default.
