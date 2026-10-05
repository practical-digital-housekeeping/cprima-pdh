# Practical Digital Housekeeping: ideas, backlog and open questions

Status: living document. The normative model is `method/taxonomy/schemas.toml` and the generated
`method/taxonomy/TAXONOMY.md`; this file holds ideas, open questions and parked items. Decisions about the taxonomy
go to its decision log (`just taxonomy` regenerates the document). Licensed under CC-BY-4.0.

Legend: **NEXT** = ready to do · **BACKLOG** = wanted, not scheduled · **IDEA** = not yet decided · **OPEN** = needs a
decision · **PARKED** = deliberately not now · **REJECTED** = decided against, do not revive.

---

## 1. Vision: a method, not only a tool  (IDEA)

One source of truth (the taxonomy: terms, facets, schemas, areas, decisions) feeding three artifacts:

| Artifact | Job | Notes |
|---|---|---|
| **A small book** | explains the method (why, principles, axes, naming, record types, routines, continuity, working with an agent) | reference chapters generated from the taxonomy; examples anonymised |
| **The tool (`pdh`)** | applies the method: inspect, check, edit | tests are the executable specification |
| **Agent skill / instructions** | lets an AI agent run the *checks* safely | see section 5 |

Related prior art: Johnny.Decimal (locations/IDs; complementary, PDH is typing and hygiene), PARA, GTD areas of
focus, 1Password and Bitwarden item and field types (see the sources in `TAXONOMY.md`).

---

## 2. Next  (NEXT)

1. **Simplify the engine.** The default profile uses no schema-local `aliases` or `types` (a test enforces it); remove
   the engine support for them. Schema-to-vocabulary integrity is done: every field a record type names is a term.
2. **`new-entry` has no tests** yet; the write paths in general need tests on real (synthetic) vault files.
3. **Profiles beyond `pdh-default`.** The structure is ready: a profile is named by its taxonomy and its own name
   (`pdh` + `default` = `pdh-default`, file `profiles/pdh-default.toml`), selected with `--profile`, `PDH_PROFILE` or the
   `profile` key in the config. A second profile needs a reason and an owner. Open: recording the profile and version
   in the vault so `doctor` can say which one a vault follows.

---

## 2b. The profile drives everything  (NEXT, in progress)

The profile is the single source of truth; the engine only interprets it, and the `kdbx` backend (extra
`cprima-pdh[kdbx]`) owns how it is stored in KeePass. Moved into the profile or the backend so far (2026-10-03):
finding levels (`[level]`), standard fields (`[standard.*]`) and their KeePass storage (`cprima_pdh_kdbxkit/kdbx_format.py`:
attribute mapping, protected standard fields, OTP plugin prefixes, how each field kind is stored), the list of field
kinds (`[kind.*]`; `behaviour = "link"` marks the kind that holds an entry reference), the default area per record type
(`area =` on `[schema.*]`) and example values (`example =` on kinds, terms and standard fields, checked against the
term's pattern) and what `conform` advises per finding (`[advice.*]`). A test checks that none of it is defined twice. Still duplicated in code, to move next:
1. the binding field name `_schema` (many string literals) -> `[binding]`;
2. generated reference pages per record type with a worked example, and a second, tiny profile that proves nothing
   else is coupled to the default one.

---

## 2c. Vault capabilities: GUI parity  (DONE, 2026-10-03)

Every function of a KeePass GUI client has a command (dry run unless `--apply`, one save, reopened and verified,
previous state kept in the entry's history): entries (delete to the bin, restore, purge, clone, tags, expiry, icon,
colours, URL override, auto-type, history restore/prune, attachments), groups (rename, move, delete, notes, icon),
the database (create, password, key file, settings, key derivation, empty bin), `io` (CSV and vault import, merge,
export), `generate`, `inspect otp`, and the online checks `check known-passwords` / `check breaches`.
Not offered: KDBX 3 to 4 conversion (pykeepass cannot), auto-type and browser integration, the graphical UI.
Since then: every write goes through `txn.execute` (a test enforces it; bulk edits snapshot each touched entry);
the write commands run on the genuine KDBX 3.1 and 4.0 templates (`just test-compatibility`, a few minutes on all cores: run it when preparing a release); breach and
leaked-password findings take level and advice from the profile; `inspect inventory` reports history and attachment
totals; `delete` records `PreviousParentGroup` in KDBX 4.1 vaults. Open: a hand-made KDBX 4.1 template and the manual
checks in `docs/testing/manual-e2e.md` (only a human with KeePassXC and KeePassDX can do them).

---

## 2d. Vault interface and the sops+age backend  (IN PROGRESS, 2026-10-03)

The engine reads snapshots (`EntryData`) from a `Vault` (`cprima_pdh_vault`); `cprima_pdh_kdbxkit`, `cprima_pdh_vault.memory` and `cprima_pdh_sopskit`
implement it (separate packages in this repository, bundled into the `cprima-pdh` wheel). Done: the interface and the contract tests; the validator, `read`, `links`, `unclassified`, `conform`, `tree`, `infer`,
`inventory`, `records`, `doctor` and the online/CSV/otp readers on snapshots (the XPath engine stays as the parity reference
`*_xpath` until the write side has moved); read-only sops+age for JSON, verified against the real `sops` binary (values, MAC, several
recipients, `mac_only_encrypted`). Next: the write side onto operations and `txn` (the KDBX workarounds move into `KdbxVault`), a temp-file
write that replaces the vault only after verification, refusing to write unverified formats, backend choice in the config, sops YAML,
creating a sops file from a vault (an encrypted backup), and the `pdh sops ...` audit commands for arbitrary sops files.

---

## 3. Taxonomy and engine  (BACKLOG / OPEN)

- **Relations are implemented:** a field of kind `link` holds another entry's UUID (a KeePass `{REF:T@I:...}`
  reference or the bare UUID). Schemas declare `links = { device = [...] }`; `pdh check validate` reports
  `link:invalid` / `dangling` / `self` (ERROR), `wrong-schema` (WARN), `target-unclassified` (INFO). `pdh edit link`
  writes it, `pdh inspect links` lists it. KeePassXC shows a `{REF:...}` value as the target's title; KeePassDX still
  to verify by hand.  (OPEN)
- Reuse links for other relations: SIM and contract, key and device, card and bank account.  (IDEA)
- Back-links ("this device has N accounts") per device in `review`.  (IDEA)
- **Case-insensitive matching** of field names, with the canonical form still reported. Edge case: two fields
  differing only by case in one entry.  (OPEN: scope)
- **Field kinds with structural behaviour** (modelled on 1Password field types): a kind supplies defaults such as
  protection; no validators (see rejected).  (BACKLOG)
- **Date rules** for validity: "expires within N days" as a reminder (WARN), not a correctness check.  (OPEN)
- **Facet vs schema:** kept as "is a" (schema) versus "has a" (facet). Idea: let `_schema` name facets too.  (IDEA)
- **Sensitivity axis** (tags such as FinancialRisk, IdentityTheft): derive from schema or kind instead of tagging by
  hand? Never used for binding.  (IDEA)
- **Default area per schema** to suggest where an entry belongs.  (IDEA)
- **More schemas** (proposed in the taxonomy): bank-account, utility-contract, hardware, hsm, identity-document,
  membership, software-license, api-credential. The `sim-card` draft needs checking against real SIM records.  (BACKLOG)

---

## 4. Features and commands  (BACKLOG / IDEA)

- `pdh inspect fields`: every distinct custom field name with count; next: mapped term or kind, gaps flagged.
- `pdh check conform`: conform / nonconform / unclassified per entry; every issue carries an `action`, an
  `automatable` flag and a `command`. Open: entries sharing one `group/title` are merged in the report.
- `pdh review`: one short monthly digest (new unclassified, expiring validity, duplicates, unprotected secrets).
- `pdh expiring --days N`: validity horizon across all owners.
- Duplicates / retire report: copies and clones, accounts without purpose; reports only, never deletes.
- Continuity overview: critical records per area and owner, where the secret lives, **no secret values**.
- 2FA coverage and password reuse by area (counts only).
- `pdh init`: starter taxonomy for a fresh vault.
- `classify` (parked, low priority): `pdh inspect classify`, read-only; proposes `_schema` values from structure, never a
  runtime binding. Design worked out: an entry fits a record type when it has every required field and at least one
  field the type names; a closed type refuses fields it does not allow; best fit = most recognised fields, then the
  smaller type; further types only for fields the first does not explain; unclear entries say why (missing required
  field, closed type, nothing but a title). Ground truth for tests: strip `_schema` from the canonical vault and
  expect the types back (`onlineshop, website` is recognised as `onlineshop`, which already contains the login).
- Label-space lint with a mechanical rename suggestion.
- A read-only MCP server exposing the checks to agents, as an extra of the same package.  (IDEA, later)

---

## 5. Agent skill  (IDEA)

Protocol the skill must encode:
1. The human unlocks the session (`pdh session unlock`) and quits KeePassXC; the agent cannot enter the master password.
2. Run `pdh check validate --summary`, then details by level; use JSON output (`-f json`).
3. Never print or read a secret value outside pdh.
4. Every write is a dry run first; `--apply` only after an explicit go-ahead; no backups by the tool (owner's job).
5. Report: errors, warnings, unclassified, expiring.
6. Taxonomy decisions go into the decision log with a test; `just test` must pass.
7. Lock the session when done (`pdh session lock`); tests never touch the real session.

---

## 6. Open questions  (OPEN)

1. Field names with spaces in a vault: rename mechanically (`_`) or by hand? (The label style itself is decided:
   snake_case, capitals only for a term that is an abbreviation; `pattern` stays at INFO.)
2. Final list of kinds and families (first proposal in `profiles/pdh-default.md`).
3. Case-insensitive matching scope.
4. Is "expires within N days" a reminder (structure) or a value check?
5. Rules as Python predicates or XPath (today: XPath)?

---

## 7. Parked and rejected  (do not revive without new reasons)

| Item | Status | Why |
|---|---|---|
| Batch write command (`set-many`) | REJECTED | separate `set` calls instead |
| Input-file driven writers | REJECTED | scripts contain their data so they stay readable |
| Tool-made backups / copies of the vault | REJECTED | backups are the owner's job; pdh never duplicates the file |
| Checksum validators (Luhn, IBAN) and lookups | REJECTED | the owner alone is responsible for data quality |
| `linkify()` / `tel:` links | REJECTED | out of scope |
| Tags as schema binding | REJECTED | explicit `_schema` field instead |
| Group globs (typing by folder) | REJECTED | folders are for browsing; typing is by `_schema` and/or fields |
| ~~Implicit matching rules~~ | **now implemented** | `[[match]]` rules bind a type from fields that belong to one type alone; `_schema` and/or rules, union (2026-10-03) |
| A `CVV` match rule (credit-card) | REJECTED | `bank-card` is `closed` so a CVV on it is reported; a rule would turn it into a second type |
| `landline` as a term | REJECTED | `phone` and `mobile` are the two terms |
| "sub-schema" name | REJECTED | called facet |
| `http://` presented as a problem | REJECTED | `http://` is a valid URI; WARN at most |
| Default output to files | REJECTED | stdout only; files only on explicit request |
| Private taxonomy overlays, vault-specific aliases | REJECTED | the taxonomy is dogma; other names are WARN |
| Wrapping external programs (e.g. keepassxc-cli) | REJECTED | implement from scratch or by Python import |
| Moving entries across owners by default | REJECTED | `pdh edit move` refuses cross-top-level moves unless `--cross-top-level` |

---

## 8. Process notes

- Quit KeePassXC fully (tray, Quit) before pdh writes and after; a stale long-running instance fails saves with "Access is denied".
- One session cache for all vaults; tests use a temporary `PDH_SESSION_FILE` (set by the test kit).
- Long batches (about 14 s per write on a real vault) run in the background with `pdh session unlock --minutes N`.
- Tests (`just test`, no vault file): `pdh_testkit.stubs` builds in-memory entries and XML; `pdh_testkit.synthetic_vault`
  writes fast real files. Prefer a table-driven case.
- `TAXONOMY.md` and the packaged copy of the taxonomy are generated; `just test` fails when they are stale.
