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

1. **Schema-to-vocabulary integrity.** With the taxonomy as dogma, a schema should only name fields that are
   vocabulary terms (or standard fields). Today `cardholder`, `issuer`, `issuer_phone`, `carrier`, `phone_number`,
   `tel` are not terms. Promote them or drop them.
2. **Simplify the engine.** Remove schema-local `aliases` and the `types` mapping (field names are terms).
3. **`new-entry` has no tests** yet; the write paths in general need tests on real (synthetic) vault files.

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
- `classify`: dry run that only *proposes* `_schema` values from structure, never a runtime binding.
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

1. Label style beyond abbreviations: separator and case of ordinary multi-word terms (`customer_no` vs `CustomerNo`),
   and compounds containing an abbreviation (`SO_PIN`, `API_key`, `User_PIN`).
2. Field names with spaces: rename mechanically (`_`) or by hand?
3. Final list of kinds and families (first proposal in `TAXONOMY.md`).
4. Does `pattern` stay at all (currently INFO)?
5. Case-insensitive matching scope.
6. Is "expires within N days" a reminder (structure) or a value check?
7. Rules as Python predicates or XPath (today: XPath)?

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
| Implicit matching rules, group globs | REJECTED | explicit `_schema` only; rules at most as seeding aid |
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
