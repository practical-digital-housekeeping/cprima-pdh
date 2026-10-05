# Testing cprima-pdh: taxonomy, strategy, guideline

Three parts: the words we use (taxonomy), which tests run when (strategy), how to write one (guideline).
The terms are the common ones from the testing literature, not our own; where a term is used here it means the same as there.

## 1. Taxonomy

A test is described along three independent dimensions. Mixing them up is the usual source of confusing names.

### Level: how much code is under test

| Level | Meaning | Here |
|---|---|---|
| Unit | isolated code | one function or class: profile parsing, link parsing, the SOPS MAC, the age unwrap |
| Integration | components together, with attention to their interaction | a command on a vault; the engine on a `Vault` snapshot; the txn write path |
| System (end-to-end) | the complete system | the CLI invoked on a real file, `just pdh …` against a vault |
| Acceptance | does it do what its user needs | the README examples run unchanged (`test_showcase_vault`) |

### Size: what resources a test uses (Google's definition)

| Size | Constraint | Here |
|---|---|---|
| Small | one process, no blocking calls, no network, no disk beyond a temporary directory | almost every test |
| Medium | several processes, `localhost` only, one machine | a test that starts `keepassxc-cli` or the real `sops` |
| Large | may span machines | none, and none planned |

Size and level are separate: a CLI test on a temporary vault is system level and small. A key derivation that burns CPU for minutes
is still small: it is slow, not large. Speed and determinism matter more than scope.

### Type: what the test is for

| Type | Question it answers | Here |
|---|---|---|
| Regression | did a fixed defect or a working behaviour come back? | most tests; named after the bug where there was one (`test_kdbx3_header_hash.py`) |
| Compatibility | does it behave the same across environments or variants? | every genuine KeePassXC template: KDBX 3.1, 4.0, 4.1; AES-256, ChaCha20, Twofish; Argon2d, Argon2id, AES-KDF |
| Interoperability | does an independently built implementation work with what we write and read? | `keepassxc-cli` reads vaults pdh wrote; real `sops` decrypts, and its MAC check accepts, what we produce |
| Conformance | does it comply with the specification? | the sops format against sops' own output; KDBX files against the header-hash rule |
| Contract | does every implementation of an interface behave alike? | `test_vault_contract.py` over the memory, KDBX and sops backends |
| Smoke | does the very basic thing work? | not separate yet; see 2. |

A *test oracle* is whatever decides the expected result. Ours are, besides hand-written expectations, **hand-made files** (templates
made by KeePassXC itself, kept in `pdh-testkit/vaults/`) and **independent programs** (`keepassxc-cli`, `sops`, `age`) used read-only.
pdh never wraps or calls those programs; only the tests do.

## 2. Strategy

### The sets

| Set | What is in it | How to run | Cost |
|---|---|---|---|
| **Default** | unit, integration and system tests on synthetic and messy vaults, regression tests, contract tests, border guards | `just test` serial, `just test-par` on all cores | about 70 seconds on 4 cores (1286 tests) |
| **Compatibility** | everything parametrised over a genuine template | `just test-compatibility` | about 6 minutes together with interoperability on 4 cores; the first run on a machine adds about 3 minutes to build the cheap AES-KDF copy |
| **Interoperability** | tests that run an independent program (`keepassxc-cli`, `sops`, `age`) | `just test-interoperability` | about 6 minutes together with compatibility; each test skips when its program is not installed |

The markers are `compatibility` and `interoperability`. `compatibility` is set automatically in `conftest.py` on any test whose id
names a template; the interoperability tests carry their marker. `just test-release` runs both expensive sets on all cores before
a release. Both are excluded from the default (`addopts` in `pyproject.toml`). A marker that is not registered is an error.

### Where a test lives

The directory says what the test is about, so a marker does not have to be remembered:

| Directory | Holds | Level |
|---|---|---|
| `unit/` | profile and schema parsing, link parsing, field rules, config, the public taxonomy tests | unit |
| `engine/` | validation, conform, tree and the committed example vaults, on snapshots | integration |
| `backends/` | what pdh does with the layers (backend registration, selection, refusals), the border guards between packages, the KDBX 3.x header rule through the CLI | integration |
| `commands/` | every command that changes a vault, import and merge, the database commands | integration |
| `cli/` | CLI wiring, output, doctor, inspect and check commands, the README examples | system, acceptance |
| `compatibility/` | the same behaviour on every genuine KeePassXC template | compatibility |
| `interoperability/` | `keepassxc-cli` reads what pdh wrote | interoperability |

The layers have their own tests, in their own packages (they must not need pdh): `packages/cprima-pdh-vault/tests/` holds the
Vault contract, run over memory, a KDBX file and a sops file; `packages/cprima-pdh-kdbxkit/tests/` the KDBX write API;
`packages/cprima-pdh-sopskit/tests/` the sops reader. A test that needs the pdh CLI, `txn`, `write` or the taxonomy stays in
`packages/cprima-pdh/tests/`, because a layer's test must not import pdh.

`conftest.py` marks everything under `compatibility/` and `interoperability/` accordingly, and any test whose id names a genuine
template. A single interoperability test elsewhere (the real `sops` checks in `cprima-pdh-sopskit/tests/test_sops_vault.py`)
carries the marker itself. Both markers are excluded from the default run.

### When to run what

- **While working**: the tests of the module you change (`pytest packages/cprima-pdh/tests/test_x.py`, or `-k name`), then the default set.
- **Before a commit**: the default set, green.
- **After touching the KDBX backend, the save path, a file format or key derivation** (`cprima-pdh-kdbxkit`,
  `cprima-pdh-vault/transaction.py`, `cprima-pdh-sopskit`, pdh's `txn.py` and `database.py`): the default set, then
  compatibility and interoperability.
- **Before a release**: all three sets. A release is a moment, not a kind of test; the tests that matter then are the two
  that check other environments and other implementations, which daily work does not need.
- **Never**: serial runs piped through `tail`, which print nothing until the end. Run in parallel and stream to a file.

The default set must stay fast. Anything that opens a genuine template, or starts another program, belongs in an expensive set.

### Why the split is where it is

The compatibility matrix finds defects only when code that touches format, cipher or key derivation changes (the KDBX 3.x header
hash and the Argon2id name were found that way). The default set runs the command logic on synthetic KDBX 4 vaults and the header
tests on a KDBX 3 file; the other variants differ in the file header and the key derivation, which a change to command logic does
not reach. The expensive sets are therefore a check before a risky change and before a release, not a daily one.

### Scope of verification that tests cannot give

Tests cannot show how a real client *presents* an entry or whether a GUI shows a warning. That is `docs/testing/manual-e2e.md`
and is optional.

## 3. Guideline

1. **A test is small, fast and isolated.** Use `tmp_path`; never a shared file, the working directory, or the owner's real vault.
   Tests run in parallel and in any order.
2. **Name the behaviour, not the function**: `test_a_move_keeps_the_entry_data`, not `test_move_entry_1`. A regression test names
   what went wrong.
3. **Build vaults with the testkit** (`pdh_testkit`): `synthetic_vault`, `messy_vault`, the memory vault for the engine. Do not
   hand-write XML. Genuine templates are only for compatibility.
4. **Prefer the lowest level that shows the defect.** Engine rules are tested on snapshots (`EntryData`), not through the CLI. Use
   the CLI only to test the CLI. Run a command on a real file when the file format matters.
5. **Test through the interface.** Anything that uses a vault goes through `Vault` and `execute_vault`. Only
   `cprima-pdh-kdbxkit` may import `pykeepass`, import `lxml` or use `._element`; `test_backend_borders.py` enforces it, and
   `test_package_borders.py` keeps the layers free of pdh and of each other. Tests that build or inspect a fixture may use
   pykeepass directly.
6. **Every backend answers the same contract.** A behaviour that is meant for every backend goes into
   `packages/cprima-pdh-vault/tests/test_vault_contract.py`, which runs it on memory and on a real KDBX file (and the read side on a
   sops file); memory is the test backend and is held to the same results as the others. A difference the contract finds is a
   finding, written down in the test (the tombstone one is there). One a backend lacks must raise `Unsupported`
   (`test_unsupported_writes.py`, with sops as the read-only example).
7. **Writes**: assert what changed *and* what did not (the other entries, the file header, the history count). `execute_vault`
   verifies this on every write; a test of a new command asserts its own expected result as well.
8. **Secrets**: never a real secret in a test or a fixture; the committed vaults use throwaway passwords. A test that checks output
   asserts the absence of the value as well as the presence of the report.
9. **Expensive setup is made once**, not per test. `create_database` costs over a second because it derives a key with the client's
    default settings, so `pdh_testkit.fresh_database` builds one cheap prototype per process and copies it (about 10 ms per vault).
    `pdh_testkit.cheap.cheap_copy` does the same for a genuine template: it lowers the cost of the key derivation (KDBX 3.1 has a
    million transform rounds, the AES-KDF template 39 million, the Argon2 ones seconds), keeps version and cipher, and caches the
    copy in the temporary directory. The behaviour tests do not depend on the cost; the fixture and contract checks open the
    genuine files at real cost. A test that must open a slow vault says so and carries the right marker.
10. **A new marker** is registered in `pyproject.toml` with a one-line meaning. A test that depends on an external program skips
    when it is missing and says why.
11. **A failing test is fixed or removed with a reason**, never skipped silently or loosened to pass.
12. **Time budget**: `--durations=10` is on by default. A test above about 20 seconds in the default set is a candidate for the
    expensive sets or for a cheaper fixture.

## 4. Open points

- (done) Markers are named after the terms above.
- A `smoke` set (seconds, one assertion per area) does not exist.
- A low-round AES-KDF template would let compatibility cover that key derivation without the 200 s open per test; only KeePassXC
  can make one, so it needs to come from the owner.
