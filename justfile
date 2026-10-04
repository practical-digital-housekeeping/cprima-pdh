set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]
set dotenv-load
set quiet

# The vault comes from KDBX_FILE (and KDBX_KEY) in the environment or a .env file; never committed.

default:
    just --list

# the fast set (the default): seconds to a few minutes
test:
    uv run --all-packages --all-extras pytest -q

# the fast set on all cores
test-par:
    uv run --all-packages --all-extras pytest -q -n auto

# interoperability: independent programs (keepassxc-cli, sops, age) read what pdh wrote; each skips when its program is missing
test-interoperability:
    uv run --all-packages --all-extras pytest -q -n auto -m "interoperability and not compatibility"

# compatibility: the same behaviour on every genuine template (all KDBX versions, ciphers, key derivations); about an hour
test-compatibility:
    uv run --all-packages --all-extras pytest -q -n auto -m compatibility

# both expensive sets, on all cores, before a release or after touching the file formats
test-release:
    uv run --all-packages --all-extras pytest -q -n auto -m "compatibility or interoperability"

# build the cprima-pdh sdist and wheel into packages/cprima-pdh/dist
build:
    uv build --package cprima-pdh --out-dir packages/cprima-pdh/dist

# refresh every profile's generated document (<name>.md) and its packaged copy from method/taxonomy/profiles/<name>.toml
taxonomy:
    uv run --all-packages python -c "from pathlib import Path; import shutil; from cprima_pdh import schema, taxonomy; [(Path(src.with_suffix('.md')).write_text(taxonomy.build(schema.load_schemas(src)).markdown, encoding='utf-8'), shutil.copyfile(src, 'packages/cprima-pdh/src/cprima_pdh/data/profiles/' + src.name)) for src in sorted(Path('method/taxonomy/profiles').glob('*.toml'))]"

# regenerate the canonical vault fixture from the default profile (run after changing a profile)
canonical:
    uv run --all-packages python -m pdh_testkit.canonical

# regenerate the showcase vault in examples/pdh-default/ (run after changing a profile)
example:
    uv run --all-packages python -m pdh_testkit.showcase

# run pdh from the workspace, e.g. `just pdh check conform -f json`
pdh *args:
    uv run --all-packages --all-extras pdh {{args}}

# overview: pdh, backend, taxonomy, vault, lock/sync conflicts, session, conformance (never prompts)
doctor *args:
    uv run --all-packages --all-extras pdh doctor {{args}}

# entries that do not conform (add --status all, -f json, ...)
check *args:
    uv run --all-packages --all-extras pdh check conform {{args}}

# every finding with its level (--summary for counts)
validate *args:
    uv run --all-packages --all-extras pdh check validate {{args}}

# group hierarchy with entry counts
tree *args:
    uv run --all-packages --all-extras pdh inspect tree {{args}}

# all entries
entries *args:
    uv run --all-packages --all-extras pdh inspect entries {{args}}

# cache the master password (default 30 min: --minutes N)
unlock *args:
    uv run --all-packages --all-extras pdh session unlock {{args}}

# discard the cached session
lock:
    uv run --all-packages --all-extras pdh session lock

# session state
status:
    uv run --all-packages --all-extras pdh session status
