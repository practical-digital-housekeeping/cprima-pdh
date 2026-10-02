set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]
set dotenv-load
set quiet

# The vault comes from KDBX_FILE (and KDBX_KEY) in the environment or a .env file; never committed.

default:
    just --list

# run all tests
test:
    uv run --all-packages --all-extras pytest -q

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
