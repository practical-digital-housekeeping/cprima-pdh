set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]
set quiet

default:
    just --list

# run all tests (e2e tests are skipped when KeePassXC is not installed)
test:
    uv run --all-packages --all-extras pytest -q

# run only the end-to-end tests on genuine vaults made by keepassxc-cli
e2e:
    uv run --all-packages --all-extras pytest -q -m e2e

# build the cprima-pdh sdist and wheel into packages/cprima-pdh/dist
build:
    uv build --package cprima-pdh --out-dir packages/cprima-pdh/dist

# run pdh from the workspace
pdh *args:
    uv run --package cprima-pdh --extra kdbx pdh {{args}}
