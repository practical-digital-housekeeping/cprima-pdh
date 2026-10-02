set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]
set quiet

default:
    just --list

# run all tests
test:
    uv run --all-packages --all-extras pytest -q

# build the cprima-pdh sdist and wheel into packages/cprima-pdh/dist
build:
    uv build --package cprima-pdh --out-dir packages/cprima-pdh/dist

# run pdh from the workspace
pdh *args:
    uv run --package cprima-pdh --extra kdbx pdh {{args}}
