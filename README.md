# Practical Digital Housekeeping

Keep your digital life in order, starting with your password database.
**Keep it tidy. Keep it trustworthy.**  Website: https://pdh.cprima.net

This monorepo holds the method and its companion tool `pdh`, published on PyPI as
[`cprima-pdh`](packages/cprima-pdh/).

```powershell
uvx --from "cprima-pdh[kdbx]" pdh doctor --db vault.kdbx
```

| Path | Content |
|---|---|
| `examples/pdh-default/` | **a sample vault**: a fictional, finished vault organised by the profile, with a tour ([README](examples/pdh-default/README.md)) |
| `method/taxonomy/profiles/` | the taxonomy profiles (source of truth, `pdh-default.toml`) and their generated documents |
| `packages/cprima-pdh/` | the Python package (`pdh` command) |
| `packages/pdh-testkit/` | test support, never published: stubs, synthetic vaults, genuine vault fixtures with sidecars |
| `docs/` | ideas, backlog and open questions |
| `biz/marketing/` | messaging |

Development: `just test`, `just doctor`, `just taxonomy` (regenerates the profile documents and the packaged copies),
`just example` (regenerates the sample vault), `just canonical` (regenerates the canonical test fixture).

## Licences

- Code: Apache-2.0 ([LICENSE](LICENSE))
- Documentation and method texts: CC-BY-4.0
