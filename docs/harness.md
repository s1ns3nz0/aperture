# Aperture Codex harness

The repository-local harness comes from [s1ns3nz0/codex-harness-s1ns3nz0](https://github.com/s1ns3nz0/codex-harness-s1ns3nz0), revision `10a0859e929407a41e3a5629302c46ccb3c73297`.

Run these commands from the repository root with Node.js 20 or newer. The harness has no npm dependencies, so no `npm install` is needed.

```sh
npm run harness:check
npm run harness:verify
```

`harness:check` validates configuration without executing adapters. `harness:verify` also runs the harness's Node.js tests. To run Aperture's existing Go unit-test target, use:

```sh
npm run harness:verify -- --adapter go
```

Selecting `--adapter go` runs the Go adapter instead of the default Node.js adapter, after validating configuration. The Go adapter requires the toolchain declared in [go.mod](../go.mod) and any prerequisites of `make unit`; its test command remains defined by the existing [Makefile](../Makefile). Dashboard commands remain in `dashboard/package.json`.

[AGENTS.md](../AGENTS.md) is the agent guide, and [harness.config.json](../harness.config.json) defines policy and adapters. `npm run harness:init` creates missing `harness.config.json` and `docs/project.md` files and fills a placeholder project identity. It preserves an existing project identity and project document.

The agent environment supplies Graft, `grill-me`, `sip`, and `shower` separately. This installation records the upstream skill references in `harness/*.lock`; it does not install or verify global skill revisions. If Graft has no index, use focused file searches to inspect the repository.

Runtime files under `.harness/` and the Graft cache are ignored. This installation adds no CI workflow; verification commands are available locally.
