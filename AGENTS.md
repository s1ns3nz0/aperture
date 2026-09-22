# Codex Harness

See [docs/harness.md](docs/harness.md) for local setup and verification commands.

Work only in this repository. Do not publish, deploy, merge, alter secrets, or
contact third parties without explicit authorization.

1. Build the MVP first: deliver the smallest testable slice before extensions,
   abstraction, automation, or polish.
2. Use Graft first for repository context: `graft ask`, `graft skeleton`, or
   `graft callers` before broad source exploration.
3. Run `$grill-me` only for product design, security, external integration,
   data/irreversible changes, or external-state changes.
4. For code, configuration, or user-visible behavior changes, run short
   `sip`/`shower` reviews before handoff.
5. Required tests and CI are Linux-first and vendor-neutral. Do not rely on
   local-only libraries, services, or OS behavior.
6. New applications and deployable artifacts must test in a suitable maintained
   Linux Docker image, pinned by digest when available. Testing never authorizes
   image push or deployment.
7. Run relevant tests and report the result concisely.
