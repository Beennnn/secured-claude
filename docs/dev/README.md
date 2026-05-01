# Developer documentation

Hands-on docs for working ON `secured-claude` (vs operating it). Read the
[main README](../../README.md) first for the project pitch + architecture
overview ; the docs here assume you've cloned the repo and want to run
the gates locally / extend a feature / debug an issue.

## Index

- [`developer-environment.md`](developer-environment.md) — set up `uv`,
  Docker, IDE integration ; cross-platform pitfalls (Mac / Linux /
  Windows). Start here.
- [`agent-container-debug.md`](agent-container-debug.md) — debug recipe
  for the agent container : how to read Claude Code's debug log, inspect
  `/proc` without `ps`, distinguish a hang from a silent exit. Captures
  the v0.8.2 root-cause investigation as a reusable playbook.

## Where else to look

- [`docs/adr/`](../adr/) — architecture decisions (47 ADRs covering
  every load-bearing security or operational choice)
- [`docs/security/`](../security/) — threat model, controls matrix,
  supply-chain story, vulnerability disclosure
- [`CHANGELOG.md`](../../CHANGELOG.md) — per-version history (each
  entry links to the full annotated git tag)
- [`CONTRIBUTING.md`](../../CONTRIBUTING.md) — commit conventions, ADR
  flow, testing standards, where the gates live
