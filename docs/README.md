# rvl documentation

Start here if you want to scan a repo:
[Scanning your repo with rvl](scanning.md) covers install, the free no-key
tier, reading the output, hooks, waivers, and the coding-agent loop, end to
end.

## For users

| Document | What is in it |
| --- | --- |
| [Scanning your repo with rvl](scanning.md) | The end-to-end user guide. Install (cask + release archives), the free OSS tier and its license, reading the ladder and COVERAGE, exit codes, hooks, suppress/bounds/waivers, the audited force escape hatch, the agent loop, privacy. |
| [Command reference](commands.md) | Every command, grouped by what it is for, including submission mode's full flag set. |
| [Gating commits and CI](gating.md) | Git hooks, the exit-code contract, `--strict`, the empty-lane guard, and asserting on coverage in CI. |
| [Configuration](configuration.md) | `.revelara.yaml` keys, environment variables, the tiered spec cache, compatibility flags. |
| [Privacy](privacy.md) | What can and cannot ride on the wire, how to see it, and how submission mode differs. |
| [Coding-agent skills and lenses](agent-skills.md) | `rvl skills` / `rvl plugin`, the `/rvl:*` commands, and the managed context block. |
| [How a scan finds your code](retrievers.md) | Per-language retrievers, their toolchain prerequisites, the five resolution slots, and what a green `doctor` does and does not prove. |

## For contributors and integrators

| Document | What is in it |
| --- | --- |
| [The `--out` document contract](out-contract.md) | The machine-readable scan document (`rvl-scan/v1`) consumed by orchestrators; the external spec for `crates/rvl/src/out_doc.rs`. |
| [Releasing](releasing.md) | Cutting a release, and how each retriever helper is packaged. |

The repository's top-level [README](../README.md) covers building, testing,
workspace layout, and where a change goes.
