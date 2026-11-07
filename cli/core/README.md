# Shared GRC core

This directory supplies GRC capabilities to every agent host. SDK adapters and the Pi extension consume core; core does not start an agent, load a provider adapter, create shell/file tools, or register terminal lifecycle hooks.

| Change | Start here |
| --- | --- |
| Add a tool family to the shared registry | `domain-tools.ts` |
| Discover a callable tool by its native name | `registry.ts` |
| Normalize and validate arguments, execute a tool, or enforce the default write gate | `tools.ts` |
| Convert schemas or format tool results | `schema.ts`, `results.ts` |
| Classify write effects and scrub credentials | `effects.ts`, `redact.ts` |
| Describe tools for catalogs and help | `tool-catalog.ts` |
| Load GRC instructions, workflows, skills, and personas | `instructions.ts`, `workflow-prompt.ts`, `skills.ts`, `personas.ts` |
| Call a tool from a local subprocess | `cli.ts` |

Native integrations remain in `../extensions/grc-tools/`. `domain-tools.ts` registers those same implementations and applies the shared strict-schema and cancellation policies. Pi adds its seven compute tools and terminal hooks in `../extensions/grc-tools.ts`; other hosts supply their own capabilities.

Core uses the Pi AI validation library and type-only native tool contracts. It does not load the Pi coding-agent host. The regression suite proves this by blocking host packages and adapter modules in a fresh process, then discovering the domain tools, loading a workflow, and executing a real offline tool.

The common package's dependencies, build, and assets are still owned by `../package.json`. This source boundary is not a separately distributed npm package. See [`../README.md`](../README.md) for the repository code map and [`../adapters/README.md`](../adapters/README.md) for SDK entrypoints.
