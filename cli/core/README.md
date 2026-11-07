# Shared GRC core

This directory supplies GRC capabilities to every agent host. SDK adapters and the Pi extension consume core; core does not start an agent, load a provider adapter, create shell/file tools, or register terminal lifecycle hooks.

| Change | Start here |
| --- | --- |
| Add a tool family to the shared registry | `domain-tools.ts` |
| Declare a native tool without depending on an agent SDK | `tool-definition.ts` |
| Discover a callable tool by its native name | `registry.ts` |
| Normalize and validate arguments | `arguments.ts` |
| Execute a tool or enforce the default write gate | `tools.ts` |
| Convert schemas or format tool results | `schema.ts`, `results.ts` |
| Classify write effects and scrub credentials | `effects.ts`, `redact.ts` |
| Describe tools for catalogs, help, and the generated website inventory | `tool-catalog.ts`, `tool-manifest.ts` |
| Publish configuration or a generated snapshot with recovery | `atomic-files.ts` |
| Load GRC instructions, workflows, skills, and personas | `instructions.ts`, `workflow-prompt.ts`, `skills.ts`, `personas.ts` |
| Call a tool from a local subprocess | `cli.ts` |

Native integrations remain in `../extensions/grc-tools/`. They accept a `GrcToolRegistrar` and define `execute(callId, args, signal)` without a terminal context. `domain-tools.ts` registers those implementations and applies cancellation policy. `tools.ts` prepares and strictly validates arguments, then returns content and host metadata with redacted errors. SDK adapters explicitly strip metadata from model-visible results. Pi adds its seven compute tools and terminal hooks in `../extensions/grc-tools.ts`; other hosts supply their own capabilities.

Core validates schemas with TypeBox directly. It imports no agent SDK, including Pi's validation library. The regression suite blocks those packages and adapter modules in a fresh process, then discovers tools, loads a workflow, and executes a real offline tool. Separate differential tests compare the native validator with the actual Pi validator through Pi's schema adapter.

The common package's dependencies, build, and assets are still owned by `../package.json`. This source boundary is not a separately distributed npm package. See [`../README.md`](../README.md) for the repository code map and [`../adapters/README.md`](../adapters/README.md) for SDK entrypoints.

Atomic multi-file and directory publication reserves its journal before staging, holds a kernel-released SQLite lock through cleanup, and recovers interrupted publications on the next journal-aware read. The private adjacent `.<journal basename>.lock.sqlite` file contains publication metadata, not configuration values. It remains after use so concurrent processes always lock the same inode; do not remove it while a publisher may be running. Recovery of a missing journal performs no filesystem writes.
