---
title: Using Specs as Inputs
description: Inspect, extend, or reimplement shipped integrations using the repository specs under /specs.
---

A spec is a Markdown description of one grclanker integration: its APIs, authentication, checks, framework mappings, and outputs. Give a spec and the shipped tools to grclanker or any other agent to review coverage, plan an extension, or build your own implementation.

The repository's `specs/` folder holds 35 specs: one for each vendor integration except Vanta, plus one for the compute backends. grclanker does not load specs at runtime. The [tool catalog](/docs/tools/catalog/) lists the tools it registers.

## What a spec contains

Specs come in two kinds. The frontmatter `status` names the kind, and generated specs also open with a note saying so.

- `generated` specs are rebuilt from the shipped code, so they describe what the tools do today: each tool and its parameters, authentication and permissions, the API requests, pagination and rate limits, the checks and their framework mappings, the export layout, and known runtime gaps. They are language-neutral and build on a shared contract, `specs/integration-contract.md`, for rules every integration follows, such as reporting unavailable data as null instead of an empty list.
- `implemented` specs are the hand-written build plans that the remaining integrations and the compute backends were built from. Most follow the same outline: overview, APIs, authentication, security controls, framework mappings, existing tools, architecture, CLI interface, build sequence, and status. They record intent, so check them against the shipped tools.

## Where to find the specs

- Site catalog: [`/specs`](/specs)
- Raw files: `https://raw.githubusercontent.com/ethanolivertroy/grclanker/main/specs`

## Start with the shipped tools

Find the integration's tools before you read its spec. `grclanker tools` lists every tool, `grclanker tools <tool_name>` shows one tool's parameters, and the [tool catalog](/docs/tools/catalog/) has the same list. Each integration guide documents authentication, collected surfaces, findings, export behavior, and limitations.

`grclanker tools` ships in `v0.1.0` and later. The older `v0.0.1` release bundle does not have it, so use the catalog page there.

## Extend an integration from its spec

Ask an agent to compare the spec with the existing implementation before you change anything. Start a grclanker session from the repository root (run `grclanker`) and send:

```text
Read specs/aws-sec-inspector.spec.md, inspect the existing AWS tools, and propose an extension.
```

You can also pass the request directly: `grclanker "Read specs/aws-sec-inspector.spec.md, inspect the existing AWS tools, and propose an extension."` The older `v0.0.1` release bundle answers `Unknown command` to that form, so start the session there and type the request.

Don't edit a generated spec by hand. It is rebuilt from the tool definitions, `cli/extensions/grc-tools/spec-registry.ts`, and the prose in `specs/narratives/`. After you change those, run `npm --prefix cli run sync:integration-specs`. CI fails when a generated spec is out of date.

## Use a spec with any agent

The same request works in any terminal agent, IDE agent, chat UI, or programmatic flow that can read a file or URL. Point the agent at the spec, by repository path or raw URL, and at the existing tool family, then ask for a comparison or a plan. A spec can also seed an independent implementation.

Here is the AWS request for common agents and interfaces:
