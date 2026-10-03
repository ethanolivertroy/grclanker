---
title: Using Specs as Inputs
description: Inspect, extend, or reimplement shipped integrations using the repository specs under /specs.
---

grclanker ships 35 integrations. The repository keeps a spec under `/specs` for every integration except Vanta, plus one for the compute backends. The raw files remain useful as design records and portable build inputs; they are not runtime registry entries.

## What a spec is

Each spec in `/specs` is a build plan for a GRC automation tool. The file describes:

- APIs
- auth
- controls and mappings
- architecture
- CLI shape
- build sequence
- current status

## Start with the shipped implementation

Use `grclanker tools` or the [tool catalog](/docs/tools/catalog/) to find the native tool family, and `grclanker tools <tool_name>` for one tool's parameters. Each integration guide documents authentication, collected surfaces, findings, export behavior, and limitations. `grclanker tools` ships in `v0.1.0`; the older `v0.0.1` release bundle does not have it, so use the catalog page there.

## Extend from a repository spec

Ask an agent to compare the spec with the existing implementation before changing it. In a grclanker session started from the repository root (`grclanker`), send:

```text
Read specs/aws-sec-inspector.spec.md, inspect the existing AWS tools, and propose an extension.
```

You can also pass the request directly: `grclanker "Read specs/aws-sec-inspector.spec.md, inspect the existing AWS tools, and propose an extension."` The older `v0.0.1` release bundle answers `Unknown command` to that form, so start the session there and type the request.

## Use any agent or interface

The same handoff works in any terminal agent, IDE agent, chat UI, or programmatic flow that can read a file or URL: point it at the spec (a repository path or the raw URL below) and at the existing tool family, then ask for a comparison or a plan. A spec can still seed an independent implementation, but it is no longer only a roadmap.

## Browse the raw catalog

- Site catalog: [`/specs`](/specs)
- Raw base: `https://raw.githubusercontent.com/ethanolivertroy/grclanker/main/specs`

## Why this matters

The spec states intent and constraints. The native tool family shows the shipped behavior. Use both when reviewing coverage or planning a change.
