---
title: Using Specs as Inputs
description: Inspect, extend, or reimplement 35 shipped integrations using the repository spec for each one.
---

grclanker ships 35 integrations, each with a repository spec under `/specs`. The raw files remain useful as design records and portable build inputs; they are not runtime registry entries.

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

Use `grclanker tools` or the [tool catalog](/docs/tools/catalog/) to find the native tool family. Each integration guide documents authentication, collected surfaces, findings, export behavior, and limitations.

## Extend from a repository spec

Ask an agent to compare the spec with the existing implementation before changing it:

```bash
grclanker "read specs/aws-sec-inspector.spec.md, inspect the existing AWS tools, and propose an extension"
```

## Use any agent or interface

The examples below show the same spec handoff pattern across terminal agents, IDE agents, chat UIs, and programmatic flows. A spec can still seed an independent implementation, but it is no longer only a roadmap.

## Browse the raw catalog

- Site catalog: [`/specs`](/specs)
- Raw base: `https://raw.githubusercontent.com/ethanolivertroy/grclanker/main/specs`

## Why this matters

The spec states intent and constraints. The native tool family shows the shipped behavior. Use both when reviewing coverage or planning a change.
