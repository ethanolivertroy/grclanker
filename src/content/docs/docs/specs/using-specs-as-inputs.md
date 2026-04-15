---
title: Using Specs as Inputs
description: Treat the repo’s spec files as build inputs for the companion instead of as a separate product.
---

The spec library is still a core surface of the project. The difference now is that the companion is the front door and the specs are one of the things it can work on directly.

## What a spec is

Each spec in `/specs` is a build plan for a GRC automation tool. The file describes:

- APIs
- auth
- controls and mappings
- architecture
- CLI shape
- build sequence
- current status

## Use a repo-local spec directly

```bash
grclanker "read specs/aws-sec-inspector.spec.md and build the tool"
```

## Use any agent or interface

If you are not using grclanker directly, the examples below show the same spec handoff pattern across terminal agents, IDE agents, chat UIs, and simple programmatic flows.

## Browse the raw catalog

- Site catalog: [`/specs`](/specs)
- Raw base: `https://raw.githubusercontent.com/hackIDLE/grclanker/main/specs`

## Why this matters

This is the bridge between the older “spec-only” site and the companion-first product shape. You no longer need to treat the specs as a separate product line. Install grclanker, then point it at the spec you want to execute against.
