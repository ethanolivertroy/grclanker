---
title: grclanker Docs
description: Install grclanker, choose a runtime, and use 241 domain tools across 35 implemented GRC integrations.
---

`grclanker` is an experimental open source AI GRC companion with 241 domain tools. All 35 integration specs in the repository now have native implementations under the CLI tool registry.

The same workflow prompts, personas, and domain tools can run in three ways:

- the Pi terminal CLI, including local-first or hosted model setup
- the Cursor Agent SDK project from a source checkout
- the bundled Flue runner or official Flue CLI

## Start here

1. [Install grclanker](/docs/getting-started/installation/).
2. Run `grclanker setup`.
3. Choose local-first or hosted.
4. Use a workflow, call a native integration tool, or hand the agent a repository spec.

The [Quick Start](/docs/getting-started/quick-start/) covers the shortest path. [Configuration](/docs/getting-started/configuration/) and [Compute Backends](/docs/getting-started/compute-backends/) cover runtime settings and execution environments.

## Runtime guides

- [Cursor Agent SDK](/docs/getting-started/agent-sdk/) documents schema conversion, read effects, approval-gated writers, dry runs, and local serving.
- [Flue Runtime](/docs/getting-started/flue-runtime/) documents the bundled runner, the official CLI, local models, persistence, and credential-safe activity logs.

## Shipped surface

- 241 domain tools and 7 compute backend tools, grouped in the [tool catalog](/docs/tools/catalog/).
- 35 implemented integration specs covering cloud, identity, collaboration, security, monitoring, vulnerability management, and enterprise platforms.
- Four structured workflows: `/investigate`, `/audit`, `/assess`, and `/validate`.
- Official FedRAMP Consolidated Rules lookups and generated reference docs under [`/docs/fedramp/`](/docs/fedramp/).
- FedRAMP readiness, artifact planning, ADS bundle generation, and portable trust-center site generation.
- Vanta audit export, SCF crosswalk lookups, and trestle-backed OSCAL workspaces.
- Optional Google Workspace CLI evidence collection.

Each integration guide in this documentation describes its authentication, collected surfaces, findings, export layout, limitations, and live smoke command.

## Safety and hardening

The current tool families share hardening for credential-aware error scrubbing, fixed-shape config errors, incomplete collection markers, and pagination status. Runtime adapters validate schemas at their boundaries. The Cursor Agent SDK marks 199 tools as read-only and approval-gates 42 writers. Flue redacts credential-shaped activity log arguments and documents where its conversation database stores raw inputs.

Exporters write redacted evidence bundles and allocate new output paths instead of overwriting a prior run. Review each integration guide before handling tenant data.

## Specs

The raw specs remain useful build inputs even though their native implementations have shipped. Browse all 35 under [`/specs`](/specs) or read [Using Specs as Inputs](/docs/specs/using-specs-as-inputs/).

`0.0.1` remains experimental. macOS and Linux are the recommended platforms. Windows support is best-effort.
