---
title: Claude Agent SDK (Planned)
description: Status and intended scope for a future standalone grclanker integration with the Claude Agent SDK.
---

**Status: planned.** This repository does not ship a grclanker Claude Agent SDK adapter, launch command, or supported deployment. Installing Anthropic's SDK alone does not register grclanker's tools. This page records the intended path; it is not a runnable tutorial.

## Intended deployment

The [Claude Agent SDK](https://code.claude.com/docs/en/agent-sdk/overview) embeds Anthropic's agent loop in an application you operate. A future grclanker integration should pair that loop with the GRC engineer instructions, workflow prompts, and an explicitly chosen set of domain tools from the provider-neutral `cli/core/` bridge.

The aim is an assistant that scopes governance and compliance work, gathers security evidence from authorized systems, maps findings to controls, prioritizes organizational risk, and helps draft remediation and compliance artifacts. It should distinguish verified evidence from recommendations and missing information.

## Requirements for a supported guide

Before this path is marked available, it needs all of the following on this page:

- A pinned SDK dependency, supported Node version, and complete installation from a fresh checkout.
- Claude authentication and vendor authentication explained separately, with a local check that needs neither credentials nor a model request.
- Runnable agent code that imports the neutral GRC bridge, with no dependency on another provider's adapter.
- Explicit tool selection, schema validation, cancellation, scrubbed errors, and approval handling for exports and other writers.
- GRC role and workflow loading, documented file locations and session behavior, and a first evidence-backed assessment.
- Tested launch, self-hosting instructions, troubleshooting, and a clear description of which actions need human review.

There is no promised release date. For the SDK's current capabilities and prerequisites, consult the [official Claude Agent SDK overview](https://code.claude.com/docs/en/agent-sdk/overview). Availability on this page will change when a tested grclanker implementation ships.
