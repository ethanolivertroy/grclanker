---
title: Choose a Deployment
description: Choose a Pi, OpenAI Agents SDK, Codex SDK, or Cursor / Grok Agent SDK host with its own setup for your GRC engineering assistant.
---

grclanker combines a GRC engineering role, evidence-driven workflows, and 241 domain tools across 35 vendor integrations. Choose the runtime that fits where you want your agent to work. Each guide includes its own prerequisites, installation, authentication, code, first run, and operating limits; no SDK guide requires another SDK guide.

## Pick your path

| Deployment | Status | Choose it when | Complete guide |
| --- | --- | --- | --- |
| Pi terminal CLI | Available in release bundles and source | You want an interactive local terminal assistant, local or hosted models, and selectable compute backends. | [Pi Terminal CLI](/docs/getting-started/pi-runtime/) |
| OpenAI Agents SDK | Available from source | You want to embed GRC tools in your own TypeScript agent using OpenAI's agent loop. | [OpenAI Agents SDK](/docs/getting-started/openai-agents-sdk/) |
| Codex SDK | Available from source; selected read tools | You want Codex to act as a GRC engineer with an explicit set of GRC tools through a local MCP server. | [Codex SDK](/docs/getting-started/codex-sdk/) |
| Cursor / Grok Agent SDK | Available from source, local harness | You want an agent project with native SDK tools, skills, and personas in the Cursor/Grok harness. | [Cursor / Grok Agent SDK](/docs/getting-started/agent-sdk/) |
| Claude Agent SDK | Planned; no grclanker adapter yet | You want to track the future Claude deployment path. | [Claude Agent SDK plan](/docs/getting-started/claude-agent-sdk/) |

OpenAI Agents SDK and Codex SDK are separate integrations with separate agent loops. Cursor's current Agent SDK is distributed as `@grok/agent-sdk`, formerly `@cursor/bdk`: Cursor and Grok refer to the same SDK path here. This does not establish compatibility with the separate xAI API SDK. See the [OpenAI Agents SDK overview](https://developers.openai.com/api/docs/guides/agents/sdk), [Codex SDK documentation](https://developers.openai.com/codex/sdk), and [Cursor Agent SDK documentation](https://cursor.com/docs/agent-sdk).

The release installer runs Pi. The OpenAI, Codex, and Cursor/Grok guides use a source checkout; installing the release does not install those SDK projects. SDK credentials authenticate the model or harness. Vendor credentials separately authorize the GRC tools to inspect your organization.

Existing [Flue](/docs/getting-started/flue-runtime/) and experimental [durable](/docs/getting-started/durable-runtime/) runners remain additional deployment options.

## A GRC engineer, with evidence

The goal is an assistant that helps manage governance, risk, and compliance across an organization. Vendor connectors supply evidence for that work; they are one part of the agent.

Today the shared instructions and four workflows support scoping an assessment, gathering evidence, mapping findings to framework controls, prioritizing risks, recommending remediation, investigating vulnerabilities, and validating cryptographic modules. FedRAMP, SCF, and OSCAL tools also support readiness planning and compliance artifacts. Use the same review pattern in any runtime:

1. Define the systems, business context, target framework, accountable owners, and timeline.
2. Enable only the tool families needed for that scope and confirm access before an assessment.
3. Gather dated evidence; distinguish permission gaps and incomplete collection from passing controls.
4. Map findings to control references, explain risk and uncertainty, and draft remediation actions for an owner to review.
5. Review generated artifacts and approvals before using the results for organizational decisions.

Policy lifecycle management, a persistent organization-wide risk register, continuous control monitoring, and autonomous remediation are future product capabilities, not features implied by an SDK adapter. The current agents can help draft and analyze this work within a conversation; they do not supply those end-to-end systems.

## What is shared and what is independent

The code separates shared GRC behavior from each agent host:

| Source directory | Owns |
| --- | --- |
| `cli/core/` | Shared domain registry, schemas, validation, redaction, results, and methodology loading |
| `cli/extensions/grc-tools/` | Native tool implementations for vendors, frameworks, and public data |
| `cli/pi/` | Pi terminal, setup wizard, sessions, and compute backends |
| `cli/adapters/openai-agents/` | OpenAI Agents SDK tools, agents, approvals, and runner |
| `cli/adapters/codex/` | Codex SDK worker and local GRC MCP server |
| `cli/adapters/cursor-grok/` | Cursor/Grok project, SDK tool definitions, skills, and subagents |

Shared instructions and assets live in `cli/.grclanker/`, `cli/prompts/`, and `cli/skills/`. The SDK adapters consume the core and native tools; they do not import one another.

Each host supplies its own model loop, authentication, sessions, file and shell access, and approval controls. Pi compute backend settings do not configure the other hosts. The individual guides explain tool selection, write permissions, output locations, and deployment for their own host.

Source dependency installation and the TypeScript build are currently shared in `cli/package.json`. Choosing an SDK gives you separate setup and configuration, not an independently packaged installation. Codex also installs dependencies from its own adapter manifest and still needs the common build. Keep the source layout and required assets together when deploying; copying an adapter directory alone is insufficient. The repository's [`cli/README.md`](https://github.com/ethanolivertroy/grclanker/blob/main/cli/README.md) maps the code and canonical commands for contributors.

The [tool catalog](/docs/tools/catalog/) and vendor integration references are optional extensions once your selected path is running. They are not prerequisites from a different SDK path.
