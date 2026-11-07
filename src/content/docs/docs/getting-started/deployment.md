---
title: Choose a Deployment
description: Choose an independent Pi, OpenAI Agents SDK, Codex SDK, or Cursor / Grok Agent SDK deployment for your GRC engineering assistant.
---

grclanker combines a GRC engineering role, evidence-driven workflows, and 241 domain tools across 35 vendor integrations. Choose the runtime that fits where you want your agent to work. Each guide includes its own prerequisites, installation, authentication, code, first run, and operating limits; no SDK guide requires another SDK guide.

## Pick your path

| Deployment | Status | Choose it when | Complete guide |
| --- | --- | --- | --- |
| Pi terminal CLI | Available in release bundles and source | You want an interactive local terminal assistant, local or hosted models, and selectable compute backends. | [Pi Terminal CLI](/docs/getting-started/pi-runtime/) |
| OpenAI Agents SDK | Available from source | You want to embed GRC tools in your own TypeScript agent using OpenAI's agent loop. | [OpenAI Agents SDK](/docs/getting-started/openai-agents-sdk/) |
| Codex SDK | Available as a source example | You want Codex to act as a GRC engineer with an explicit set of GRC tools through a local MCP server. | [Codex SDK](/docs/getting-started/codex-sdk/) |
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

The repository shares native tool implementations, JSON schemas, argument validation, result formatting, workflows, and the GRC role. The provider-neutral bridge lives in `cli/runtime/`. Sharing that code keeps evidence collection consistent without making the OpenAI or Codex path import the Cursor/Grok SDK project.

Each host supplies its own model loop, authentication, sessions, file and shell access, and approval controls. Pi compute backend settings do not configure the other hosts. The individual guides explain tool selection, write permissions, output locations, and deployment for their own host.

The [tool catalog](/docs/tools/catalog/) and vendor integration references are optional extensions once your selected path is running. They are not prerequisites from a different SDK path.
