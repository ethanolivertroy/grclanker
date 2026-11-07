# OpenAI Agents SDK adapter

This adapter runs grclanker's GRC engineering role and tools in the `@openai/agents` TypeScript SDK. `agent.ts` exports the agent factory and tool adapters; `cli.ts` provides the one-shot runner. Shared domain tools and methodology come from `cli/core/` and `cli/extensions/grc-tools/`.

Use Git, npm, Node.js 22.19 or newer, and an OpenAI API key with access to your selected model. From the repository root:

```bash
npm --prefix cli ci
npm --prefix cli run build
npm --prefix cli run openai-agents:check
export OPENAI_API_KEY='your-openai-api-key'
npm --prefix cli run openai-agents:run -- \
  "Investigate CVE-2024-3400 using KEV and EPSS evidence. Cite sources and explain what still needs organization-specific verification."
```

The check constructs the agent without calling a provider or tenant. The default agent exposes four public-data tools, workflow and cryptographic skill loaders, and auditor/verifier reviewer agents. `--model` or `GRCLANKER_OPENAI_MODEL` changes the model; `--tools` replaces the domain tool selection.

For an organization assessment:

```bash
export GITHUB_ORG='your-organization'
export GITHUB_TOKEN='your-github-token'
npm --prefix cli run openai-agents:run -- \
  --tools github_check_access,github_assess_org_access,github_assess_repo_protection \
  "Check access first, assess GitHub access and repository protection, then report evidence gaps and remediation priorities."
```

The vendor token needs read access to the organization and repositories; authorize it for SSO when required. Model credentials do not grant vendor access. The adapter reads credentials from its Node process environment.

To embed it after building, create `cli/openai-example.mjs`:

```javascript
import { Runner } from "@openai/agents";
import { createGrclankerOpenAIAgent } from "./dist/adapters/openai-agents/agent.js";

const agent = createGrclankerOpenAIAgent({
  toolNames: ["kevs_search", "kevs_get_epss"],
});
const runner = new Runner({ tracingDisabled: true });
const result = await runner.run(agent, "Investigate CVE-2024-3400 and cite evidence.");
if (result.interruptions.length) throw new Error("A tool requires operator approval.");
console.log(result.finalOutput);
```

Run `node cli/openai-example.mjs` from the repository root. Exports and other file-writing tools require SDK approval. The shipped CLI asks an interactive operator for each pending write and rejects pending writes in noninteractive runs. An embedding service must bind approval/resume decisions to its authenticated operator. Relative artifact paths resolve against the Node process working directory; use absolute paths for deployment outputs.

After building, run `node --test tests/openai-agents.test.mjs` from `cli/` for offline SDK regression coverage. A live run separately verifies model and tenant access. Deploy the shared build, production dependencies, and methodology assets alongside the adapter; this folder alone is not a deployment bundle.

The adapter has its own configuration and runs without Pi terminal setup or Cursor authentication. Its dependency installation and TypeScript build are currently shared in `cli/package.json`; it is not separately packaged. See the complete [OpenAI Agents SDK guide](https://grclanker.com/docs/getting-started/openai-agents-sdk/) for all setup, approval, and hosting details.
