import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  createBashTool,
  createEditTool,
  createFindTool,
  createGrepTool,
  createLsTool,
  createReadTool,
  createWriteTool,
  type ExtensionAPI,
} from "@earendil-works/pi-coding-agent";
import { getGrclankerSettingsPath } from "../config/paths.js";
import {
  buildComputeBackendSystemPromptNote,
  resolveComputeBackendExecution,
} from "../pi/backend-exec.js";
import { getComputeBackendConfigurationIssues } from "../pi/compute.js";
import { shutdownComputeSessions } from "../pi/compute-shutdown.js";
import { executeComputeAwareGrep } from "../pi/search-tools.js";
import { readGrclankerSettings } from "../pi/settings.js";
import { initialPromptInputResult } from "../pi/prompt-envelope.js";
import { registerDomainTools } from "../core/domain-tools.js";
import { toPiToolDefinition } from "../pi/tool-adapter.js";
import { formatGrclankerStatus, installGrclankerHeader } from "./grc-tools/header.js";

function resolveCliVersion(currentDir: string): string {
  const candidatePaths = [
    resolve(currentDir, "../package.json"),
    resolve(currentDir, "../../package.json"),
  ];

  for (const packageJsonPath of candidatePaths) {
    if (!existsSync(packageJsonPath)) continue;
    try {
      const contents = JSON.parse(readFileSync(packageJsonPath, "utf8")) as { version?: string };
      if (typeof contents.version === "string" && contents.version.trim().length > 0) {
        return contents.version.trim();
      }
    } catch {
      // fall through to next candidate
    }
  }

  return "0.0.0";
}

export default function grcTools(pi: ExtensionAPI): void {
  const cliVersion = resolveCliVersion(import.meta.dirname);
  const localCwd = process.cwd();
  const settingsPath = getGrclankerSettingsPath();
  const cache: { agentsPromise?: Promise<string[]> } = {};
  const runtime: {
    settings?: ReturnType<typeof readGrclankerSettings>;
    execution?: ReturnType<typeof resolveComputeBackendExecution>;
  } = {};
  const localBash = createBashTool(localCwd);
  const localRead = createReadTool(localCwd);
  const localWrite = createWriteTool(localCwd);
  const localEdit = createEditTool(localCwd);
  const localLs = createLsTool(localCwd);
  const localFind = createFindTool(localCwd);
  const localGrep = createGrepTool(localCwd);

  pi.on("input", (event) => initialPromptInputResult(event.text, event.source));

  function getSettings() {
    if (!runtime.settings) {
      runtime.settings = readGrclankerSettings(settingsPath);
    }
    return runtime.settings;
  }

  function getExecution() {
    if (!runtime.execution) {
      runtime.execution = resolveComputeBackendExecution(localCwd, getSettings());
    }
    return runtime.execution;
  }

  pi.registerTool({
    ...localBash,
    label: "bash (compute backend)",
    async execute(id, params, signal, onUpdate, _ctx) {
      const execution = getExecution();
      const tool = createBashTool(localCwd, { operations: execution.bashOperations });
      return tool.execute(id, params, signal, onUpdate);
    },
  });

  pi.registerTool({
    ...localRead,
    label: "read (compute backend)",
    async execute(id, params, signal, onUpdate, _ctx) {
      const execution = getExecution();
      if (!execution.readOperations) {
        return localRead.execute(id, params, signal, onUpdate);
      }
      const tool = createReadTool(localCwd, { operations: execution.readOperations });
      return tool.execute(id, params, signal, onUpdate);
    },
  });

  pi.registerTool({
    ...localWrite,
    label: "write (compute backend)",
    async execute(id, params, signal, onUpdate, _ctx) {
      const execution = getExecution();
      if (!execution.writeOperations) {
        return localWrite.execute(id, params, signal, onUpdate);
      }
      const tool = createWriteTool(localCwd, { operations: execution.writeOperations });
      return tool.execute(id, params, signal, onUpdate);
    },
  });

  pi.registerTool({
    ...localEdit,
    label: "edit (compute backend)",
    async execute(id, params, signal, onUpdate, _ctx) {
      const execution = getExecution();
      if (!execution.editOperations) {
        return localEdit.execute(id, params, signal, onUpdate);
      }
      const tool = createEditTool(localCwd, { operations: execution.editOperations });
      return tool.execute(id, params, signal, onUpdate);
    },
  });

  pi.registerTool({
    ...localLs,
    label: "ls (compute backend)",
    async execute(id, params, signal, onUpdate, _ctx) {
      const execution = getExecution();
      if (!execution.lsOperations) {
        return localLs.execute(id, params, signal, onUpdate);
      }
      const tool = createLsTool(localCwd, { operations: execution.lsOperations });
      return tool.execute(id, params, signal, onUpdate);
    },
  });

  pi.registerTool({
    ...localFind,
    label: "find (compute backend)",
    async execute(id, params, signal, onUpdate, _ctx) {
      const execution = getExecution();
      if (!execution.findOperations) {
        return localFind.execute(id, params, signal, onUpdate);
      }
      const tool = createFindTool(localCwd, { operations: execution.findOperations });
      return tool.execute(id, params, signal, onUpdate);
    },
  });

  pi.registerTool({
    ...localGrep,
    label: "grep (compute backend)",
    async execute(id, params, signal, onUpdate, _ctx) {
      const execution = getExecution();
      if (!execution.grepOperations) {
        return localGrep.execute(id, params, signal, onUpdate);
      }
      return executeComputeAwareGrep(execution, localCwd, params);
    },
  });

  pi.on("user_bash", () => {
    const execution = getExecution();
    if (execution.kind === "host") return;
    return { operations: execution.bashOperations };
  });

  pi.on("before_agent_start", async (event) => {
    const settings = getSettings();
    const note = buildComputeBackendSystemPromptNote(localCwd, settings);
    return { systemPrompt: `${event.systemPrompt.trimEnd()}\n\n${note}` };
  });

  const domainToolCount = registerDomainTools({ registerTool(tool) { pi.registerTool(toPiToolDefinition(tool)); } });

  pi.on("session_start", async (_event, ctx) => {
    if (!ctx.hasUI) return;
    ctx.ui.setTitle?.("grclanker");
    ctx.ui.setWorkingMessage?.("Correlating evidence...");
    ctx.ui.setHiddenThinkingLabel?.("GRC analysis");
    const settings = getSettings();
    const execution = getExecution();
    ctx.ui.setStatus?.("grclanker", formatGrclankerStatus([
      `compute: ${execution.summary}`,
      `${domainToolCount} domain tools ready`,
    ]));
    for (const issue of getComputeBackendConfigurationIssues(settings, execution.kind)) {
      ctx.ui.notify(`Compute backend warning: ${issue}`, "warning");
    }
    await installGrclankerHeader(pi, ctx, cache, cliVersion);
  });

  pi.on("session_tree", async (_event, ctx) => {
    if (!ctx.hasUI) return;
    await installGrclankerHeader(pi, ctx, cache, cliVersion);
  });

  pi.on("session_shutdown", async () => {
    await shutdownComputeSessions(getSettings());
  });
}
