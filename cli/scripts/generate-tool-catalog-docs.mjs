import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  getRegisteredToolSummaries,
  groupRegisteredTools,
} from "../dist/pi/tool-catalog.js";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, "../..");
const defaultOutputPath = resolve(repoRoot, "src/content/docs/docs/tools/catalog.md");

function escapePipe(value) {
  return String(value).replaceAll("|", "\\|");
}

// Compute tool labels only repeat the tool name, so their purpose comes from
// the first sentence of the upstream description instead.
function toolPurpose(tool) {
  if (tool.kind !== "compute") return tool.label;
  const sentence = String(tool.description).match(/^.*?\.(?=\s|$)/s)?.[0] ?? tool.description;
  return sentence.trim().replace(/\.$/, "");
}

export function buildToolCatalogMarkdown(tools = getRegisteredToolSummaries()) {
  const domainCount = tools.filter((tool) => tool.kind === "domain").length;
  const computeCount = tools.filter((tool) => tool.kind === "compute").length;
  const lines = [
    "---",
    "title: Tool Catalog",
    "description: Every tool grclanker ships, with a one-line purpose for each, grouped by integration and data source.",
    "---",
    "",
    `grclanker ships ${domainCount} domain tools and ${computeCount} compute backend tools. The domain tools do the GRC work and are grouped below by name prefix, such as \`aws_\` for AWS or \`fedramp_\` for FedRAMP. The compute backend tools, listed last, run shell commands and read, search, and change files.`,
    "",
    "From a terminal, `grclanker tools` prints the same list, `grclanker tools <name>` shows one tool's parameters, and `grclanker tools --json` prints the list as JSON for scripts.",
    "",
  ];

  const groups = groupRegisteredTools(tools);
  const orderedGroups = [
    ...groups.filter((group) => group.kind === "domain"),
    ...groups.filter((group) => group.kind === "compute"),
  ];

  for (const group of orderedGroups) {
    const sortedTools = [...group.tools].sort((left, right) => left.name.localeCompare(right.name));
    lines.push(`## ${group.group}`, "");
    if (group.kind === "compute") {
      lines.push(
        "Your [compute backend](/docs/getting-started/compute-backends/) decides where these run.",
        "",
      );
    }
    lines.push("| Tool | Purpose |", "|---|---|");
    for (const tool of sortedTools) {
      lines.push(`| \`${tool.name}\` | ${escapePipe(toolPurpose(tool))} |`);
    }
    lines.push("");
  }

  return lines.join("\n").trimEnd() + "\n";
}

export async function writeToolCatalogDocs(outputPath = defaultOutputPath) {
  const markdown = buildToolCatalogMarkdown();
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, markdown, "utf8");
  return outputPath;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const outputPath = process.argv[2] ? resolve(process.cwd(), process.argv[2]) : defaultOutputPath;
  await writeToolCatalogDocs(outputPath);
  console.log(`Wrote tool catalog docs to ${outputPath}`);
}
