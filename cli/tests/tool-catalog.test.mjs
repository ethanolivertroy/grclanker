import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  findRegisteredTool,
  formatToolCatalogText,
  formatToolDetailText,
  getRegisteredToolSummaries,
  groupRegisteredTools,
} from "../dist/pi/tool-catalog.js";
import { buildToolCatalogMarkdown } from "../scripts/generate-tool-catalog-docs.mjs";

const BASELINE_DOMAIN_TOOL_COUNT = 107;
const cliRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function countTools(tools, kind) {
  return tools.filter((tool) => tool.kind === kind).length;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

test("tool catalog reflects the bundled extension registration surface", () => {
  const tools = getRegisteredToolSummaries();
  const domainTools = tools.filter((tool) => tool.kind === "domain");
  const computeTools = tools.filter((tool) => tool.kind === "compute");

  assert.ok(
    domainTools.length >= BASELINE_DOMAIN_TOOL_COUNT,
    `expected at least ${BASELINE_DOMAIN_TOOL_COUNT} domain tools, saw ${domainTools.length}`,
  );
  assert.equal(new Set(tools.map((tool) => tool.name)).size, tools.length, "tool names must be unique");
  assert.equal(computeTools.length, 7);
  assert.ok(
    domainTools.every((tool) => tool.group !== "Other Domain Tools"),
    `every domain tool needs a DOMAIN_GROUPS entry: ${domainTools
      .filter((tool) => tool.group === "Other Domain Tools")
      .map((tool) => tool.name)
      .join(", ")}`,
  );
  assert.ok(tools.some((tool) => tool.name === "ansible_check_access"));
  assert.ok(tools.some((tool) => tool.name === "ansible_export_audit_bundle"));
  assert.ok(tools.some((tool) => tool.name === "aws_check_access"));
  assert.ok(tools.some((tool) => tool.name === "aws_export_audit_bundle"));
  assert.ok(tools.some((tool) => tool.name === "azure_check_access"));
  assert.ok(tools.some((tool) => tool.name === "azure_export_audit_bundle"));
  assert.ok(tools.some((tool) => tool.name === "cloudflare_check_access"));
  assert.ok(tools.some((tool) => tool.name === "cloudflare_export_audit_bundle"));
  assert.ok(tools.some((tool) => tool.name === "fedramp_check_sources"));
  assert.ok(tools.some((tool) => tool.name === "gcp_check_access"));
  assert.ok(tools.some((tool) => tool.name === "gcp_export_audit_bundle"));
  assert.ok(tools.some((tool) => tool.name === "github_assess_actions_security"));
  assert.ok(tools.some((tool) => tool.name === "gws_ops_collect_evidence_bundle"));
  assert.ok(tools.some((tool) => tool.name === "oci_check_access"));
  assert.ok(tools.some((tool) => tool.name === "oci_export_audit_bundle"));
  assert.ok(tools.some((tool) => tool.name === "oscal_validate_model"));
  assert.ok(tools.some((tool) => tool.name === "slack_check_access"));
  assert.ok(tools.some((tool) => tool.name === "slack_export_audit_bundle"));
  assert.ok(tools.some((tool) => tool.name === "webex_check_access"));
  assert.ok(tools.some((tool) => tool.name === "webex_export_audit_bundle"));
  assert.ok(tools.some((tool) => tool.name === "zoom_check_access"));
  assert.ok(tools.some((tool) => tool.name === "zoom_export_audit_bundle"));
});

test("audit and assess prompts name the exact Google Workspace operator tools", () => {
  const checkTool = "gws_ops_check_cli";
  const purposeByTool = {
    gws_ops_investigate_alerts: /\balerts?\b/i,
    gws_ops_trace_admin_activity: /\badmin activity\b/i,
    gws_ops_review_tokens: /\btokens?\b/i,
    gws_ops_collect_evidence_bundle: /\bevidence\b/i,
  };
  const operatorTools = [checkTool, ...Object.keys(purposeByTool)];

  const registeredOperatorTools = getRegisteredToolSummaries()
    .filter((tool) => tool.name.startsWith("gws_ops_"))
    .map((tool) => tool.name);
  assert.deepEqual([...registeredOperatorTools].sort(), [...operatorTools].sort());

  for (const prompt of ["audit", "assess"]) {
    const text = readFileSync(resolve(cliRoot, "prompts", `${prompt}.md`), "utf8").replace(/\s+/g, " ");
    const referenced = new Set([...text.matchAll(/`(gws_ops_[^`]*)`/g)].map((match) => match[1]));
    assert.deepEqual([...referenced].sort(), [...operatorTools].sort(), `${prompt}.md must reference exactly the registered operator tools`);

    const checkIndex = text.indexOf(`\`${checkTool}\``);
    for (const [name, purpose] of Object.entries(purposeByTool)) {
      const toolIndex = text.indexOf(`\`${name}\``);
      assert.ok(toolIndex > checkIndex, `${prompt}.md must name ${name} after ${checkTool}`);

      // The description that follows a tool reference runs until the next backticked name.
      const afterTool = toolIndex + name.length + 2;
      const nextReference = text.indexOf("`", afterTool);
      const description = text.slice(afterTool, nextReference === -1 ? afterTool + 80 : Math.min(nextReference, afterTool + 80));
      assert.match(description, purpose, `${prompt}.md must pair ${name} with its purpose`);
      for (const [otherName, otherPurpose] of Object.entries(purposeByTool)) {
        if (otherName === name) continue;
        assert.doesNotMatch(description, otherPurpose, `${prompt}.md pairs ${name} with ${otherName}'s purpose`);
      }
    }
  }
});

test("tool catalog groups tools by domain for CLI display", () => {
  const tools = getRegisteredToolSummaries();
  const groups = groupRegisteredTools(tools);
  const groupNames = groups.map((group) => group.group);

  assert.ok(groupNames.includes("Compute Backend"));
  assert.ok(groupNames.includes("Ansible AAP"));
  assert.ok(groupNames.includes("FedRAMP"));
  assert.ok(groupNames.includes("Google Workspace"));
  assert.ok(groupNames.includes("Google Workspace Operator"));

  const text = formatToolCatalogText(tools);
  assert.match(
    text,
    new RegExp(`${countTools(tools, "domain")} domain tools \\+ ${countTools(tools, "compute")} compute backend tools`),
  );
  for (const group of groups) {
    assert.ok(group.tools.length > 0, `group ${group.group} has no tools`);
    assert.match(text, new RegExp(`${escapeRegExp(group.group)} \\(${group.tools.length}\\)`));
  }
  assert.match(text, /fedramp_generate_ads_site -/);
  assert.match(text, /Compute Backend \(7\)/);
});

test("tool catalog formats detailed parameter help for a single tool", () => {
  const tools = getRegisteredToolSummaries();
  const tool = findRegisteredTool(tools, "fedramp_check_sources");

  assert.ok(tool);
  assert.equal(tool.group, "FedRAMP");
  assert.ok(tool.parameterSummaries.some((parameter) => parameter.name === "refresh"));

  const text = formatToolDetailText(tool);
  assert.match(text, /grclanker tool: fedramp_check_sources/);
  assert.match(text, /refresh \(boolean, optional/);
  assert.match(text, /Force a live refresh/);
});

test("tool catalog docs markdown is generated from registered tools", () => {
  const tools = getRegisteredToolSummaries();
  const markdown = buildToolCatalogMarkdown(tools);

  assert.match(markdown, /title: Tool Catalog/);
  assert.match(markdown, new RegExp(`- ${countTools(tools, "domain")} domain tools`));
  assert.match(markdown, /## Ansible AAP/);
  assert.match(markdown, /\| `ansible_export_audit_bundle` \| Export Ansible AAP audit bundle \|/);
  assert.match(markdown, /## AWS/);
  assert.match(markdown, /\| `aws_export_audit_bundle` \| Export AWS audit bundle \|/);
  assert.match(markdown, /## Azure/);
  assert.match(markdown, /\| `azure_export_audit_bundle` \| Export Azure audit bundle \|/);
  assert.match(markdown, /## Cloudflare/);
  assert.match(markdown, /\| `cloudflare_export_audit_bundle` \| Export Cloudflare audit bundle \|/);
  assert.match(markdown, /## GCP/);
  assert.match(markdown, /\| `gcp_export_audit_bundle` \| Export GCP audit bundle \|/);
  assert.match(markdown, /## OCI/);
  assert.match(markdown, /\| `oci_export_audit_bundle` \| Export OCI audit bundle \|/);
  assert.match(markdown, /## Slack/);
  assert.match(markdown, /\| `slack_export_audit_bundle` \| Export Slack audit bundle \|/);
  assert.match(markdown, /## Webex/);
  assert.match(markdown, /\| `webex_export_audit_bundle` \| Export Webex audit bundle \|/);
  assert.match(markdown, /## Zoom/);
  assert.match(markdown, /\| `zoom_export_audit_bundle` \| Export Zoom audit bundle \|/);
});
