import test from "node:test";
import assert from "node:assert/strict";

import {
  findRegisteredTool,
  formatToolCatalogText,
  formatToolDetailText,
  getRegisteredToolSummaries,
  groupRegisteredTools,
} from "../dist/pi/tool-catalog.js";
import { buildToolCatalogMarkdown } from "../scripts/generate-tool-catalog-docs.mjs";

test("tool catalog reflects the bundled extension registration surface", () => {
  const tools = getRegisteredToolSummaries();
  const domainTools = tools.filter((tool) => tool.kind === "domain");
  const computeTools = tools.filter((tool) => tool.kind === "compute");

  assert.equal(domainTools.length, 72);
  assert.equal(computeTools.length, 7);
  assert.ok(tools.some((tool) => tool.name === "ansible_check_access"));
  assert.ok(tools.some((tool) => tool.name === "ansible_export_audit_bundle"));
  assert.ok(tools.some((tool) => tool.name === "fedramp_check_sources"));
  assert.ok(tools.some((tool) => tool.name === "github_assess_actions_security"));
  assert.ok(tools.some((tool) => tool.name === "gws_ops_collect_evidence_bundle"));
  assert.ok(tools.some((tool) => tool.name === "oscal_validate_model"));
  assert.ok(tools.some((tool) => tool.name === "slack_check_access"));
  assert.ok(tools.some((tool) => tool.name === "slack_export_audit_bundle"));
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
  assert.match(text, /72 domain tools \+ 7 compute backend tools/);
  assert.match(text, /Ansible AAP \(5\)/);
  assert.match(text, /FedRAMP \(10\)/);
  assert.match(text, /Slack \(6\)/);
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
  assert.match(markdown, /72 domain tools/);
  assert.match(markdown, /## Ansible AAP/);
  assert.match(markdown, /\| `ansible_export_audit_bundle` \| Export Ansible AAP audit bundle \|/);
  assert.match(markdown, /## Slack/);
  assert.match(markdown, /\| `slack_export_audit_bundle` \| Export Slack audit bundle \|/);
});
