import {
  getGrclankerSandboxConfigPath,
  getGrclankerSettingsPath,
} from "../config/paths.js";
import {
  detectComputeBackendStatuses,
  formatSystemResources,
  getComputeBackendConfigurationIssues,
  getComputeBackendLabel,
  getParallelsTemplateInfo,
  getParallelsVmInfo,
  listParallelsTemplates,
  listParallelsVms,
  resolveDockerImage,
  resolveDockerWorkspacePath,
  resolveParallelsAutoStart,
  resolveParallelsBaseVmName,
  resolveParallelsClonePrefix,
  resolveParallelsSourceKind,
  resolveParallelsTemplateName,
  resolveParallelsWorkspacePath,
  resolveComputeBackend,
} from "./compute.js";
import { getProjectSandboxConfigPath, loadSandboxConfig } from "./sandbox.js";
import { readGrclankerSettings } from "./settings.js";

export async function runComputeDoctor(): Promise<void> {
  const settings = readGrclankerSettings(getGrclankerSettingsPath());
  const preferredBackend = resolveComputeBackend(settings);
  const statuses = detectComputeBackendStatuses();

  console.log("\ngrclanker env doctor\n");
  console.log(`Preferred compute backend: ${getComputeBackendLabel(preferredBackend)} (${preferredBackend})`);
  console.log(`Configured runtime surface: ${formatSystemResources(preferredBackend)}`);
  console.log("");
  console.log("Backend configuration:");
  console.log(`  docker.image        ${resolveDockerImage(settings)}`);
  console.log(`  docker.workspace    ${resolveDockerWorkspacePath(settings)}`);
  const parallelsSourceKind = resolveParallelsSourceKind(settings);
  const parallelsBaseVmName = resolveParallelsBaseVmName(settings);
  const parallelsBaseVm = parallelsBaseVmName ? getParallelsVmInfo(parallelsBaseVmName) : undefined;
  const parallelsTemplateName = resolveParallelsTemplateName(settings);
  const parallelsTemplate = parallelsTemplateName
    ? getParallelsTemplateInfo(parallelsTemplateName)
    : undefined;
  console.log(`  parallels.source    ${parallelsSourceKind}`);
  console.log(`  parallels.template  ${parallelsTemplateName ?? "(not set)"}`);
  console.log(`  parallels.base      ${parallelsBaseVmName ?? "(not set)"}`);
  console.log(`  parallels.baseState ${parallelsBaseVm?.status ?? "(unknown)"}`);
  console.log(`  parallels.clonePref ${resolveParallelsClonePrefix(settings)}`);
  console.log(`  parallels.workspace ${resolveParallelsWorkspacePath(settings) ?? "(auto-detect guest share path)"}`);
  console.log(`  parallels.autostart ${resolveParallelsAutoStart(settings) ? "yes" : "no"}`);
  if (parallelsSourceKind === "template" && parallelsTemplateName) {
    const templateReadiness = !parallelsTemplate
      ? `Template "${parallelsTemplateName}" was not found.`
      : `Template "${parallelsTemplateName}" is registered and ready for disposable sandbox deployment.`;
    console.log(`  parallels.check     ${parallelsTemplate ? "ok" : "needs attention"}`);
    console.log(`  parallels.detail    ${templateReadiness}`);
  } else if (parallelsBaseVmName) {
    const cloneReadiness = !parallelsBaseVm
      ? `Base VM "${parallelsBaseVmName}" was not found.`
      : parallelsBaseVm.status === "stopped"
        ? `Base VM "${parallelsBaseVmName}" is stopped and safe to clone.`
        : `Base VM "${parallelsBaseVmName}" is ${parallelsBaseVm.status}. Stop it before using disposable sandboxes.`;
    console.log(`  parallels.check     ${parallelsBaseVm?.status === "stopped" ? "ok" : "needs attention"}`);
    console.log(`  parallels.detail    ${cloneReadiness}`);
  }
  const sandboxConfig = loadSandboxConfig(process.cwd());
  console.log(`  sandbox.global      ${getGrclankerSandboxConfigPath()}`);
  console.log(`  sandbox.project     ${getProjectSandboxConfigPath(process.cwd())}`);
  console.log(`  sandbox.enabled     ${sandboxConfig.enabled === false ? "no" : "yes"}`);
  console.log(`  sandbox.net.allow   ${sandboxConfig.network.allowedDomains.length}`);
  console.log(`  sandbox.fs.write    ${sandboxConfig.filesystem.allowWrite.join(", ")}`);
  console.log("");
  console.log("Backends:");

  for (const status of statuses) {
    const marker = status.available ? "ok" : "--";
    console.log(`  ${marker} ${status.kind.padEnd(16)} ${status.summary}`);
    console.log(`     ${status.detail}`);
  }

  const configurationIssues = getComputeBackendConfigurationIssues(settings, preferredBackend);
  if (configurationIssues.length > 0) {
    console.log("");
    console.log("Configuration issues:");
    for (const issue of configurationIssues) {
      console.log(`  - ${issue}`);
    }
  }

  const parallelsVms = listParallelsVms();
  if (parallelsVms.length > 0) {
    console.log("");
    console.log("Parallels inventory:");
    for (const vm of parallelsVms) {
      console.log(`  - ${vm.name} (${vm.status})`);
    }
  }

  const parallelsTemplates = listParallelsTemplates();
  if (parallelsTemplates.length > 0) {
    console.log("");
    console.log("Parallels templates:");
    for (const template of parallelsTemplates) {
      console.log(`  - ${template.name} (${template.status})`);
    }
  }

  const preferredStatus = statuses.find((status) => status.kind === preferredBackend);
  if (preferredStatus && !preferredStatus.available) {
    console.log("");
    console.log(
      `warning: preferred backend ${preferredBackend} is not currently available on this machine.`,
    );
  }

  console.log("");
  console.log(
    "note: this keeps Feynman's useful split between model/provider choice and execution environment choice, but grclanker treats Parallels more defensively by deploying disposable sandboxes from a template or stopped base VM instead of running inside one of your existing VMs.",
  );
  console.log("");
}
