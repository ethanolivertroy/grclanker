import {
  getParallelsTemplateInfo,
  getParallelsVmInfo,
  resolveParallelsAutoStart,
  resolveParallelsBaseVmName,
  resolveParallelsSourceKind,
  resolveParallelsTemplateName,
} from "./compute.js";
import { teardownComputeSessions } from "./compute-sessions.js";
import type { GrclankerSettings } from "./settings.js";

export type ParallelsSource = {
  sourceKind: "template" | "base-vm";
  sourceName: string;
};

function assertBaseVmIsSafe(baseVmName: string, settings: GrclankerSettings): void {
  const baseVm = getParallelsVmInfo(baseVmName);
  if (!baseVm) {
    throw new Error(`Configured Parallels base VM "${baseVmName}" was not found in \`prlctl list -a\`.`);
  }

  if (baseVm.status !== "stopped") {
    throw new Error(
      `Configured Parallels base VM "${baseVmName}" is ${baseVm.status}. Use a stopped base image or template so grclanker can clone it safely.`,
    );
  }

  if (!resolveParallelsAutoStart(settings)) {
    throw new Error(
      "Disposable Parallels sandboxes require `parallelsAutoStart=true` so grclanker can boot the fresh clone it just created.",
    );
  }
}

function assertTemplateIsUsable(templateName: string, settings: GrclankerSettings): void {
  const template = getParallelsTemplateInfo(templateName);
  if (!template) {
    throw new Error(`Configured Parallels template "${templateName}" was not found in \`prlctl list -a -t\`.`);
  }

  if (!resolveParallelsAutoStart(settings)) {
    throw new Error(
      "Disposable Parallels sandboxes require `parallelsAutoStart=true` so grclanker can boot the fresh sandbox it just created.",
    );
  }
}

export function resolveParallelsSource(settings: GrclankerSettings): ParallelsSource {
  const sourceKind = resolveParallelsSourceKind(settings);
  const sourceName = sourceKind === "template"
    ? resolveParallelsTemplateName(settings)
    : resolveParallelsBaseVmName(settings);
  if (!sourceName) {
    throw new Error(
      sourceKind === "template"
        ? "Parallels sandboxing requires `parallelsTemplateName` so grclanker knows which template to deploy sandboxes from."
        : "Parallels sandboxing requires `parallelsBaseVmName` so grclanker knows which stopped base VM to clone.",
    );
  }
  return { sourceKind, sourceName };
}

export function assertParallelsSourceIsUsable(settings: GrclankerSettings): ParallelsSource {
  const source = resolveParallelsSource(settings);
  if (source.sourceKind === "template") {
    assertTemplateIsUsable(source.sourceName, settings);
  } else {
    assertBaseVmIsSafe(source.sourceName, settings);
  }
  return source;
}

export async function cleanupParallelsSandboxes(): Promise<void> {
  await teardownComputeSessions();
}
