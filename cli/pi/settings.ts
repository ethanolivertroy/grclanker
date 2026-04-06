import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import {
  DEFAULT_COMPUTE_BACKEND,
  normalizeComputeBackend,
  type ComputeBackendKind,
  type ParallelsSourceKind,
  normalizeParallelsSourceKind,
} from "./compute.js";

export type SkillDiscoveryMode = "bundled-only" | "bundled-and-project";

export type GrclankerSettings = Record<string, unknown> & {
  defaultProvider?: string;
  defaultModel?: string;
  modelMode?: "local" | "hosted";
  providerKind?: string;
  providerBaseUrl?: string;
  skillDiscoveryMode?: SkillDiscoveryMode;
  computeBackend?: ComputeBackendKind;
  dockerImage?: string;
  dockerWorkspacePath?: string;
  parallelsSourceKind?: ParallelsSourceKind;
  parallelsTemplateName?: string;
  parallelsBaseVmName?: string;
  parallelsVmName?: string;
  parallelsWorkspacePath?: string;
  parallelsAutoStart?: boolean;
  parallelsClonePrefix?: string;
};

function normalizeOptionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
}

export function normalizeSkillDiscoveryMode(value: unknown): SkillDiscoveryMode {
  return value === "bundled-and-project" ? "bundled-and-project" : "bundled-only";
}

export function resolveSkillDiscoveryMode(settings: GrclankerSettings): SkillDiscoveryMode {
  return normalizeSkillDiscoveryMode(settings.skillDiscoveryMode);
}

export function readJson(path: string): Record<string, unknown> {
  if (!existsSync(path)) return {};

  try {
    return JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
  } catch {
    return {};
  }
}

export function normalizeGrclankerSettings(
  settingsPath: string,
  bundledSettingsPath: string,
): void {
  const settings: GrclankerSettings = {
    ...readJson(bundledSettingsPath),
    ...readJson(settingsPath),
  };

  settings.theme = "grclanker";
  settings.quietStartup = true;
  settings.collapseChangelog = true;
  settings.editorPaddingX ??= 1;
  settings.agentScope ??= "both";
  settings.skillDiscoveryMode = normalizeSkillDiscoveryMode(settings.skillDiscoveryMode);
  settings.computeBackend = normalizeComputeBackend(
    (settings.computeBackend as unknown) ?? DEFAULT_COMPUTE_BACKEND,
  );
  const normalizedParallelsBaseVmName =
    normalizeOptionalString(settings.parallelsBaseVmName)
    ?? normalizeOptionalString(settings.parallelsVmName);
  settings.dockerImage = normalizeOptionalString(settings.dockerImage);
  settings.dockerWorkspacePath = normalizeOptionalString(settings.dockerWorkspacePath);
  settings.parallelsSourceKind = normalizeParallelsSourceKind(settings.parallelsSourceKind);
  settings.parallelsTemplateName = normalizeOptionalString(settings.parallelsTemplateName);
  settings.parallelsBaseVmName = normalizedParallelsBaseVmName;
  settings.parallelsVmName = normalizedParallelsBaseVmName;
  settings.parallelsWorkspacePath = normalizeOptionalString(settings.parallelsWorkspacePath);
  settings.parallelsAutoStart =
    typeof settings.parallelsAutoStart === "boolean" ? settings.parallelsAutoStart : undefined;
  settings.parallelsClonePrefix = normalizeOptionalString(settings.parallelsClonePrefix);

  mkdirSync(dirname(settingsPath), { recursive: true });
  writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + "\n", "utf8");
}

export function readGrclankerSettings(path: string): GrclankerSettings {
  return readJson(path) as GrclankerSettings;
}

export function writeGrclankerSettings(
  path: string,
  settings: GrclankerSettings,
): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(settings, null, 2) + "\n", "utf8");
}
