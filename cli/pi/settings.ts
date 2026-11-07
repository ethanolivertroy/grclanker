import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { recoverFileTransactionSync, writeFileAtomicallySync } from "../core/atomic-files.js";
import { ConfigFileError, readJsonConfig } from "../extensions/grc-tools/hardening/config-file.js";
import {
  DEFAULT_COMPUTE_BACKEND,
  isComputeBackendKind,
  isComputeProfile,
  normalizeComputeBackend,
  normalizeComputeDefaults,
  type ComputeBackendKind,
  type ComputeDefaults,
  type ComputeProfile,
  type ParallelsSourceKind,
  normalizeParallelsSourceKind,
} from "./compute.js";

export type SkillDiscoveryMode = "bundled-only" | "bundled-and-project";

export const COMPUTE_BACKEND_OVERRIDE_ENV = "GRCLANKER_COMPUTE_BACKEND_OVERRIDE";

export type GrclankerSettings = Record<string, unknown> & {
  defaultProvider?: string;
  defaultModel?: string;
  modelMode?: "local" | "hosted";
  providerKind?: string;
  providerBaseUrl?: string;
  skillDiscoveryMode?: SkillDiscoveryMode;
  computeBackend?: ComputeBackendKind;
  computeProfile?: ComputeProfile;
  computeDefaults?: ComputeDefaults;
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

function assertJsonObject(path: string, value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ConfigFileError({ kind: "parse", path, format: "JSON", code: "INVALID_JSON" });
  }
  return value as Record<string, unknown>;
}

// A missing file is an empty object. Malformed JSON, or JSON that is not an
// object, throws ConfigFileError with a fixed message so a credential on the
// bad line is not quoted and the caller does not replace the file.
export function readJson(path: string): Record<string, unknown> {
  recoverFileTransactionSync(configurationJournalPath(path));
  const result = readJsonConfig(path);
  if (!result.ok) return {};
  return assertJsonObject(path, result.value);
}

/** Settings and model providers are one recoverable configuration commit. */
export function configurationJournalPath(memberPath: string): string {
  return resolve(dirname(memberPath), ".configuration-transaction.json");
}

export function readModelsConfig(path: string): Record<string, unknown> {
  const parsed = readJson(path);
  if (!parsed.providers || typeof parsed.providers !== "object") {
    parsed.providers = {};
  }
  return parsed;
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
  settings.computeProfile = isComputeProfile(settings.computeProfile)
    ? settings.computeProfile
    : undefined;
  settings.computeDefaults = settings.computeDefaults === undefined
    ? undefined
    : normalizeComputeDefaults(settings.computeDefaults);
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

  writeGrclankerSettings(settingsPath, settings);
}

export function applyComputeBackendOverride(
  settings: GrclankerSettings,
  kind: ComputeBackendKind | undefined,
): GrclankerSettings {
  if (!kind) return settings;
  return { ...settings, computeBackend: kind };
}

export function readGrclankerSettings(path: string): GrclankerSettings {
  const settings = readJson(path) as GrclankerSettings;
  const override = process.env[COMPUTE_BACKEND_OVERRIDE_ENV];
  return isComputeBackendKind(override)
    ? applyComputeBackendOverride(settings, override)
    : settings;
}

export function writeGrclankerSettings(
  path: string,
  settings: GrclankerSettings,
): void {
  recoverFileTransactionSync(configurationJournalPath(path));
  const serialized = JSON.stringify(settings, null, 2) + "\n";
  if (existsSync(path) && readFileSync(path, "utf8") === serialized) return;
  writeFileAtomicallySync(path, serialized, { mode: 0o600 });
}
