import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { stdin as input, stdout as output } from "node:process";
import {
  autocomplete,
  cancel,
  confirm,
  intro,
  isCancel,
  outro,
  select,
  text,
  type Option,
} from "@clack/prompts";
import {
  getGrclankerModelsPath,
  getGrclankerSettingsPath,
} from "../config/paths.js";
import {
  type GrclankerSettings,
  readGrclankerSettings,
  resolveSkillDiscoveryMode,
  type SkillDiscoveryMode,
  writeGrclankerSettings,
} from "./settings.js";
import {
  DEFAULT_DOCKER_IMAGE,
  DEFAULT_DOCKER_WORKSPACE_PATH,
  DEFAULT_PARALLELS_SOURCE_KIND,
  detectComputeBackendStatuses,
  getComputeBackendChoices,
  isComputeBackendAvailable,
  listParallelsTemplates,
  listParallelsVms,
  resolveComputeBackend,
  resolveDockerImage,
  resolveDockerWorkspacePath,
  resolveParallelsBaseVmName,
  resolveParallelsClonePrefix,
  resolveParallelsSourceKind,
  resolveParallelsTemplateName,
  resolveParallelsWorkspacePath,
  type ComputeBackendKind,
  type ParallelsSourceKind,
  type ParallelsVmInfo,
} from "./compute.js";
import { getProjectSandboxConfigPath } from "./sandbox.js";

type SetupMode = "local" | "hosted";

type LocalProviderConfig = {
  providers: {
    ollama: {
      baseUrl: string;
      api: "openai-completions";
      apiKey: "ollama";
      compat: {
        supportsDeveloperRole: false;
        supportsReasoningEffort: false;
      };
      models: Array<{
        id: string;
        name: string;
        reasoning: false;
        input: ["text"];
      }>;
    };
  };
};

const LOCAL_PROVIDER = "ollama";
const LOCAL_BASE_URL = "http://localhost:11434/v1";
const LOCAL_MODEL = "gemma4";
const LOCAL_MODEL_PREFERENCES = [
  "gemma4",
  "gemma4:latest",
  "gemma3:4b",
  "gemma3:12b",
  "gemma3:27b",
  "gemma3:latest",
  "llama3.2:3b",
  "llama3.1:latest",
  "granite4:micro",
  "phi3:mini",
  "tinyllama:latest",
] as const;
const HOSTED_DEFAULTS = {
  openai: "gpt-5.2",
  anthropic: "claude-sonnet-4-20250514",
  google: "gemini-2.5-pro",
} as const;
const HOSTED_MODEL_OPTIONS = {
  openai: ["gpt-5.2", "gpt-5", "gpt-5-mini", "gpt-5-nano", "gpt-4.1"],
  anthropic: [
    "claude-sonnet-4-20250514",
    "claude-opus-4-1-20250805",
    "claude-opus-4-20250514",
    "claude-3-7-sonnet-20250219",
  ],
  google: ["gemini-2.5-pro", "gemini-2.5-flash", "gemini-2.5-flash-lite"],
} as const;
const COMMON_DOCKER_IMAGES = [
  "ubuntu:24.04",
  "debian:bookworm-slim",
  "python:3.12-slim",
  "node:20-bookworm",
  "alpine:3.20",
] as const;
const CUSTOM_TEMPLATE_OPTION = "__custom_template__";
const CUSTOM_BASE_VM_OPTION = "__custom_base_vm__";
const CUSTOM_LOCAL_MODEL_OPTION = "__custom_local_model__";
const CUSTOM_HOSTED_MODEL_OPTION = "__custom_hosted_model__";
const CUSTOM_DOCKER_IMAGE_OPTION = "__custom_docker_image__";

class SetupCancelledError extends Error {
  constructor() {
    super("Setup cancelled.");
    this.name = "SetupCancelledError";
  }
}

export class GrclankerUserError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GrclankerUserError";
  }
}

function normalizeBaseUrl(raw: string): string {
  const trimmed = raw.trim().replace(/\/+$/, "");
  if (!trimmed) return LOCAL_BASE_URL;
  if (trimmed.endsWith("/v1")) return trimmed;
  return `${trimmed}/v1`;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function isConfigured(settings: GrclankerSettings): boolean {
  return (
    (settings.modelMode === "local" || settings.modelMode === "hosted") &&
    isNonEmptyString(settings.defaultProvider) &&
    isNonEmptyString(settings.defaultModel) &&
    isNonEmptyString(settings.providerKind)
  );
}

function loadModelsConfig(path: string): Record<string, unknown> {
  if (!existsSync(path)) {
    return { providers: {} };
  }

  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
    if (!parsed.providers || typeof parsed.providers !== "object") {
      parsed.providers = {};
    }
    return parsed;
  } catch {
    return { providers: {} };
  }
}

function writeModelsConfig(path: string, config: Record<string, unknown>): void {
  writeFileSync(path, JSON.stringify(config, null, 2) + "\n", "utf8");
}

function unwrapPrompt<T>(value: T | symbol): T {
  if (isCancel(value)) {
    throw new SetupCancelledError();
  }

  return value;
}

function uniqueStrings(values: Iterable<string>): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const value of values) {
    const trimmed = value.trim();
    if (!trimmed || seen.has(trimmed)) continue;
    seen.add(trimmed);
    result.push(trimmed);
  }
  return result;
}

async function promptWithDefault(question: string, fallback: string): Promise<string> {
  const answer = unwrapPrompt(await text({
    message: question,
    defaultValue: fallback,
    placeholder: fallback,
  })).trim();
  return answer || fallback;
}

async function promptYesNo(question: string, defaultValue: boolean): Promise<boolean> {
  return unwrapPrompt(await confirm({
    message: question,
    initialValue: defaultValue,
  }));
}

function formatParallelsVmChoice(vm: ParallelsVmInfo): string {
  return `${vm.name} (${vm.status})`;
}

async function promptParallelsSourceKind(
  settings: GrclankerSettings,
  templates: ParallelsVmInfo[],
): Promise<ParallelsSourceKind> {
  const fallback = templates.length > 0
    ? "template"
    : resolveParallelsSourceKind(settings) ?? DEFAULT_PARALLELS_SOURCE_KIND;

  console.log("Parallels source strategy:");
  console.log("  template   recommended for Windows, Linux, and macOS automation sandboxes");
  console.log("  base-vm    fallback if you do not have a dedicated template yet");
  console.log("");

  while (true) {
    const selected = unwrapPrompt(await select<ParallelsSourceKind>({
      message: "Parallels source kind",
      initialValue: fallback,
      options: [
        {
          value: "template",
          label: "Template",
          hint: "recommended for disposable automation sandboxes",
        },
        {
          value: "base-vm",
          label: "Stopped base VM",
          hint: "fallback if you do not have a dedicated template yet",
        },
      ],
    }));

    if (selected === "template" && templates.length === 0) {
      const saveWithoutTemplate = await promptYesNo(
        "No Parallels templates were detected. Save template mode anyway?",
        false,
      );
      if (!saveWithoutTemplate) continue;
    }

    return selected;
  }
}

async function promptParallelsTemplateName(
  settings: GrclankerSettings,
  templates: ParallelsVmInfo[],
): Promise<string> {
  const configuredTemplate = resolveParallelsTemplateName(settings)?.trim();
  const defaultTemplate = configuredTemplate ?? templates[0]?.name ?? "template-name";

  if (templates.length === 0) {
    return promptWithDefault("Parallels template name", defaultTemplate);
  }

  const options: Array<Option<string>> = templates.map((vm) => ({
    value: vm.name,
    label: formatParallelsVmChoice(vm),
  }));
  options.push({
    value: CUSTOM_TEMPLATE_OPTION,
    label: "Enter a custom template name",
    hint: "use this if the template is not in the detected list",
  });

  while (true) {
    const answer = unwrapPrompt(await autocomplete<string>({
      message: "Parallels template",
      initialValue: templates.some((vm) => vm.name === defaultTemplate)
        ? defaultTemplate
        : CUSTOM_TEMPLATE_OPTION,
      options,
      maxItems: 10,
    }));

    if (answer !== CUSTOM_TEMPLATE_OPTION) return answer;

    const customName = (await promptWithDefault("Parallels template name", defaultTemplate)).trim();
    const exactMatch = templates.find((vm) => vm.name === customName || vm.uuid === customName);
    if (exactMatch) return exactMatch.name;

    const saveAnyway = await promptYesNo(
      `No detected template matches "${customName}". Save that name anyway?`,
      false,
    );
    if (saveAnyway) return customName;
  }
}

async function promptParallelsBaseVmName(
  settings: GrclankerSettings,
  vms: ParallelsVmInfo[],
): Promise<string> {
  const configuredVm = resolveParallelsBaseVmName(settings)?.trim();
  const defaultVmName = configuredVm ?? vms[0]?.name ?? "vm-name";

  if (vms.length === 0) {
    return promptWithDefault("Parallels stopped base VM", defaultVmName);
  }

  console.log("Pick a stopped base VM. grclanker will clone it and never exec into the base directly.");

  const options: Array<Option<string>> = vms.map((vm) => ({
    value: vm.name,
    label: formatParallelsVmChoice(vm),
    hint: vm.status === "stopped" ? "safe clone source" : "not currently stopped",
  }));
  options.push({
    value: CUSTOM_BASE_VM_OPTION,
    label: "Enter a custom base VM name",
    hint: "use this if the VM is not in the detected list",
  });

  while (true) {
    const answer = unwrapPrompt(await autocomplete<string>({
      message: "Parallels stopped base VM",
      initialValue: vms.some((vm) => vm.name === defaultVmName)
        ? defaultVmName
        : CUSTOM_BASE_VM_OPTION,
      options,
      maxItems: 10,
    }));

    if (answer === CUSTOM_BASE_VM_OPTION) {
      const customName = (await promptWithDefault("Parallels stopped base VM", defaultVmName)).trim();
      const selected = vms.find((vm) => vm.name === customName || vm.uuid === customName);
      if (!selected || selected.status === "stopped") return customName;
      const saveRunningVm = await promptYesNo(
        `Base VM "${selected.name}" is ${selected.status}. Save it anyway?`,
        false,
      );
      if (saveRunningVm) return customName;
      continue;
    }

    const selected = vms.find((vm) => vm.name === answer || vm.uuid === answer);
    if (!selected) {
      const saveAnyway = await promptYesNo(
        `No detected VM matches "${answer}". Save that name anyway?`,
        false,
      );
      if (saveAnyway) return answer;
      continue;
    }

    if (selected.status === "stopped") return selected.name;

    const saveRunningVm = await promptYesNo(
      `Base VM "${selected.name}" is ${selected.status}. Save it anyway?`,
      false,
    );
    if (saveRunningVm) return selected.name;
  }
}

async function promptParallelsWorkspaceOverride(
  settings: GrclankerSettings,
): Promise<string | undefined> {
  console.log("");
  console.log("grclanker will attach the current repo to each disposable clone as a shared folder.");
  console.log("Leave this on auto-detect unless your guest mounts host shares somewhere custom.");

  const configuredPath = resolveParallelsWorkspacePath(settings);
  const answer = unwrapPrompt(await text({
    message: "Guest workspace override",
    defaultValue: configuredPath ?? "auto-detect",
    placeholder: configuredPath ?? "auto-detect",
  })).trim();

  if (!answer) return configuredPath;
  if (answer.toLowerCase() === "auto" || answer.toLowerCase() === "auto-detect") {
    return undefined;
  }

  return answer;
}

async function promptMode(settings: GrclankerSettings): Promise<SetupMode> {
  const initialValue = settings.modelMode === "hosted" ? "hosted" : "local";
  return unwrapPrompt(await select<SetupMode>({
    message: "Choose model mode",
    initialValue,
    options: [
      {
        value: "local",
        label: "Local-first",
        hint: "recommended: Ollama + Gemma running on this machine",
      },
      {
        value: "hosted",
        label: "Hosted",
        hint: "use OpenAI, Anthropic, or Google credentials",
      },
    ],
  }));
}

async function promptHostedProvider(
  settings: GrclankerSettings,
): Promise<keyof typeof HOSTED_DEFAULTS> {
  const initialValue = settings.providerKind === "anthropic" || settings.providerKind === "google"
    ? settings.providerKind
    : "openai";

  return unwrapPrompt(await select<keyof typeof HOSTED_DEFAULTS>({
    message: "Hosted provider",
    initialValue,
    options: [
      { value: "openai", label: "OpenAI", hint: HOSTED_DEFAULTS.openai },
      { value: "anthropic", label: "Anthropic", hint: HOSTED_DEFAULTS.anthropic },
      { value: "google", label: "Google", hint: HOSTED_DEFAULTS.google },
    ],
  }));
}

async function promptHostedModel(
  provider: keyof typeof HOSTED_DEFAULTS,
  settings: GrclankerSettings,
): Promise<string> {
  const currentModel = settings.providerKind === provider && isNonEmptyString(settings.defaultModel)
    ? settings.defaultModel.trim()
    : "";
  const defaultModel = currentModel || HOSTED_DEFAULTS[provider];
  const modelOptions = uniqueStrings([
    currentModel,
    HOSTED_DEFAULTS[provider],
    ...HOSTED_MODEL_OPTIONS[provider],
  ]);

  const options: Array<Option<string>> = modelOptions.map((modelId) => ({
    value: modelId,
    label: modelId,
    hint: modelId === defaultModel ? "recommended" : "suggested",
  }));
  options.push({
    value: CUSTOM_HOSTED_MODEL_OPTION,
    label: "Enter a custom model id",
    hint: "use this if the provider model you want is not listed",
  });

  const answer = unwrapPrompt(await autocomplete<string>({
    message: `Default model for ${provider}`,
    initialValue: modelOptions.includes(defaultModel) ? defaultModel : CUSTOM_HOSTED_MODEL_OPTION,
    options,
    maxItems: 10,
  }));

  if (answer === CUSTOM_HOSTED_MODEL_OPTION) {
    return promptWithDefault(`Default model for ${provider}`, defaultModel);
  }

  return answer;
}

async function promptComputeBackend(fallback: ComputeBackendKind): Promise<ComputeBackendKind> {
  const statuses = detectComputeBackendStatuses();

  console.log("Choose a default compute backend.");
  console.log("Pick where grclanker should run bash, file, and search tools by default.");

  const options: Array<Option<ComputeBackendKind>> = getComputeBackendChoices().map((option) => {
    const status = statuses.find((entry) => entry.kind === option.kind);
    const availabilityHint = status?.available ? "detected" : "not detected";
    return {
      value: option.kind,
      label: option.kind,
      hint: `${option.summary} · ${availabilityHint}`,
    };
  });

  while (true) {
    const selected = unwrapPrompt(await select<ComputeBackendKind>({
      message: "Compute backend",
      initialValue: fallback,
      options,
      maxItems: 8,
    }));

    if (selected !== "host" && !isComputeBackendAvailable(selected)) {
      const saveAnyway = await promptYesNo(
        `${selected} is not detected on this machine. Save it as the preferred backend anyway?`,
        false,
      );
      if (!saveAnyway) continue;
    }

    return selected;
  }
}

function listAvailableDockerImages(): string[] {
  if (!isComputeBackendAvailable("docker")) return [];

  const result = spawnSync("docker", ["image", "ls", "--format", "{{.Repository}}:{{.Tag}}"], {
    encoding: "utf8",
  });

  if (result.status !== 0) return [];

  return uniqueStrings(
    result.stdout
      .split(/\r?\n/)
      .filter((value) => value && !value.startsWith("<none>:")),
  );
}

async function promptDockerImage(settings: GrclankerSettings): Promise<string> {
  const currentImage = resolveDockerImage(settings) || DEFAULT_DOCKER_IMAGE;
  const installedImages = listAvailableDockerImages();
  const imageOptions = uniqueStrings([
    currentImage,
    DEFAULT_DOCKER_IMAGE,
    ...installedImages,
    ...COMMON_DOCKER_IMAGES,
  ]);

  const options: Array<Option<string>> = imageOptions.map((image) => ({
    value: image,
    label: image,
    hint: installedImages.includes(image)
      ? image === currentImage
        ? "current · installed"
        : "installed"
      : image === currentImage
        ? "current"
        : "common",
  }));
  options.push({
    value: CUSTOM_DOCKER_IMAGE_OPTION,
    label: "Enter a custom Docker image",
    hint: "use this if the image you want is not listed",
  });

  const answer = unwrapPrompt(await autocomplete<string>({
    message: "Docker image",
    initialValue: imageOptions.includes(currentImage) ? currentImage : CUSTOM_DOCKER_IMAGE_OPTION,
    options,
    maxItems: 12,
  }));

  if (answer === CUSTOM_DOCKER_IMAGE_OPTION) {
    return promptWithDefault("Docker image", currentImage);
  }

  return answer;
}

async function promptComputeBackendSettings(
  settings: GrclankerSettings,
  computeBackend: ComputeBackendKind,
): Promise<Partial<GrclankerSettings>> {
  const nextSettings: Partial<GrclankerSettings> = { computeBackend };

  if (computeBackend === "sandbox-runtime") {
    console.log("");
    console.log("sandbox-runtime settings");
    console.log(
      `Use ${getProjectSandboxConfigPath(process.cwd())} to tighten allowed domains or filesystem paths for this repo.`,
    );
  }

  if (computeBackend === "docker") {
    console.log("");
    console.log("Docker backend settings");
    console.log("grclanker will bind-mount the current repo into the container for bash commands.");
    nextSettings.dockerImage = await promptDockerImage(settings);
    nextSettings.dockerWorkspacePath = await promptWithDefault(
      "Container workspace path",
      resolveDockerWorkspacePath(settings) || DEFAULT_DOCKER_WORKSPACE_PATH,
    );
  }

  if (computeBackend === "parallels-vm") {
    console.log("");
    console.log("Parallels backend settings");
    console.log("grclanker deploys disposable sandboxes for Windows, Linux, or macOS guests.");
    console.log("Preferred path: a dedicated Parallels template built for automation.");
    console.log("Fallback path: a stopped base VM cloned into a disposable sandbox.");
    const vms = listParallelsVms();
    const templates = listParallelsTemplates();
    nextSettings.parallelsAutoStart = true;
    nextSettings.parallelsSourceKind = await promptParallelsSourceKind(settings, templates);
    if (nextSettings.parallelsSourceKind === "template") {
      nextSettings.parallelsTemplateName = await promptParallelsTemplateName(settings, templates);
      nextSettings.parallelsBaseVmName = undefined;
      nextSettings.parallelsVmName = undefined;
    } else {
      nextSettings.parallelsBaseVmName = await promptParallelsBaseVmName(settings, vms);
      nextSettings.parallelsVmName = nextSettings.parallelsBaseVmName;
      nextSettings.parallelsTemplateName = undefined;
    }
    nextSettings.parallelsClonePrefix = await promptWithDefault(
      "Disposable clone name prefix",
      resolveParallelsClonePrefix(settings),
    );
    nextSettings.parallelsWorkspacePath = await promptParallelsWorkspaceOverride(settings);
  }

  return nextSettings;
}

async function promptLocalModel(
  suggestedModel: string,
  installedLocalModels: string[],
): Promise<string> {
  if (installedLocalModels.length === 0) {
    return promptWithDefault("Local model", suggestedModel);
  }

  const options: Array<Option<string>> = installedLocalModels.map((modelId) => ({
    value: modelId,
    label: modelId,
    hint: modelId === suggestedModel ? "recommended" : "installed",
  }));
  options.push({
    value: CUSTOM_LOCAL_MODEL_OPTION,
    label: "Enter a custom model id",
    hint: "use this if you want a model not shown in the detected list",
  });

  const answer = unwrapPrompt(await autocomplete<string>({
    message: "Local model",
    initialValue: installedLocalModels.includes(suggestedModel)
      ? suggestedModel
      : CUSTOM_LOCAL_MODEL_OPTION,
    options,
    maxItems: 10,
  }));

  if (answer === CUSTOM_LOCAL_MODEL_OPTION) {
    return promptWithDefault("Local model", suggestedModel);
  }

  return answer;
}

function hasAdvancedComputeConfiguration(settings: GrclankerSettings): boolean {
  return resolveComputeBackend(settings) !== "host";
}

async function promptAdvancedComputeSetup(settings: GrclankerSettings): Promise<boolean> {
  const defaultValue = hasAdvancedComputeConfiguration(settings);
  return promptYesNo(
    "Configure advanced compute backend settings (Docker, sandbox-runtime, Parallels)?",
    defaultValue,
  );
}

async function promptSkillDiscoveryMode(
  settings: GrclankerSettings,
): Promise<SkillDiscoveryMode> {
  const currentMode = resolveSkillDiscoveryMode(settings);

  console.log("");
  console.log("Skill visibility");
  console.log("grclanker always ships its own bundled GRC skills.");
  console.log("You can keep the session isolated to those, or also expose project/local Pi skills.");

  return unwrapPrompt(await select<SkillDiscoveryMode>({
    message: "Which skills should grclanker expose by default?",
    initialValue: currentMode,
    options: [
      {
        value: "bundled-only",
        label: "Bundled grclanker skills only",
        hint: "recommended · hides repo .agents/.pi skills and global Pi skill folders",
      },
      {
        value: "bundled-and-project",
        label: "Bundled + project/local Pi skills",
        hint: "also discovers .agents/skills, .pi/skills, and local Pi skill folders",
      },
    ],
  }));
}

async function fetchModelIds(baseUrl: string): Promise<string[]> {
  const url = `${baseUrl.replace(/\/+$/, "")}/models`;
  const response = await fetch(url, {
    headers: { Authorization: "Bearer ollama" },
    signal: AbortSignal.timeout(3000),
  });

  if (!response.ok) {
    throw new Error(`Received ${response.status} from ${url}`);
  }

  const payload = (await response.json()) as { data?: Array<{ id?: string }> };
  return Array.isArray(payload.data)
    ? payload.data.map((item) => item.id).filter(isNonEmptyString)
    : [];
}

function isCloudModel(modelId: string): boolean {
  return modelId.endsWith(":cloud") || modelId.endsWith("-cloud");
}

function isInstalledModel(modelIds: string[], modelId: string): boolean {
  return modelIds.some(
    (candidate) => candidate === modelId || candidate.startsWith(`${modelId}:`),
  );
}

function filterLocalModels(modelIds: string[]): string[] {
  return modelIds.filter((modelId) => !isCloudModel(modelId));
}

function choosePreferredLocalModel(modelIds: string[]): string | undefined {
  for (const preferred of LOCAL_MODEL_PREFERENCES) {
    const match = modelIds.find(
      (candidate) => candidate === preferred || candidate.startsWith(`${preferred}:`),
    );
    if (match) return match;
  }

  return modelIds.find((modelId) => modelId.startsWith("gemma")) ?? modelIds[0];
}

async function fetchReachableModelIds(baseUrl: string, modelId: string): Promise<string[]> {
  try {
    return await fetchModelIds(baseUrl);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new GrclankerUserError(
      [
        `Could not reach a local OpenAI-compatible endpoint at ${baseUrl}.`,
        "",
        "Expected local-first path:",
        "  ollama serve",
        `  ollama pull ${modelId}`,
        "  grclanker setup",
        "",
        `Reachability error: ${message}`,
      ].join("\n"),
    );
  }
}

function localModelsConfig(baseUrl: string, modelId: string): LocalProviderConfig {
  return {
    providers: {
      ollama: {
        baseUrl,
        api: "openai-completions",
        apiKey: "ollama",
        compat: {
          supportsDeveloperRole: false,
          supportsReasoningEffort: false,
        },
        models: [
          {
            id: modelId,
            name: `${modelId} (Local)`,
            reasoning: false,
            input: ["text"],
          },
        ],
      },
    },
  };
}

function saveLocalSetup(
  settingsPath: string,
  modelsPath: string,
  baseSettings: GrclankerSettings,
  baseUrl: string,
  modelId: string,
  computeSettings: Partial<GrclankerSettings>,
): void {
  const settings: GrclankerSettings = {
    ...baseSettings,
    modelMode: "local",
    providerKind: LOCAL_PROVIDER,
    providerBaseUrl: baseUrl,
    defaultProvider: LOCAL_PROVIDER,
    defaultModel: modelId,
    ...computeSettings,
  };
  writeGrclankerSettings(settingsPath, settings);

  const modelsConfig = loadModelsConfig(modelsPath);
  const providers =
    modelsConfig.providers && typeof modelsConfig.providers === "object"
      ? (modelsConfig.providers as Record<string, unknown>)
      : {};
  providers[LOCAL_PROVIDER] = localModelsConfig(baseUrl, modelId).providers.ollama;
  writeModelsConfig(modelsPath, { ...modelsConfig, providers });
}

function saveHostedSetup(
  settingsPath: string,
  baseSettings: GrclankerSettings,
  provider: keyof typeof HOSTED_DEFAULTS,
  modelId: string,
  computeSettings: Partial<GrclankerSettings>,
): void {
  const settings: GrclankerSettings = {
    ...baseSettings,
    modelMode: "hosted",
    providerKind: provider,
    defaultProvider: provider,
    defaultModel: modelId,
    ...computeSettings,
  };
  delete settings.providerBaseUrl;
  writeGrclankerSettings(settingsPath, settings);
}

function describeSkillDiscoveryMode(mode: SkillDiscoveryMode): string {
  return mode === "bundled-and-project"
    ? "Bundled grclanker skills plus discovered project/local Pi skills."
    : "Bundled grclanker skills only.";
}

export async function ensureCliConfigured(): Promise<void> {
  const settings = readGrclankerSettings(getGrclankerSettingsPath());
  if (isConfigured(settings)) return;

  if (!input.isTTY || !output.isTTY) {
    throw new Error(
      "grclanker is not configured yet. Run `grclanker setup` in an interactive terminal first.",
    );
  }

  await runSetupWizard();
}

export async function runSetupWizard(force = true): Promise<void> {
  const settingsPath = getGrclankerSettingsPath();
  const modelsPath = getGrclankerModelsPath();
  const settings = readGrclankerSettings(settingsPath);
  const currentComputeBackend = resolveComputeBackend(settings);

  if (!force && isConfigured(settings)) {
    return;
  }

  try {
    intro("grclanker setup");
    console.log("Configure the CLI before first use.");
    console.log("Recommended local-first path: Ollama + Gemma 4.\n");
    console.log("This wizard now covers model choice, compute backend, and skill visibility.\n");

    const mode = await promptMode(settings);

    if (mode === "local") {
      const configuredBaseUrl = settings.providerKind === LOCAL_PROVIDER && isNonEmptyString(settings.providerBaseUrl)
        ? normalizeBaseUrl(settings.providerBaseUrl)
        : LOCAL_BASE_URL;
      const baseUrl = normalizeBaseUrl(
        await promptWithDefault("Local endpoint", configuredBaseUrl),
      );
      const reachableModelIds = await fetchReachableModelIds(baseUrl, LOCAL_MODEL);
      const installedLocalModels = filterLocalModels(reachableModelIds);
      let suggestedModel = choosePreferredLocalModel(installedLocalModels)
        ?? (settings.providerKind === LOCAL_PROVIDER && isNonEmptyString(settings.defaultModel)
          ? settings.defaultModel
          : LOCAL_MODEL);

      while (true) {
        const modelId = await promptLocalModel(suggestedModel, installedLocalModels);
        if (isInstalledModel(reachableModelIds, modelId)) {
          const shouldConfigureCompute = await promptAdvancedComputeSetup(settings);
          const computeBackend = shouldConfigureCompute
            ? await promptComputeBackend(currentComputeBackend)
            : currentComputeBackend;
          const computeSettings = shouldConfigureCompute
            ? await promptComputeBackendSettings(settings, computeBackend)
            : { computeBackend };
          const skillDiscoveryMode = await promptSkillDiscoveryMode(settings);

          saveLocalSetup(settingsPath, modelsPath, settings, baseUrl, modelId, {
            ...computeSettings,
            skillDiscoveryMode,
          });
          console.log("");
          console.log(`Pinned local runtime to ${LOCAL_PROVIDER}/${modelId}.`);
          console.log(`Preferred compute backend: ${computeBackend}.`);
          console.log(`Skill visibility: ${describeSkillDiscoveryMode(skillDiscoveryMode)}`);
          if (!shouldConfigureCompute) {
            console.log("Skipped advanced compute setup. Re-run setup later if you want Docker or Parallels.");
          }
          console.log("grclanker will stay on that local model until you rerun setup.");
          outro("Saved local-first setup.");
          return;
        }

        const fallbackModel = choosePreferredLocalModel(installedLocalModels);
        console.log(`\nReached ${baseUrl}, but ${modelId} is not installed locally.\n`);

        if (fallbackModel && fallbackModel !== modelId) {
          const useFallback = await promptYesNo(
            `Use installed local model ${fallbackModel} instead?`,
            true,
          );
          if (useFallback) {
            const shouldConfigureCompute = await promptAdvancedComputeSetup(settings);
            const computeBackend = shouldConfigureCompute
              ? await promptComputeBackend(currentComputeBackend)
              : currentComputeBackend;
            const computeSettings = shouldConfigureCompute
              ? await promptComputeBackendSettings(settings, computeBackend)
              : { computeBackend };
            const skillDiscoveryMode = await promptSkillDiscoveryMode(settings);

            saveLocalSetup(
              settingsPath,
              modelsPath,
              settings,
              baseUrl,
              fallbackModel,
              {
                ...computeSettings,
                skillDiscoveryMode,
              },
            );
            console.log("");
            console.log(`Pinned local runtime to ${LOCAL_PROVIDER}/${fallbackModel}.`);
            console.log(`Preferred compute backend: ${computeBackend}.`);
            console.log(`Skill visibility: ${describeSkillDiscoveryMode(skillDiscoveryMode)}`);
            if (!shouldConfigureCompute) {
              console.log("Skipped advanced compute setup. Re-run setup later if you want Docker or Parallels.");
            }
            console.log("grclanker will stay on that local model until you rerun setup.");
            outro("Saved local-first setup.");
            return;
          }
          suggestedModel = fallbackModel;
        }

        console.log("Install another local model or enter a different one:");
        console.log(`  ollama pull ${modelId}`);
        console.log(
          `Installed local models: ${installedLocalModels.length > 0 ? installedLocalModels.join(", ") : "none"}`,
        );
        console.log("");
      }
    }

    const provider = await promptHostedProvider(settings);
    const modelId = await promptHostedModel(provider, settings);
    const shouldConfigureCompute = await promptAdvancedComputeSetup(settings);
    const computeBackend = shouldConfigureCompute
      ? await promptComputeBackend(currentComputeBackend)
      : currentComputeBackend;
    const computeSettings = shouldConfigureCompute
      ? await promptComputeBackendSettings(settings, computeBackend)
      : { computeBackend };
    const skillDiscoveryMode = await promptSkillDiscoveryMode(settings);

    saveHostedSetup(settingsPath, settings, provider, modelId, {
      ...computeSettings,
      skillDiscoveryMode,
    });
    console.log("");
    console.log(`Preferred compute backend: ${computeBackend}.`);
    console.log(`Skill visibility: ${describeSkillDiscoveryMode(skillDiscoveryMode)}`);
    if (!shouldConfigureCompute) {
      console.log("Skipped advanced compute setup. Re-run setup later if you want Docker or Parallels.");
    }
    console.log("grclanker will use the configured provider/model when credentials are available.");
    outro("Saved hosted setup.");
  } catch (error) {
    if (error instanceof SetupCancelledError) {
      cancel("Setup cancelled.");
      return;
    }
    throw error;
  }
}
