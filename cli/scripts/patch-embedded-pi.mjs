#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const BRAND_NAME = "grclanker";
const BRAND_CONFIG_DIR = ".grclanker";
const PI_TITLE = 'process.title = "pi";';
const BRANDED_TITLE = `process.title = "${BRAND_NAME}";`;
const INTERACTIVE_TITLE = "`π - ${sessionName} - ${cwdBasename}`";
const BRANDED_INTERACTIVE_TITLE = `\`${BRAND_NAME} - \${sessionName} - \${cwdBasename}\``;
const INTERACTIVE_FALLBACK_TITLE = "`π - ${cwdBasename}`";
const BRANDED_INTERACTIVE_FALLBACK_TITLE = `\`${BRAND_NAME} - \${cwdBasename}\``;
const EDITOR_THEME_RE = /export function getEditorTheme\(\) \{[\s\S]*?\n\}\nexport function getSettingsListTheme\(\) \{/m;

const DESIRED_GET_EDITOR_THEME = [
  "export function getEditorTheme() {",
  "    return {",
  '        borderColor: (text) => " ".repeat(text.length),',
  '        bgColor: (text) => theme.bg("userMessageBg", text),',
  '        placeholderText: "Ask about CMVP, KEV, EPSS, or type /audit",',
  '        placeholder: (text) => theme.fg("dim", text),',
  "        selectList: getSelectListTheme(),",
  "    };",
  "}",
].join("\n");

const scriptDir = dirname(fileURLToPath(import.meta.url));
const companionDir = resolve(scriptDir, "..");

function parseRootArg(argv) {
  const index = argv.indexOf("--root");
  if (index === -1) return companionDir;
  const value = argv[index + 1];
  if (!value) {
    throw new Error("Missing value for --root");
  }
  return resolve(value);
}

function patchTextFile(filePath, search, replace) {
  if (!existsSync(filePath)) return false;

  const source = readFileSync(filePath, "utf8");
  if (!source.includes(search) || source.includes(replace)) return false;

  writeFileSync(filePath, source.replace(search, replace), "utf8");
  return true;
}

function patchRegexFile(filePath, pattern, replace) {
  if (!existsSync(filePath)) return false;

  const source = readFileSync(filePath, "utf8");
  const next = source.replace(pattern, replace);
  if (next === source) return false;

  writeFileSync(filePath, next, "utf8");
  return true;
}

function patchEmbeddedPi(rootDir) {
  const rootPackageJson = join(rootDir, "package.json");
  if (!existsSync(rootPackageJson)) {
    throw new Error(`No package.json found under ${rootDir}`);
  }

  const packageRoot = join(rootDir, "node_modules", "@earendil-works", "pi-coding-agent");
  const packageJsonPath = join(packageRoot, "package.json");
  if (!existsSync(packageJsonPath)) {
    throw new Error(`Embedded pi package not found under ${packageRoot}`);
  }
  const pkg = JSON.parse(readFileSync(packageJsonPath, "utf8"));

  let changed = false;

  if (
    pkg.piConfig?.name !== BRAND_NAME ||
    pkg.piConfig?.configDir !== BRAND_CONFIG_DIR
  ) {
    pkg.piConfig = {
      ...(pkg.piConfig ?? {}),
      name: BRAND_NAME,
      configDir: BRAND_CONFIG_DIR,
    };
    writeFileSync(packageJsonPath, `${JSON.stringify(pkg, null, "\t")}\n`, "utf8");
    changed = true;
  }

  changed = patchTextFile(join(packageRoot, "dist", "cli.js"), PI_TITLE, BRANDED_TITLE) || changed;
  changed =
    patchTextFile(join(packageRoot, "dist", "bun", "cli.js"), PI_TITLE, BRANDED_TITLE) ||
    changed;
  changed =
    patchTextFile(
      join(packageRoot, "dist", "modes", "interactive", "interactive-mode.js"),
      INTERACTIVE_TITLE,
      BRANDED_INTERACTIVE_TITLE,
    ) || changed;
  changed =
    patchTextFile(
      join(packageRoot, "dist", "modes", "interactive", "interactive-mode.js"),
      INTERACTIVE_FALLBACK_TITLE,
      BRANDED_INTERACTIVE_FALLBACK_TITLE,
    ) || changed;
  changed =
    patchRegexFile(
      join(packageRoot, "dist", "modes", "interactive", "theme", "theme.js"),
      EDITOR_THEME_RE,
      `${DESIRED_GET_EDITOR_THEME}\nexport function getSettingsListTheme() {`,
    ) || changed;

  return { changed, packageJsonPath };
}

try {
  const rootDir = parseRootArg(process.argv.slice(2));
  const { changed, packageJsonPath } = patchEmbeddedPi(rootDir);
  if (changed) {
    console.log(`Patched embedded pi package at ${packageJsonPath}`);
  } else {
    console.log(`Embedded pi package already branded at ${packageJsonPath}`);
  }
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`Failed to patch embedded pi package: ${message}`);
  process.exit(1);
}
