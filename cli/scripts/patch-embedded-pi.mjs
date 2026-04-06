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
const EDITOR_IMPORT_ORIGINAL =
  'import { getSegmenter, isPunctuationChar, isWhitespaceChar, truncateToWidth, visibleWidth } from "../utils.js";';
const EDITOR_IMPORT_PATCHED =
  'import { applyBackgroundToLine, getSegmenter, isPunctuationChar, isWhitespaceChar, truncateToWidth, visibleWidth } from "../utils.js";';
const EDITOR_THEME_RE = /export function getEditorTheme\(\) \{[\s\S]*?\n\}\nexport function getSettingsListTheme\(\) \{/m;
const EDITOR_RENDER_RE = /    render\(width\) \{[\s\S]*?\n    handleInput\(data\) \{/m;

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

const DESIRED_EDITOR_RENDER = [
  "    render(width) {",
  "        const maxPadding = Math.max(0, Math.floor((width - 1) / 2));",
  "        const paddingX = Math.min(this.paddingX, maxPadding);",
  "        const contentWidth = Math.max(1, width - paddingX * 2);",
  "        // Layout width: with padding the cursor can overflow into it,",
  "        // without padding we reserve 1 column for the cursor.",
  "        const layoutWidth = Math.max(1, contentWidth - (paddingX ? 0 : 1));",
  "        // Store for cursor navigation (must match wrapping width)",
  "        this.lastWidth = layoutWidth;",
  '        const horizontal = this.borderColor("─");',
  "        const bgColor = this.theme.bgColor;",
  "        // Layout the text",
  "        const layoutLines = this.layoutText(layoutWidth);",
  "        // Calculate max visible lines: 30% of terminal height, minimum 5 lines",
  "        const terminalRows = this.tui.terminal.rows;",
  "        const maxVisibleLines = Math.max(5, Math.floor(terminalRows * 0.3));",
  "        // Find the cursor line index in layoutLines",
  "        let cursorLineIndex = layoutLines.findIndex((line) => line.hasCursor);",
  "        if (cursorLineIndex === -1)",
  "            cursorLineIndex = 0;",
  "        // Adjust scroll offset to keep cursor visible",
  "        if (cursorLineIndex < this.scrollOffset) {",
  "            this.scrollOffset = cursorLineIndex;",
  "        }",
  "        else if (cursorLineIndex >= this.scrollOffset + maxVisibleLines) {",
  "            this.scrollOffset = cursorLineIndex - maxVisibleLines + 1;",
  "        }",
  "        // Clamp scroll offset to valid range",
  "        const maxScrollOffset = Math.max(0, layoutLines.length - maxVisibleLines);",
  "        this.scrollOffset = Math.max(0, Math.min(this.scrollOffset, maxScrollOffset));",
  "        // Get visible lines slice",
  "        const visibleLines = layoutLines.slice(this.scrollOffset, this.scrollOffset + maxVisibleLines);",
  "        const result = [];",
  '        const leftPadding = " ".repeat(paddingX);',
  "        const rightPadding = leftPadding;",
  "        const renderBorderLine = (indicator) => {",
  "            const remaining = width - visibleWidth(indicator);",
  "            if (remaining >= 0) {",
  '                return this.borderColor(indicator + "─".repeat(remaining));',
  "            }",
  "            return this.borderColor(truncateToWidth(indicator, width));",
  "        };",
  "        if (bgColor) {",
  "            if (this.scrollOffset > 0) {",
  "                const indicator = `  ↑ ${this.scrollOffset} more`;",
  "                result.push(applyBackgroundToLine(indicator, width, bgColor));",
  "            }",
  "            else {",
  '                result.push(applyBackgroundToLine("", width, bgColor));',
  "            }",
  "        }",
  "        else if (this.scrollOffset > 0) {",
  "            const indicator = `─── ↑ ${this.scrollOffset} more `;",
  "            result.push(renderBorderLine(indicator));",
  "        }",
  "        else {",
  "            result.push(horizontal.repeat(width));",
  "        }",
  "        const emitCursorMarker = this.focused && !this.autocompleteState;",
  "        const showPlaceholder = this.state.lines.length === 1 &&",
  '            this.state.lines[0] === "" &&',
  '            typeof this.theme.placeholderText === "string" &&',
  "            this.theme.placeholderText.length > 0;",
  "        for (let visibleIndex = 0; visibleIndex < visibleLines.length; visibleIndex++) {",
  "            const layoutLine = visibleLines[visibleIndex];",
  "            const isFirstLayoutLine = this.scrollOffset + visibleIndex === 0;",
  "            let displayText = layoutLine.text;",
  "            let lineVisibleWidth = visibleWidth(layoutLine.text);",
  "            const isPlaceholderLine = showPlaceholder && isFirstLayoutLine;",
  "            if (isPlaceholderLine) {",
  '                const marker = emitCursorMarker ? CURSOR_MARKER : "";',
  "                const rawPlaceholder = this.theme.placeholderText;",
  '                const styledPlaceholder = typeof this.theme.placeholder === "function"',
  "                    ? this.theme.placeholder(rawPlaceholder)",
  "                    : rawPlaceholder;",
  "                displayText = marker + styledPlaceholder;",
  "                lineVisibleWidth = visibleWidth(rawPlaceholder);",
  "            }",
  "            else if (layoutLine.hasCursor && layoutLine.cursorPos !== undefined) {",
  '                const marker = emitCursorMarker ? CURSOR_MARKER : "";',
  "                const before = displayText.slice(0, layoutLine.cursorPos);",
  "                const after = displayText.slice(layoutLine.cursorPos);",
  "                displayText = before + marker + after;",
  "            }",
  '            const padding = " ".repeat(Math.max(0, contentWidth - lineVisibleWidth));',
  "            const renderedLine = `${leftPadding}${displayText}${padding}${rightPadding}`;",
  "            result.push(bgColor ? applyBackgroundToLine(renderedLine, width, bgColor) : renderedLine);",
  "        }",
  "        const linesBelow = layoutLines.length - (this.scrollOffset + visibleLines.length);",
  "        if (bgColor) {",
  "            if (linesBelow > 0) {",
  "                const indicator = `  ↓ ${linesBelow} more`;",
  "                result.push(applyBackgroundToLine(indicator, width, bgColor));",
  "            }",
  "            else {",
  '                result.push(applyBackgroundToLine("", width, bgColor));',
  "            }",
  "        }",
  "        else if (linesBelow > 0) {",
  "            const indicator = `─── ↓ ${linesBelow} more `;",
  "            const bottomLine = renderBorderLine(indicator);",
  "            result.push(bottomLine);",
  "        }",
  "        else {",
  "            const bottomLine = horizontal.repeat(width);",
  "            result.push(bottomLine);",
  "        }",
  "        if (this.autocompleteState && this.autocompleteList) {",
  "            const autocompleteResult = this.autocompleteList.render(contentWidth);",
  "            for (const line of autocompleteResult) {",
  "                const lineWidth = visibleWidth(line);",
  '                const linePadding = " ".repeat(Math.max(0, contentWidth - lineWidth));',
  "                const autocompleteLine = `${leftPadding}${line}${linePadding}${rightPadding}`;",
  "                result.push(bgColor ? applyBackgroundToLine(autocompleteLine, width, bgColor) : autocompleteLine);",
  "            }",
  "        }",
  "        return result;",
  "    }",
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

  const packageRoot = join(rootDir, "node_modules", "@mariozechner", "pi-coding-agent");
  const piTuiRoot = join(rootDir, "node_modules", "@mariozechner", "pi-tui");
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
  changed =
    patchTextFile(join(piTuiRoot, "dist", "components", "editor.js"), EDITOR_IMPORT_ORIGINAL, EDITOR_IMPORT_PATCHED) ||
    changed;
  changed =
    patchRegexFile(
      join(piTuiRoot, "dist", "components", "editor.js"),
      EDITOR_RENDER_RE,
      `${DESIRED_EDITOR_RENDER}\n    handleInput(data) {`,
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
