/**
 * The parts of Pi's interactive mode that the durable terminal app uses but
 * `@earendil-works/pi-coding-agent` does not export: the shared theme
 * instance, the editor theme, the app keybindings, the working status
 * indicator, and token counts.
 *
 * Adapted from pi-coding-agent 1.3.0 (`src/modes/interactive/` and
 * `src/core/keybindings.ts`). Copyright (c) 2025 Mario Zechner. MIT License;
 * see NOTICE.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { getSelectListTheme, type Theme } from "@earendil-works/pi-coding-agent";
import {
  type EditorTheme,
  type KeybindingDefinitions,
  type KeybindingsConfig,
  KeybindingsManager,
  Loader,
  TUI_KEYBINDINGS,
  truncateToWidth,
  type TUI,
} from "@earendil-works/pi-tui";

const THEME_KEY = Symbol.for("@earendil-works/pi-coding-agent:theme");

/** The theme `initTheme()` installed. Pi shares it through globalThis, so its components draw with the same one. */
export const theme = new Proxy({} as Theme, {
  get(_target, property) {
    const current = (globalThis as { [THEME_KEY]?: Theme })[THEME_KEY];
    if (!current) throw new Error("Theme not initialized. Call initTheme() first.");
    return current[property as keyof Theme];
  },
});

export function durableEditorTheme(): EditorTheme {
  return { borderColor: (text) => theme.fg("borderMuted", text), selectList: getSelectListTheme() };
}

function useWindowsKeybindings(platform = process.platform, env = process.env): boolean {
  return platform === "win32" || (platform === "linux" && Boolean(env.WSL_DISTRO_NAME || env.WSL_INTEROP));
}

const windowsKeybindings = useWindowsKeybindings();

/** Pi's defaults for the app actions this terminal app handles. */
const APP_KEYBINDINGS = {
  "app.interrupt": { defaultKeys: "escape", description: "Cancel or abort" },
  "app.clear": { defaultKeys: "ctrl+c", description: "Exit" },
  "app.exit": { defaultKeys: "ctrl+d", description: "Exit when editor is empty" },
  "app.thinking.cycle": { defaultKeys: "shift+tab", description: "Cycle thinking level" },
  "app.model.select": { defaultKeys: "ctrl+l", description: "Open model selector" },
  "app.tools.expand": { defaultKeys: "ctrl+o", description: "Toggle tool output" },
  "app.message.followUp": {
    defaultKeys: windowsKeybindings ? "ctrl+q" : "alt+enter",
    description: "Queue follow-up message",
  },
} satisfies KeybindingDefinitions;

const DURABLE_KEYBINDINGS: KeybindingDefinitions = {
  ...TUI_KEYBINDINGS,
  "tui.editor.undo": {
    ...TUI_KEYBINDINGS["tui.editor.undo"],
    defaultKeys: process.platform === "win32" ? "ctrl+z" : windowsKeybindings ? "alt+z" : "ctrl+-",
  },
  "tui.altScreen.previousPrompt": {
    ...TUI_KEYBINDINGS["tui.altScreen.previousPrompt"],
    defaultKeys: windowsKeybindings ? "ctrl+up" : ["ctrl+shift+up", "ctrl+up"],
  },
  "tui.altScreen.nextPrompt": {
    ...TUI_KEYBINDINGS["tui.altScreen.nextPrompt"],
    defaultKeys: windowsKeybindings ? "ctrl+down" : ["ctrl+shift+down", "ctrl+down"],
  },
  "tui.altScreen.search": {
    ...TUI_KEYBINDINGS["tui.altScreen.search"],
    defaultKeys: windowsKeybindings ? "ctrl+f" : "ctrl+shift+f",
  },
  ...APP_KEYBINDINGS,
};

function isKeyList(value: unknown): value is string | string[] {
  return typeof value === "string" || (Array.isArray(value) && value.every((key) => typeof key === "string"));
}

/** The overrides in a Pi `keybindings.json`; an unreadable file, or an entry that is not a key or list of keys, is ignored. */
function readUserKeybindings(path: string): KeybindingsConfig {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8").replace(/^\uFEFF/, ""));
  } catch {
    return {};
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return {};
  const config: KeybindingsConfig = {};
  for (const [action, keys] of Object.entries(raw)) {
    if (Object.hasOwn(DURABLE_KEYBINDINGS, action) && isKeyList(keys)) config[action] = keys as KeybindingsConfig[string];
  }
  return config;
}

/** Pi's keybindings for the editor, the alt screen, and the app actions above, with the overrides in `<agentDir>/keybindings.json`. */
export function createDurableKeybindings(agentDir: string): KeybindingsManager {
  return new KeybindingsManager(DURABLE_KEYBINDINGS, readUserKeybindings(join(agentDir, "keybindings.json")));
}

/** A spinner and message drawn in the editor's top border. */
export class WorkingStatusIndicator extends Loader {
  readonly kind = "working";

  constructor(ui: TUI, message: string, color: (text: string) => string) {
    super(ui, color, color, message);
  }

  renderInBorder(width: number): string {
    const line = super.render(width + 2)[1] ?? "";
    return truncateToWidth(line.startsWith(" ") ? line.slice(1).trimEnd() : line.trimEnd(), width, "");
  }

  renderSpinnerInBorder(width: number): string {
    return truncateToWidth(this.getRenderedIndicator(), width, "");
  }

  dispose(): void {
    this.stop();
  }
}

export function formatTokens(count: number): string {
  if (count < 1000) return count.toString();
  if (count < 10000) return `${(count / 1000).toFixed(1)}k`;
  if (count < 1000000) return `${Math.round(count / 1000)}k`;
  if (count < 10000000) return `${(count / 1000000).toFixed(1)}M`;
  return `${Math.round(count / 1000000)}M`;
}
