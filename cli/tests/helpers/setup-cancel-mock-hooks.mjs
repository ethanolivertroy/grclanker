import { load as loadPiMock, resolve as resolvePiMock } from "./pi-launch-mock-hooks.mjs";

const PROMPTS_URL = "grclanker-setup-cancel-mock:prompts";
const PROMPTS_SOURCE = [
  'const cancelled = Symbol("cancelled");',
  "export const isCancel = (value) => value === cancelled;",
  "export const select = async (options) => {",
  '  if (process.env.GRCLANKER_TEST_SETUP_MODE !== "anthropic") return cancelled;',
  '  if (options.message === "Choose model mode") return "hosted";',
  '  if (options.message === "Hosted provider") return "anthropic";',
  '  if (options.message.startsWith("Configure advanced compute")) return false;',
  "  return options.initialValue;",
  "};",
  "export const autocomplete = select;",
  "export const confirm = select;",
  "export const text = select;",
  "export const intro = () => {};",
  "export const outro = () => {};",
  "export const cancel = (message) => console.log(message);",
].join("\n");

export async function resolve(specifier, context, nextResolve) {
  if (specifier === "@clack/prompts" && context.parentURL?.endsWith("/dist/pi/setup.js")) {
    return { url: PROMPTS_URL, shortCircuit: true };
  }
  return resolvePiMock(specifier, context, nextResolve);
}

export async function load(url, context, nextLoad) {
  if (url === PROMPTS_URL) {
    return { format: "module", shortCircuit: true, source: PROMPTS_SOURCE };
  }
  return loadPiMock(url, context, nextLoad);
}
