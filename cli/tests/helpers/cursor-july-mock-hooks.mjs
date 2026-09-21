/**
 * Node module customization hooks that replace the `@cursor/july` entry
 * points with recording stubs, so the Agent SDK entry files under
 * `agent-sdk/agent/` can be loaded without the real framework or any
 * network access. Register from a test with:
 *
 *   register("./helpers/cursor-july-mock-hooks.mjs", import.meta.url);
 *
 * Every `define*` call is recorded on `globalThis.__grclankerCursorJulyMockCalls`
 * and returns the config tagged with `__agentServe` (the SDK's brand key) and
 * `__mockHelper`.
 */
const MOCK_URL_PREFIX = "grclanker-cursor-july-mock:";

const HELPERS_BY_SPECIFIER = {
  "@cursor/july": { defineAgent: "agent", defineInstructions: "instructions" },
  "@cursor/july/tools": { defineTool: "tool" },
  "@cursor/july/skills": { defineSkill: "skill" },
};

function buildMockSource(specifier) {
  const helperExports = Object.entries(HELPERS_BY_SPECIFIER[specifier])
    .map(
      ([helper, kind]) =>
        `export function ${helper}(config) { return record(${JSON.stringify(kind)}, ${JSON.stringify(helper)}, config); }`,
    )
    .join("\n");

  return [
    "const calls = (globalThis.__grclankerCursorJulyMockCalls ??= []);",
    "function record(kind, helper, config) {",
    "  const definition = { ...config, __agentServe: kind, __mockHelper: helper };",
    "  calls.push({ helper, kind, config, definition });",
    "  return definition;",
    "}",
    helperExports,
    "",
  ].join("\n");
}

export async function resolve(specifier, context, nextResolve) {
  if (Object.hasOwn(HELPERS_BY_SPECIFIER, specifier)) {
    return { url: `${MOCK_URL_PREFIX}${specifier}`, shortCircuit: true };
  }
  return nextResolve(specifier, context);
}

export async function load(url, context, nextLoad) {
  if (!url.startsWith(MOCK_URL_PREFIX)) {
    return nextLoad(url, context);
  }
  return {
    format: "module",
    shortCircuit: true,
    source: buildMockSource(url.slice(MOCK_URL_PREFIX.length)),
  };
}
