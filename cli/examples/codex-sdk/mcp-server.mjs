import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { executeRegisteredGrcTool } from "../../dist/runtime/tools.js";
import { toJsonSchema } from "../../dist/runtime/schema.js";
import { selectTools } from "./tools.mjs";

const tools = selectTools(process.argv.length > 2 ? process.argv.slice(2) : undefined);
const allowedNames = new Set(tools.map((tool) => tool.name));
const server = new Server(
  { name: "grclanker", version: "0.1.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: tools.map((tool) => ({
    name: tool.name,
    description: tool.description,
    inputSchema: toJsonSchema(tool.parameters),
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
  })),
}));

server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
  const { name, arguments: input = {} } = request.params;
  if (!allowedNames.has(name)) {
    return { content: [{ type: "text", text: "Tool is not enabled in this Codex deployment." }], isError: true };
  }
  const result = await executeRegisteredGrcTool(name, input, { signal: extra.signal });
  return { ...result };
});

await server.connect(new StdioServerTransport());
