import type { Static, TSchema } from "typebox";

export type GrcToolContent =
  | { type: "text"; text: string }
  | { type: "image"; data: string; mimeType: string };

export interface GrcToolResult<Details = unknown> {
  content: GrcToolContent[];
  details?: Details;
  isError?: boolean;
  terminate?: boolean;
}

/** Native tools declare GRC capabilities; an agent host adapts this contract. */
export interface GrcToolDefinition<Parameters extends TSchema = TSchema, Details = unknown> {
  name: string;
  label: string;
  description: string;
  parameters: Parameters;
  prepareArguments?: (input: unknown) => unknown;
  execute(toolCallId: string, args: Static<Parameters>, signal?: AbortSignal): Promise<GrcToolResult<Details>>;
}

/** The complete registration surface available to a native integration. */
export interface GrcToolRegistrar {
  registerTool<Parameters extends TSchema = TSchema, Details = unknown>(
    tool: GrcToolDefinition<Parameters, Details>,
  ): void;
}
