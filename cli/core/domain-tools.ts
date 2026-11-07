/** Shared domain registration. Agent hosts add their own compute tools and lifecycle hooks. */
import type { ExtensionAPI, ToolDefinition } from "@earendil-works/pi-coding-agent";
import { runToolCall, type ToolCallState } from "../extensions/grc-tools/abort.js";
import { registerAnsibleTools } from "../extensions/grc-tools/ansible.js";
import { registerAwsTools } from "../extensions/grc-tools/aws.js";
import { registerAzureTools } from "../extensions/grc-tools/azure.js";
import { registerBoxTools } from "../extensions/grc-tools/box.js";
import { registerCloudflareTools } from "../extensions/grc-tools/cloudflare.js";
import { registerCmvpTools } from "../extensions/grc-tools/cmvp.js";
import { registerCrowdstrikeTools } from "../extensions/grc-tools/crowdstrike.js";
import { registerDatadogTools } from "../extensions/grc-tools/datadog.js";
import { registerDuoTools } from "../extensions/grc-tools/duo.js";
import { registerElasticTools } from "../extensions/grc-tools/elastic.js";
import { registerFedrampTools } from "../extensions/grc-tools/fedramp.js";
import { registerGitHubTools } from "../extensions/grc-tools/github.js";
import { registerGcpTools } from "../extensions/grc-tools/gcp.js";
import { registerGwsTools } from "../extensions/grc-tools/gws.js";
import { registerGwsOperatorTools } from "../extensions/grc-tools/gws-ops.js";
import { registerKevsTools } from "../extensions/grc-tools/kevs.js";
import { registerKnowbe4Tools } from "../extensions/grc-tools/knowbe4.js";
import { registerLaunchdarklyTools } from "../extensions/grc-tools/launchdarkly.js";
import { registerMulesoftTools } from "../extensions/grc-tools/mulesoft.js";
import { registerNewrelicTools } from "../extensions/grc-tools/newrelic.js";
import { registerOktaTools } from "../extensions/grc-tools/okta.js";
import { registerOciTools } from "../extensions/grc-tools/oci.js";
import { registerOscalTools } from "../extensions/grc-tools/oscal.js";
import { registerPagerdutyTools } from "../extensions/grc-tools/pagerduty.js";
import { registerPaloaltoTools } from "../extensions/grc-tools/paloalto.js";
import { registerQualysTools } from "../extensions/grc-tools/qualys.js";
import { registerSalesforceTools } from "../extensions/grc-tools/salesforce.js";
import { registerScfTools } from "../extensions/grc-tools/scf.js";
import { registerServicenowTools } from "../extensions/grc-tools/servicenow.js";
import { registerSlackTools } from "../extensions/grc-tools/slack.js";
import { registerSnowflakeTools } from "../extensions/grc-tools/snowflake.js";
import { registerSplunkTools } from "../extensions/grc-tools/splunk.js";
import { registerSumologicTools } from "../extensions/grc-tools/sumologic.js";
import { registerTenableTools } from "../extensions/grc-tools/tenable.js";
import { registerVantaTools } from "../extensions/grc-tools/vanta.js";
import { registerVeracodeTools } from "../extensions/grc-tools/veracode.js";
import { registerWebexTools } from "../extensions/grc-tools/webex.js";
import { registerZendeskTools } from "../extensions/grc-tools/zendesk.js";
import { registerZoomTools } from "../extensions/grc-tools/zoom.js";
import { registerZscalerTools } from "../extensions/grc-tools/zscaler.js";

/**
 * Domain tool registrars, kept alphabetical by integration. Add a new
 * integration by importing its `registerXxxTools` above and inserting it here
 * in alphabetical order; the domain tool count is derived from this list.
 */
const DOMAIN_TOOL_REGISTRARS: ReadonlyArray<(pi: ExtensionAPI) => void> = [
  registerAnsibleTools,
  registerAwsTools,
  registerAzureTools,
  registerBoxTools,
  registerCloudflareTools,
  registerCmvpTools,
  registerCrowdstrikeTools,
  registerDatadogTools,
  registerDuoTools,
  registerElasticTools,
  registerFedrampTools,
  registerGcpTools,
  registerGitHubTools,
  registerGwsOperatorTools,
  registerGwsTools,
  registerKevsTools,
  registerKnowbe4Tools,
  registerLaunchdarklyTools,
  registerMulesoftTools,
  registerNewrelicTools,
  registerOciTools,
  registerOktaTools,
  registerOscalTools,
  registerPagerdutyTools,
  registerPaloaltoTools,
  registerQualysTools,
  registerSalesforceTools,
  registerScfTools,
  registerServicenowTools,
  registerSlackTools,
  registerSnowflakeTools,
  registerSplunkTools,
  registerSumologicTools,
  registerTenableTools,
  registerVantaTools,
  registerVeracodeTools,
  registerWebexTools,
  registerZendeskTools,
  registerZoomTools,
  registerZscalerTools,
];

/**
 * Domain tools pass their abort signal into their API collection, and a
 * collector that tolerates per-dataset failures can still finish after an
 * abort with every dataset failed. So a call aborted before it starts never
 * runs, and a call whose signal aborts while it runs rejects with the abort
 * reason instead of returning that result. The exception is a call that
 * committed its output before it returned: the output exists either way, so
 * the call reports where it is.
 */
function rejectAbortedCalls(tool: ToolDefinition): ToolDefinition {
  return {
    ...tool,
    async execute(toolCallId, params, signal, onUpdate, ctx) {
      signal?.throwIfAborted();
      const call: ToolCallState = { committed: false };
      let result: Awaited<ReturnType<ToolDefinition["execute"]>>;
      try {
        result = await runToolCall(call, () => tool.execute(toolCallId, params, signal, onUpdate, ctx));
      } catch (error) {
        signal?.throwIfAborted();
        throw error;
      }
      if (!call.committed) signal?.throwIfAborted();
      return result;
    },
  };
}

const LEGACY_TYPEBOX_KIND = Symbol.for("TypeBox.Kind");

/**
 * Pi's tool argument validation coerces mistyped arguments ("7" to 7, 1.5 to
 * 1, 42 to "42") unless the parameter schema is plain JSON Schema, without
 * typebox's non-enumerable `~kind` markers, and carries the
 * `Symbol.for("TypeBox.Kind")` marker of @sinclair/typebox 0.34 schemas.
 * Domain tools reject mistyped arguments that their `prepareArguments` shim
 * leaves in place, so they register their parameters in that form.
 */
export function disableArgumentCoercion(tool: ToolDefinition): ToolDefinition {
  const parameters = JSON.parse(JSON.stringify(tool.parameters)) as ToolDefinition["parameters"];
  return { ...tool, parameters: Object.assign(parameters, { [LEGACY_TYPEBOX_KIND]: "Object" }) };
}

export function registerDomainTools(pi: Pick<ExtensionAPI, "registerTool">): number {
  let count = 0;
  const counting = new Proxy(pi, {
    get(target, property) {
      if (property === "registerTool") {
        return (tool: ToolDefinition) => {
          count += 1;
          return target.registerTool(rejectAbortedCalls(disableArgumentCoercion(tool)));
        };
      }
      const value = Reflect.get(target, property, target) as unknown;
      return typeof value === "function" ? value.bind(target) : value;
    },
  });

  for (const register of DOMAIN_TOOL_REGISTRARS) {
    register(counting as ExtensionAPI);
  }
  return count;
}

/** Collect domain tools directly, without initializing an agent host or compute backend. */
export function collectDomainToolDefinitions(): ToolDefinition[] {
  const tools: ToolDefinition[] = [];
  const registerTool: ExtensionAPI["registerTool"] = (tool) => {
    // Collection erases each tool's parameter/render generic types; it never
    // calls the renderers that make the host's registerTool signature invariant.
    tools.push(tool as unknown as ToolDefinition);
  };
  registerDomainTools({ registerTool });
  return tools;
}
