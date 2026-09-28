import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { registerAnsibleTools } from "./ansible.js";
import { ANSIBLE_SPEC } from "./ansible.spec.js";
import { registerAwsTools } from "./aws.js";
import { AWS_SPEC } from "./aws.spec.js";
import { registerAzureTools } from "./azure.js";
import { AZURE_SPEC } from "./azure.spec.js";
import { registerBoxTools } from "./box.js";
import { BOX_SPEC } from "./box.spec.js";
import { registerCloudflareTools } from "./cloudflare.js";
import { CLOUDFLARE_SPEC } from "./cloudflare.spec.js";
import { registerCrowdstrikeTools } from "./crowdstrike.js";
import { CROWDSTRIKE_SPEC } from "./crowdstrike.spec.js";
import { registerDatadogTools } from "./datadog.js";
import { DATADOG_SPEC } from "./datadog.spec.js";
import { registerDuoTools } from "./duo.js";
import { DUO_SPEC } from "./duo.spec.js";
import { registerElasticTools } from "./elastic.js";
import { ELASTIC_SPEC } from "./elastic.spec.js";
import { registerGcpTools } from "./gcp.js";
import { GCP_SPEC } from "./gcp.spec.js";
import { registerGwsTools } from "./gws.js";
import { GWS_SPEC } from "./gws.spec.js";
import type { IntegrationSpecContract } from "./spec-model.js";
import { registerKnowbe4Tools } from "./knowbe4.js";
import { KNOWBE4_SPEC } from "./knowbe4.spec.js";
import { registerLaunchdarklyTools } from "./launchdarkly.js";
import { LAUNCHDARKLY_SPEC } from "./launchdarkly.spec.js";
import { registerMulesoftTools } from "./mulesoft.js";
import { MULESOFT_SPEC } from "./mulesoft.spec.js";
import { registerNewrelicTools } from "./newrelic.js";
import { NEWRELIC_SPEC } from "./newrelic.spec.js";
import { registerOciTools } from "./oci.js";
import { OCI_SPEC } from "./oci.spec.js";
import { registerOktaTools } from "./okta.js";
import { OKTA_SPEC } from "./okta.spec.js";
import { registerPaloaltoTools } from "./paloalto.js";
import { PALOALTO_SPEC } from "./paloalto.spec.js";
import { registerPagerdutyTools } from "./pagerduty.js";
import { PAGERDUTY_SPEC } from "./pagerduty.spec.js";
import { registerQualysTools } from "./qualys.js";
import { QUALYS_SPEC } from "./qualys.spec.js";
import { registerSalesforceTools } from "./salesforce.js";
import { SALESFORCE_SPEC } from "./salesforce.spec.js";
import { registerServicenowTools } from "./servicenow.js";
import { SERVICENOW_SPEC } from "./servicenow.spec.js";
import { registerSlackTools } from "./slack.js";
import { SLACK_SPEC } from "./slack.spec.js";
import { registerSnowflakeTools } from "./snowflake.js";
import { SNOWFLAKE_SPEC } from "./snowflake.spec.js";
import { registerSplunkTools } from "./splunk.js";
import { SPLUNK_SPEC } from "./splunk.spec.js";
import { withIntegrationToolContracts } from "./batch-spec-builder.js";
import { registerSumologicTools } from "./sumologic.js";
import { SUMOLOGIC_SPEC } from "./sumologic.spec.js";
import { registerTenableTools } from "./tenable.js";
import { TENABLE_SPEC } from "./tenable.spec.js";
import { registerVeracodeTools } from "./veracode.js";
import { VERACODE_SPEC } from "./veracode.spec.js";
import { registerWebexTools } from "./webex.js";
import { WEBEX_SPEC } from "./webex.spec.js";
import { registerZendeskTools } from "./zendesk.js";
import { ZENDESK_SPEC } from "./zendesk.spec.js";
import { registerZoomTools } from "./zoom.js";
import { ZOOM_SPEC } from "./zoom.spec.js";
import { registerZscalerTools } from "./zscaler.js";
import { ZSCALER_SPEC } from "./zscaler.spec.js";

export interface PublishedIntegrationSpec {
  contract: IntegrationSpecContract;
  narrativePath: string;
  outputPath: string;
  registerTools: (pi: ExtensionAPI) => void;
}

export const PUBLISHED_INTEGRATION_SPECS: readonly PublishedIntegrationSpec[] = [
  {
    contract: ANSIBLE_SPEC,
    narrativePath: "specs/narratives/ansible.md",
    outputPath: "specs/ansible-aap-audit.spec.md",
    registerTools: (pi) => registerAnsibleTools(withIntegrationToolContracts(pi, ANSIBLE_SPEC)),
  },
  {
    contract: AWS_SPEC,
    narrativePath: "specs/narratives/aws.md",
    outputPath: "specs/aws-sec-inspector.spec.md",
    registerTools: registerAwsTools,
  },
  {
    contract: AZURE_SPEC,
    narrativePath: "specs/narratives/azure.md",
    outputPath: "specs/azure-sec-inspector.spec.md",
    registerTools: registerAzureTools,
  },
  {
    contract: BOX_SPEC,
    narrativePath: "specs/narratives/box.md",
    outputPath: "specs/box-sec-inspector.spec.md",
    registerTools: registerBoxTools,
  },
  {
    contract: CLOUDFLARE_SPEC,
    narrativePath: "specs/narratives/cloudflare.md",
    outputPath: "specs/cloudflare-sec-inspector.spec.md",
    registerTools: registerCloudflareTools,
  },
  {
    contract: CROWDSTRIKE_SPEC,
    narrativePath: "specs/narratives/crowdstrike.md",
    outputPath: "specs/crowdstrike-sec-inspector.spec.md",
    registerTools: registerCrowdstrikeTools,
  },
  {
    contract: DATADOG_SPEC,
    narrativePath: "specs/narratives/datadog.md",
    outputPath: "specs/datadog-sec-inspector.spec.md",
    registerTools: (pi) => registerDatadogTools(withIntegrationToolContracts(pi, DATADOG_SPEC)),
  },
  {
    contract: DUO_SPEC,
    narrativePath: "specs/narratives/duo.md",
    outputPath: "specs/duo-sec-inspector.spec.md",
    registerTools: registerDuoTools,
  },
  {
    contract: ELASTIC_SPEC,
    narrativePath: "specs/narratives/elastic.md",
    outputPath: "specs/elastic-sec-inspector.spec.md",
    registerTools: (pi) => registerElasticTools(withIntegrationToolContracts(pi, ELASTIC_SPEC)),
  },
  {
    contract: GCP_SPEC,
    narrativePath: "specs/narratives/gcp.md",
    outputPath: "specs/gcp-sec-inspector.spec.md",
    registerTools: registerGcpTools,
  },
  {
    contract: GWS_SPEC,
    narrativePath: "specs/narratives/gws.md",
    outputPath: "specs/gws-inspector-go.spec.md",
    registerTools: registerGwsTools,
  },
  {
    contract: KNOWBE4_SPEC,
    narrativePath: "specs/narratives/knowbe4.md",
    outputPath: "specs/knowbe4-sec-inspector.spec.md",
    registerTools: registerKnowbe4Tools,
  },
  {
    contract: LAUNCHDARKLY_SPEC,
    narrativePath: "specs/narratives/launchdarkly.md",
    outputPath: "specs/launchdarkly-sec-inspector.spec.md",
    registerTools: (pi) => registerLaunchdarklyTools(withIntegrationToolContracts(pi, LAUNCHDARKLY_SPEC)),
  },
  {
    contract: MULESOFT_SPEC,
    narrativePath: "specs/narratives/mulesoft.md",
    outputPath: "specs/mulesoft-sec-inspector.spec.md",
    registerTools: (pi) => registerMulesoftTools(withIntegrationToolContracts(pi, MULESOFT_SPEC)),
  },
  {
    contract: NEWRELIC_SPEC,
    narrativePath: "specs/narratives/newrelic.md",
    outputPath: "specs/newrelic-sec-inspector.spec.md",
    registerTools: (pi) => registerNewrelicTools(withIntegrationToolContracts(pi, NEWRELIC_SPEC)),
  },
  {
    contract: OCI_SPEC,
    narrativePath: "specs/narratives/oci.md",
    outputPath: "specs/oci-sec-inspector.spec.md",
    registerTools: registerOciTools,
  },
  {
    contract: OKTA_SPEC,
    narrativePath: "specs/narratives/okta.md",
    outputPath: "specs/okta-sec-inspector.spec.md",
    registerTools: registerOktaTools,
  },
  {
    contract: PALOALTO_SPEC,
    narrativePath: "specs/narratives/paloalto.md",
    outputPath: "specs/paloalto-sec-inspector.spec.md",
    registerTools: registerPaloaltoTools,
  },
  {
    contract: PAGERDUTY_SPEC,
    narrativePath: "specs/narratives/pagerduty.md",
    outputPath: "specs/pagerduty-sec-inspector.spec.md",
    registerTools: (pi) => registerPagerdutyTools(withIntegrationToolContracts(pi, PAGERDUTY_SPEC)),
  },
  {
    contract: QUALYS_SPEC,
    narrativePath: "specs/narratives/qualys.md",
    outputPath: "specs/qualys-sec-inspector.spec.md",
    registerTools: registerQualysTools,
  },
  {
    contract: SALESFORCE_SPEC,
    narrativePath: "specs/narratives/salesforce.md",
    outputPath: "specs/salesforce-sec-inspector.spec.md",
    registerTools: registerSalesforceTools,
  },
  {
    contract: SERVICENOW_SPEC,
    narrativePath: "specs/narratives/servicenow.md",
    outputPath: "specs/servicenow-sec-inspector.spec.md",
    registerTools: registerServicenowTools,
  },
  {
    contract: SLACK_SPEC,
    narrativePath: "specs/narratives/slack.md",
    outputPath: "specs/slack-sec-inspector.spec.md",
    registerTools: registerSlackTools,
  },
  {
    contract: SNOWFLAKE_SPEC,
    narrativePath: "specs/narratives/snowflake.md",
    outputPath: "specs/snowflake-sec-inspector.spec.md",
    registerTools: (pi) => registerSnowflakeTools(withIntegrationToolContracts(pi, SNOWFLAKE_SPEC)),
  },
  {
    contract: SPLUNK_SPEC,
    narrativePath: "specs/narratives/splunk.md",
    outputPath: "specs/splunk-sec-inspector.spec.md",
    registerTools: (pi) => registerSplunkTools(withIntegrationToolContracts(pi, SPLUNK_SPEC)),
  },
  {
    contract: SUMOLOGIC_SPEC,
    narrativePath: "specs/narratives/sumologic.md",
    outputPath: "specs/sumologic-sec-inspector.spec.md",
    registerTools: (pi) => registerSumologicTools(withIntegrationToolContracts(pi, SUMOLOGIC_SPEC)),
  },
  {
    contract: TENABLE_SPEC,
    narrativePath: "specs/narratives/tenable.md",
    outputPath: "specs/tenable-sec-inspector.spec.md",
    registerTools: registerTenableTools,
  },
  {
    contract: VERACODE_SPEC,
    narrativePath: "specs/narratives/veracode.md",
    outputPath: "specs/veracode-sec-inspector.spec.md",
    registerTools: registerVeracodeTools,
  },
  {
    contract: WEBEX_SPEC,
    narrativePath: "specs/narratives/webex.md",
    outputPath: "specs/webex-sec-inspector.spec.md",
    registerTools: registerWebexTools,
  },
  {
    contract: ZENDESK_SPEC,
    narrativePath: "specs/narratives/zendesk.md",
    outputPath: "specs/zendesk-sec-inspector.spec.md",
    registerTools: registerZendeskTools,
  },
  {
    contract: ZOOM_SPEC,
    narrativePath: "specs/narratives/zoom.md",
    outputPath: "specs/zoom-sec-inspector.spec.md",
    registerTools: registerZoomTools,
  },
  {
    contract: ZSCALER_SPEC,
    narrativePath: "specs/narratives/zscaler.md",
    outputPath: "specs/zscaler-sec-inspector.spec.md",
    registerTools: registerZscalerTools,
  },
];
