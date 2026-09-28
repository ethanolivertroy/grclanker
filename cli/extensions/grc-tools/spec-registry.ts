import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { registerAwsTools } from "./aws.js";
import { AWS_SPEC } from "./aws.spec.js";
import { registerAzureTools } from "./azure.js";
import { AZURE_SPEC } from "./azure.spec.js";
import { registerBoxTools } from "./box.js";
import { BOX_SPEC } from "./box.spec.js";
import { registerCloudflareTools } from "./cloudflare.js";
import { CLOUDFLARE_SPEC } from "./cloudflare.spec.js";
import { registerDuoTools } from "./duo.js";
import { DUO_SPEC } from "./duo.spec.js";
import { registerGcpTools } from "./gcp.js";
import { GCP_SPEC } from "./gcp.spec.js";
import { registerGwsTools } from "./gws.js";
import { GWS_SPEC } from "./gws.spec.js";
import type { IntegrationSpecContract } from "./spec-model.js";
import { registerOciTools } from "./oci.js";
import { OCI_SPEC } from "./oci.spec.js";
import { registerOktaTools } from "./okta.js";
import { OKTA_SPEC } from "./okta.spec.js";
import { registerSalesforceTools } from "./salesforce.js";
import { SALESFORCE_SPEC } from "./salesforce.spec.js";
import { registerServicenowTools } from "./servicenow.js";
import { SERVICENOW_SPEC } from "./servicenow.spec.js";
import { registerSlackTools } from "./slack.js";
import { SLACK_SPEC } from "./slack.spec.js";
import { registerWebexTools } from "./webex.js";
import { WEBEX_SPEC } from "./webex.spec.js";
import { registerZendeskTools } from "./zendesk.js";
import { ZENDESK_SPEC } from "./zendesk.spec.js";
import { registerZoomTools } from "./zoom.js";
import { ZOOM_SPEC } from "./zoom.spec.js";

export interface PublishedIntegrationSpec {
  contract: IntegrationSpecContract;
  narrativePath: string;
  outputPath: string;
  registerTools: (pi: ExtensionAPI) => void;
}

export const PUBLISHED_INTEGRATION_SPECS: readonly PublishedIntegrationSpec[] = [
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
    contract: DUO_SPEC,
    narrativePath: "specs/narratives/duo.md",
    outputPath: "specs/duo-sec-inspector.spec.md",
    registerTools: registerDuoTools,
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
];
