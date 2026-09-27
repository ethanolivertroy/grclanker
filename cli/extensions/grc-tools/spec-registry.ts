import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { registerAwsTools } from "./aws.js";
import { AWS_SPEC } from "./aws.spec.js";
import type { IntegrationSpecContract } from "./spec-model.js";
import { registerWebexTools } from "./webex.js";
import { WEBEX_SPEC } from "./webex.spec.js";

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
    contract: WEBEX_SPEC,
    narrativePath: "specs/narratives/webex.md",
    outputPath: "specs/webex-sec-inspector.spec.md",
    registerTools: registerWebexTools,
  },
];
