import type { FedrampApplicability, FedrampKsiIndicatorRecord, FedrampProcessRecord, FedrampLoadedCatalog } from "../fedramp-source.js";
import type { ArtifactPlanItem, RolloutPhase } from "./artifact-model.js";

/** Presentation consumes a completed plan and provenance, never a catalog or its loader. */
export type AdsSource = Pick<FedrampLoadedCatalog, "provenance" | "cacheStatus" | "notes">;

export type AdsPackageArgs = {
  applies_to?: FedrampApplicability | "any";
  audience?: "provider" | "trust-center" | "any";
};

export type AdsBundleArgs = {
  output_dir?: string;
  applies_to?: FedrampApplicability | "any";
  audience?: "provider" | "trust-center" | "any";
};

export type AdsSiteArgs = {
  output_dir?: string;
  applies_to?: FedrampApplicability | "any";
  audience?: "provider" | "trust-center" | "any";
  provider_name?: string;
  offering_name?: string;
  primary_domain?: string;
  support_email?: string;
};

export type AdsPackagePlan = {
  process: FedrampProcessRecord;
  linkedIndicators: FedrampKsiIndicatorRecord[];
  audience: "provider" | "trust-center" | "any";
  appliesTo: FedrampApplicability | "any";
  publicItems: ArtifactPlanItem[];
  controlledItems: ArtifactPlanItem[];
  privateItems: ArtifactPlanItem[];
  rollout: RolloutPhase[];
  text: string;
};

export type BundleTemplateFile = {
  path: string;
  content: string;
};

export type AdsStarterBundle = {
  bundleName: string;
  files: BundleTemplateFile[];
  plan: AdsPackagePlan;
};

export type AdsStarterBundleResult = {
  outputDir: string;
  files: string[];
  plan: AdsPackagePlan;
};

export type AdsSiteMetadata = {
  providerName: string;
  offeringName: string;
  primaryDomain: string;
  supportEmail: string;
  baseUrl: string;
  siteTitle: string;
  approvalStatus: "draft-unapproved";
  requiresHumanApproval: true;
};

export type AdsPublicSite = {
  bundleName: string;
  files: BundleTemplateFile[];
  plan: AdsPackagePlan;
  metadata: AdsSiteMetadata;
};

export type AdsPublicSiteResult = {
  outputDir: string;
  files: string[];
  plan: AdsPackagePlan;
  metadata: AdsSiteMetadata;
};

export const ADS_BUNDLE_DIRNAME = "ads-starter-bundle";

export const ADS_SITE_DIRNAME = "ads-public-site";

export const PUBLIC_JSON_HOSTING_NOTE =
  "Serve the public JSON files with `Content-Type: application/json` and `X-Content-Type-Options: nosniff`, and enable CORS so web applications on other domains can read them directly (FRC-CSO-JSN).";

export function findArtifactItem(plan: AdsPackagePlan, name: string): ArtifactPlanItem | undefined {
  return [
    ...plan.publicItems,
    ...plan.controlledItems,
    ...plan.privateItems,
  ].find((item) => item.name === name);
}

export function groundedIds(item: ArtifactPlanItem | undefined): string[] {
  return item?.groundedBy ?? [];
}

function normalizePrimaryDomain(value: string | undefined): string {
  const trimmed = value?.trim();
  if (!trimmed) return "trust.example.com";
  return trimmed.replace(/^https?:\/\//i, "").replace(/\/+$/, "");
}

function toBaseUrl(domain: string): string {
  return `https://${domain.replace(/^https?:\/\//i, "").replace(/\/+$/, "")}`;
}

export function buildAdsSiteMetadata(args: AdsSiteArgs): AdsSiteMetadata {
  const providerName = args.provider_name ?? "Example Provider";
  const offeringName = args.offering_name ?? "Example Cloud Service";
  const primaryDomain = normalizePrimaryDomain(args.primary_domain);
  const baseUrl = toBaseUrl(primaryDomain);

  return {
    providerName,
    offeringName,
    primaryDomain,
    supportEmail: args.support_email ?? "security@example.com",
    baseUrl,
    siteTitle: `${offeringName} Trust Center`,
    approvalStatus: "draft-unapproved",
    requiresHumanApproval: true,
  };
}
