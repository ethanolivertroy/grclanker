import type { AdsSource, AdsPackagePlan, AdsPublicSite, AdsSiteArgs, BundleTemplateFile } from "./ads-model.js";
import { ADS_SITE_DIRNAME, buildAdsSiteMetadata } from "./ads-model.js";
import { buildAdsSiteSourceMetadataFile, buildAdsSiteAuthorizationDataJson, buildAdsSiteServiceInventoryJson, buildAdsQueryIndexJson, buildAdsTrustCenterMarkdown, buildAdsLlmsTxt, buildAdsLlmsFullTxt, buildAdsOpenApiYaml, buildAdsApprovalChecklist, buildAdsSiteReadme } from "./ads-data.js";
import { buildAdsOverviewPage, buildAdsServicesPage, buildAdsAccessPage, buildAdsHistoryPage, buildAds404Page, buildAdsRobotsTxt, buildAdsSitemapXml } from "./ads-pages.js";
import { buildAdsSiteCss } from "./ads-style.js";

export function renderAdsPublicSite(source: AdsSource, plan: AdsPackagePlan, args: AdsSiteArgs): AdsPublicSite {
  const metadata = buildAdsSiteMetadata(args);
  const files: BundleTemplateFile[] = [
    { path: "README.md", content: buildAdsSiteReadme(source, plan, metadata) },
    { path: "APPROVAL_REQUIRED.md", content: buildAdsApprovalChecklist(metadata) },
    { path: "_source.json", content: buildAdsSiteSourceMetadataFile(source, plan, metadata) },
    { path: "assets/site.css", content: buildAdsSiteCss() },
    { path: "index.html", content: buildAdsOverviewPage(metadata, source, plan) },
    { path: "services/index.html", content: buildAdsServicesPage(metadata, source, plan) },
    { path: "access/index.html", content: buildAdsAccessPage(metadata, source, plan) },
    { path: "history/index.html", content: buildAdsHistoryPage(metadata, source, plan) },
    { path: "404.html", content: buildAds404Page(metadata) },
    { path: "robots.txt", content: buildAdsRobotsTxt(metadata) },
    { path: "sitemap.xml", content: buildAdsSitemapXml(metadata) },
    {
      path: "authorization-data.json",
      content: buildAdsSiteAuthorizationDataJson(plan, metadata),
    },
    {
      path: "service-inventory.json",
      content: buildAdsSiteServiceInventoryJson(plan, metadata),
    },
    {
      path: "query-index.json",
      content: buildAdsQueryIndexJson(source, plan, metadata),
    },
    {
      path: "trust-center.md",
      content: buildAdsTrustCenterMarkdown(source, plan, metadata),
    },
    {
      path: "llms.txt",
      content: buildAdsLlmsTxt(metadata),
    },
    {
      path: "llms-full.txt",
      content: buildAdsLlmsFullTxt(source, plan, metadata),
    },
    {
      path: "documentation/api/api.yaml",
      content: buildAdsOpenApiYaml(metadata),
    },
  ];

  return {
    bundleName: ADS_SITE_DIRNAME,
    files,
    plan,
    metadata,
  };
}
