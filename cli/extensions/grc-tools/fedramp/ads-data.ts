import type { AdsSource, AdsPackagePlan, AdsSiteMetadata } from "./ads-model.js";
import { ADS_SITE_DIRNAME, PUBLIC_JSON_HOSTING_NOTE, findArtifactItem, groundedIds } from "./ads-model.js";

export function buildAdsSiteSourceMetadataFile(
  source: AdsSource,
  plan: AdsPackagePlan,
  metadata: AdsSiteMetadata,
): string {
  return `${JSON.stringify(
    {
      generated_by: "grclanker",
      bundle: ADS_SITE_DIRNAME,
      site: {
        title: metadata.siteTitle,
        provider_name: metadata.providerName,
        offering_name: metadata.offeringName,
        primary_domain: metadata.primaryDomain,
        base_url: metadata.baseUrl,
        support_email: metadata.supportEmail,
        approval_status: metadata.approvalStatus,
        requires_human_approval: metadata.requiresHumanApproval,
      },
      process: {
        id: plan.process.id,
        name: plan.process.name,
        short_name: plan.process.shortName,
        source_url: plan.process.sourceUrl,
      },
      applies_to: plan.appliesTo,
      audience: plan.audience,
      linked_indicators: plan.linkedIndicators.map((indicator) => ({
        id: indicator.id,
        name: indicator.name,
        reference: indicator.reference,
      })),
      public_items: plan.publicItems,
      controlled_items: plan.controlledItems,
      rollout: plan.rollout,
      publication: {
        status: metadata.approvalStatus,
        requires_human_approval: metadata.requiresHumanApproval,
        note:
          "Generated trust-center output is a draft scaffold. Review and approve the content before public hosting or indexing.",
      },
      provenance: {
        ...source.provenance,
        cache_status: source.cacheStatus,
        notes: source.notes,
      },
    },
    null,
    2,
  )}\n`;
}

export function buildAdsSiteAuthorizationDataJson(plan: AdsPackagePlan, metadata: AdsSiteMetadata): string {
  const machineReadable = findArtifactItem(plan, "Machine-readable authorization data feed");
  return `${JSON.stringify(
    {
      version: "0.1.0-draft",
      generated_by: "grclanker",
      trust_center: {
        title: metadata.siteTitle,
        provider_name: metadata.providerName,
        offering_name: metadata.offeringName,
        base_url: metadata.baseUrl,
        support_email: metadata.supportEmail,
        approval_status: metadata.approvalStatus,
        requires_human_approval: metadata.requiresHumanApproval,
      },
      fedramp: {
        process: plan.process.shortName,
        process_name: plan.process.name,
        applies_to: plan.appliesTo,
        marketplace_url: "TODO",
        public_summary_url: `${metadata.baseUrl}/`,
        machine_readable_url: `${metadata.baseUrl}/authorization-data.json`,
        service_inventory_url: `${metadata.baseUrl}/service-inventory.json`,
      },
      offering: {
        name: metadata.offeringName,
        status_summary: "TODO",
        last_updated: "TODO",
        included_services: [
          {
            name: "TODO",
            service_model: "TODO",
            included_in_scope: true,
            notes: "TODO",
          },
        ],
        customer_responsibilities: ["TODO"],
      },
      publication: {
        status: metadata.approvalStatus,
        requires_human_approval: metadata.requiresHumanApproval,
        note:
          "Draft scaffold only. A human owner must review and approve the shared information before public publication.",
      },
      grounding: {
        artifact: machineReadable?.name ?? "Machine-readable authorization data feed",
        requirement_ids: groundedIds(machineReadable),
      },
    },
    null,
    2,
  )}\n`;
}

export function buildAdsSiteServiceInventoryJson(plan: AdsPackagePlan, metadata: AdsSiteMetadata): string {
  const inventory = findArtifactItem(plan, "Service inventory and assessment-scope page");
  return `${JSON.stringify(
    {
      generated_by: "grclanker",
      trust_center: metadata.siteTitle,
      process: plan.process.shortName,
      offering_name: metadata.offeringName,
      services: [
        {
          name: "TODO",
          marketing_name: "TODO",
          service_model: "TODO",
          included_in_scope: true,
          notes: "TODO",
        },
      ],
      shared_responsibility_summary: "TODO",
      boundary_notes: "TODO",
      publication: {
        status: metadata.approvalStatus,
        requires_human_approval: metadata.requiresHumanApproval,
        note:
          "Draft scaffold only. A human owner must review and approve the shared information before public publication.",
      },
      grounding: {
        artifact: inventory?.name ?? "Service inventory and assessment-scope page",
        requirement_ids: groundedIds(inventory),
      },
    },
    null,
    2,
  )}\n`;
}

export function buildAdsQueryIndexJson(
  source: AdsSource,
  plan: AdsPackagePlan,
  metadata: AdsSiteMetadata,
): string {
  return `${JSON.stringify(
    {
      generated_by: "grclanker",
      title: `${metadata.siteTitle} public resource index`,
      summary:
        "Machine-readable index of the public trust-center resources intentionally exposed for broad retrieval.",
      base_url: metadata.baseUrl,
      support_email: metadata.supportEmail,
      publication: {
        status: metadata.approvalStatus,
        requires_human_approval: metadata.requiresHumanApproval,
        note:
          "This index describes a draft public trust-center scaffold. Human approval is required before the represented content should be treated as final public disclosure.",
      },
      process: {
        id: plan.process.id,
        short_name: plan.process.shortName,
        name: plan.process.name,
        applies_to: plan.appliesTo,
      },
      resources: [
        {
          id: "overview-html",
          path: "/",
          url: `${metadata.baseUrl}/`,
          content_type: "text/html",
          query_intent: "Human-readable public trust-center summary.",
        },
        {
          id: "services-html",
          path: "/services/",
          url: `${metadata.baseUrl}/services/`,
          content_type: "text/html",
          query_intent: "Human-readable service inventory and scope summary.",
        },
        {
          id: "access-html",
          path: "/access/",
          url: `${metadata.baseUrl}/access/`,
          content_type: "text/html",
          query_intent: "Public access guidance and controlled retrieval explanation.",
        },
        {
          id: "history-html",
          path: "/history/",
          url: `${metadata.baseUrl}/history/`,
          content_type: "text/html",
          query_intent: "Public version history and update policy.",
        },
        {
          id: "authorization-data-json",
          path: "/authorization-data.json",
          url: `${metadata.baseUrl}/authorization-data.json`,
          content_type: "application/json",
          query_intent: "Machine-readable public authorization summary and trust-center metadata.",
        },
        {
          id: "service-inventory-json",
          path: "/service-inventory.json",
          url: `${metadata.baseUrl}/service-inventory.json`,
          content_type: "application/json",
          query_intent: "Machine-readable public service inventory and scope data.",
        },
        {
          id: "query-index-json",
          path: "/query-index.json",
          url: `${metadata.baseUrl}/query-index.json`,
          content_type: "application/json",
          query_intent: "Index of all public, shareable resources exposed by this trust center.",
        },
        {
          id: "openapi-yaml",
          path: "/documentation/api/api.yaml",
          url: `${metadata.baseUrl}/documentation/api/api.yaml`,
          content_type: "application/yaml",
          query_intent: "OpenAPI contract for the public trust-center GET surface.",
        },
        {
          id: "trust-center-markdown",
          path: "/trust-center.md",
          url: `${metadata.baseUrl}/trust-center.md`,
          content_type: "text/markdown",
          query_intent: "Markdown trust-center documentation for agent or script consumption.",
        },
        {
          id: "llms-txt",
          path: "/llms.txt",
          url: `${metadata.baseUrl}/llms.txt`,
          content_type: "text/plain",
          query_intent: "Agent-friendly discovery index for public trust-center resources.",
        },
        {
          id: "llms-full-txt",
          path: "/llms-full.txt",
          url: `${metadata.baseUrl}/llms-full.txt`,
          content_type: "text/plain",
          query_intent: "Full text bundle of public trust-center documentation and endpoints.",
        },
      ],
      share_boundary: {
        public_only: true,
        controlled_access_included: false,
        private_operational_material_included: false,
        note:
          "Only broadly shareable trust-center information is represented here. Controlled and private authorization materials should be exposed through separate, non-public workflows.",
      },
      provenance: {
        version: source.provenance.version,
        source_repo: source.provenance.repo,
        source_path: source.provenance.path,
        source_branch: source.provenance.branch,
        source_blob_sha: source.provenance.blobSha,
        upstream_last_updated: source.provenance.upstreamLastUpdated,
        cache_status: source.cacheStatus,
      },
    },
    null,
    2,
  )}\n`;
}

export function buildAdsTrustCenterMarkdown(
  source: AdsSource,
  plan: AdsPackagePlan,
  metadata: AdsSiteMetadata,
): string {
  const publicItems = plan.publicItems.map((item) => `- **${item.name}**: ${item.rationale}`).join("\n");
  const controlledItems = plan.controlledItems.map((item) => `- **${item.name}**: ${item.rationale}`).join("\n");
  return `# ${metadata.siteTitle}

> Draft public trust-center surface for ${metadata.offeringName}. This markdown file is intended for agents, scripts, and organizations that want the shareable facts without parsing the HTML site.

This trust center exposes only the public layer of the provider's Certification Data Sharing posture. Controlled-access and private operational materials are intentionally excluded from this file and from the public host.

## Approval status

- Status: draft-unapproved
- Human approval required before publication: yes

## Public resources

- [Overview](${metadata.baseUrl}/): Human-readable public trust-center summary.
- [Services](${metadata.baseUrl}/services/): Human-readable service inventory and scope summary.
- [Access](${metadata.baseUrl}/access/): Public explanation of what is openly published versus controlled retrieval.
- [History](${metadata.baseUrl}/history/): Public version history and update policy.
- [authorization-data.json](${metadata.baseUrl}/authorization-data.json): Machine-readable public authorization summary.
- [service-inventory.json](${metadata.baseUrl}/service-inventory.json): Machine-readable public service inventory and scope data.
- [query-index.json](${metadata.baseUrl}/query-index.json): Machine-readable index of all public resources.
- [documentation/api/api.yaml](${metadata.baseUrl}/documentation/api/api.yaml): OpenAPI contract for the public trust-center GET surface.

## Publicly shareable artifact categories

${publicItems || "- TODO: replace with actual public artifact descriptions."}

## Controlled-access categories not published here

${controlledItems || "- TODO: document controlled-access artifact classes outside the public host."}

## Query guidance

- Treat \`query-index.json\` as the public index of the trust center's shareable machine-readable resources.
- Use \`documentation/api/api.yaml\` when an organization or tool wants a formal API contract for the public GET surface.
- Use \`authorization-data.json\` for public posture metadata and \`service-inventory.json\` for service/scope data.
- Use \`llms.txt\` for quick discovery and \`llms-full.txt\` for a full text bundle.
- Do not assume controlled or private authorization data exists on this public host.

## Provenance

- Source repo: ${source.provenance.repo}
- Source path: ${source.provenance.path}
- Source branch: ${source.provenance.branch}
- Source blob SHA: ${source.provenance.blobSha ?? "Unavailable"}
- Consolidated Rules version: ${source.provenance.version}
- Upstream last updated: ${source.provenance.upstreamLastUpdated}
- Cache status during generation: ${source.cacheStatus}
`;
}

export function buildAdsLlmsTxt(metadata: AdsSiteMetadata): string {
  return `# ${metadata.siteTitle}

> Draft public trust-center resources for ${metadata.offeringName}, including human-readable pages and machine-readable JSON endpoints that organizations can query safely after human approval.

This site exposes only the information the provider is willing to share publicly. Controlled-access and private authorization materials are intentionally excluded from the public host.
Human approval is required before these draft resources should be treated as final public disclosures.

## Public trust center

- [Overview](${metadata.baseUrl}/): Human-readable trust-center summary and public artifact overview.
- [Services](${metadata.baseUrl}/services/): Human-readable service inventory and scope summary.
- [Access](${metadata.baseUrl}/access/): Public access guidance and controlled retrieval explanation.
- [History](${metadata.baseUrl}/history/): Public version history and update policy.

## Machine-readable resources

- [authorization-data.json](${metadata.baseUrl}/authorization-data.json): Public authorization summary in JSON form.
- [service-inventory.json](${metadata.baseUrl}/service-inventory.json): Public service inventory and scope data in JSON form.
- [query-index.json](${metadata.baseUrl}/query-index.json): Index of all public, queryable resources.
- [documentation/api/api.yaml](${metadata.baseUrl}/documentation/api/api.yaml): OpenAPI description of the public GET endpoints.

## Agent-friendly documentation

- [trust-center.md](${metadata.baseUrl}/trust-center.md): Markdown trust-center documentation for agent or script consumption.
- [llms-full.txt](${metadata.baseUrl}/llms-full.txt): Full text bundle of the public trust-center documentation and resources.
`;
}

export function buildAdsLlmsFullTxt(
  source: AdsSource,
  plan: AdsPackagePlan,
  metadata: AdsSiteMetadata,
): string {
  const publicItemText = plan.publicItems
    .map((item) => `- ${item.name} [${item.format}] — ${item.rationale} Grounded by: ${item.groundedBy.join(", ") || "linked official text"}.`)
    .join("\n");
  const controlledItemText = plan.controlledItems
    .map((item) => `- ${item.name} [${item.format}] — ${item.rationale} Grounded by: ${item.groundedBy.join(", ") || "linked official text"}.`)
    .join("\n");
  return `# ${metadata.siteTitle}

> Draft public trust-center surface for ${metadata.offeringName}. This file bundles the public documentation and machine-readable resource map into one text response for agents and automation.

## Public trust center summary

- Provider: ${metadata.providerName}
- Offering: ${metadata.offeringName}
- Base URL: ${metadata.baseUrl}
- Support email: ${metadata.supportEmail}
- Official process: ${plan.process.name} [${plan.process.shortName}]
- Applies to: ${plan.appliesTo}
- Approval status: ${metadata.approvalStatus}
- Human approval required before publication: yes

## Public resources

- \`GET ${metadata.baseUrl}/\` — Overview HTML page
- \`GET ${metadata.baseUrl}/services/\` — Services and scope HTML page
- \`GET ${metadata.baseUrl}/access/\` — Access guidance HTML page
- \`GET ${metadata.baseUrl}/history/\` — History HTML page
- \`GET ${metadata.baseUrl}/authorization-data.json\` — Machine-readable public authorization data
- \`GET ${metadata.baseUrl}/service-inventory.json\` — Machine-readable public service inventory
- \`GET ${metadata.baseUrl}/query-index.json\` — Machine-readable public resource index
- \`GET ${metadata.baseUrl}/documentation/api/api.yaml\` — OpenAPI contract for the public trust-center surface
- \`GET ${metadata.baseUrl}/trust-center.md\` — Markdown trust-center documentation
- \`GET ${metadata.baseUrl}/llms.txt\` — Discovery index
- \`GET ${metadata.baseUrl}/llms-full.txt\` — Full text bundle

## Public artifact categories

${publicItemText || "- TODO: replace with actual public artifact descriptions."}

## Controlled-access categories not exposed on the public host

${controlledItemText || "- TODO: document controlled-access categories elsewhere."}

## Query policy

- Only the resources listed above should be assumed public and broadly retrievable.
- \`query-index.json\` is the canonical machine-readable index of publicly shareable resources.
- \`authorization-data.json\` and \`service-inventory.json\` are the preferred structured endpoints for scripts and organizations that need machine-readable data.
- Controlled-access and private operational materials should be requested through non-public workflows and must not be inferred to exist on this public host.

## Provenance

- Source repo: ${source.provenance.repo}
- Source path: ${source.provenance.path}
- Source branch: ${source.provenance.branch}
- Source blob SHA: ${source.provenance.blobSha ?? "Unavailable"}
- Consolidated Rules version: ${source.provenance.version}
- Upstream last updated: ${source.provenance.upstreamLastUpdated}
- Cache status during generation: ${source.cacheStatus}
`;
}

export function buildAdsOpenApiYaml(metadata: AdsSiteMetadata): string {
  return `openapi: 3.0.3
info:
  title: ${metadata.siteTitle} API
  version: 0.1.0
  description: >
    Draft, public, read-only trust-center contract for the information the provider is willing to share broadly.
    This API description covers only static GET resources exposed by the public host and requires human approval before publication.
servers:
  - url: ${metadata.baseUrl}
paths:
  /authorization-data.json:
    get:
      summary: Get public authorization data summary
      operationId: getAuthorizationData
      responses:
        '200':
          description: Public authorization summary
          content:
            application/json:
              schema:
                type: object
  /service-inventory.json:
    get:
      summary: Get public service inventory and scope data
      operationId: getServiceInventory
      responses:
        '200':
          description: Public service inventory and scope data
          content:
            application/json:
              schema:
                type: object
  /query-index.json:
    get:
      summary: Get public resource index
      operationId: getQueryIndex
      responses:
        '200':
          description: Machine-readable index of public trust-center resources
          content:
            application/json:
              schema:
                type: object
  /trust-center.md:
    get:
      summary: Get markdown trust-center documentation
      operationId: getTrustCenterMarkdown
      responses:
        '200':
          description: Markdown trust-center documentation
          content:
            text/markdown:
              schema:
                type: string
  /llms.txt:
    get:
      summary: Get agent-friendly discovery index
      operationId: getLlmsIndex
      responses:
        '200':
          description: Agent-friendly discovery index for public resources
          content:
            text/plain:
              schema:
                type: string
  /llms-full.txt:
    get:
      summary: Get full text trust-center bundle
      operationId: getLlmsFull
      responses:
        '200':
          description: Full text bundle of public trust-center documentation and endpoints
          content:
            text/plain:
              schema:
                type: string
`;
}

export function buildAdsApprovalChecklist(metadata: AdsSiteMetadata): string {
  return `# Approval Required Before Publication

This generated trust-center bundle is a draft scaffold. Do not publish it to a public domain until a human owner reviews and approves the content.

## Required review checks

- Confirm the provider name, offering name, domain, and support contact are correct.
- Review every TODO field in the HTML, markdown, JSON, and YAML files.
- Confirm that no controlled-access or private operational information leaked into the public files.
- Confirm the organization is actually willing to publish each JSON field and page section.
- Confirm the public query surface is limited to the files intentionally exposed:
  - \`authorization-data.json\`
  - \`service-inventory.json\`
  - \`query-index.json\`
  - \`trust-center.md\`
  - \`llms.txt\`
  - \`llms-full.txt\`
  - \`documentation/api/api.yaml\`
- Confirm the host serves the public JSON files with \`Content-Type: application/json\` and \`X-Content-Type-Options: nosniff\`, and allows cross-origin (CORS) reads (FRC-CSO-JSN).
- Confirm the trust-center summary, access guidance, and version history match the latest approved public posture.
- Only after approval: remove draft/noindex warnings, update \`robots.txt\`, and publish to the customer-owned host.

## Approval record

- Reviewer: TODO
- Approval date: TODO
- Approval scope: TODO
- Notes: TODO

If approval is still pending, keep this bundle private and unhosted.
`;
}

export function buildAdsSiteReadme(
  source: AdsSource,
  plan: AdsPackagePlan,
  metadata: AdsSiteMetadata,
): string {
  const lines = [
    `# ${metadata.siteTitle}`,
    "",
    "This directory is a portable, public-only ADS trust-center scaffold generated by grclanker.",
    "",
    "Draft status:",
    "- Approval status: draft-unapproved",
    "- Human approval required before publication: yes",
    "- Default indexing posture: blocked until a human explicitly reviews and flips it",
    "",
    "What is included:",
    "- Static HTML pages for the trust-center summary, services, access guidance, and version history.",
    "- Public machine-readable files: `authorization-data.json` and `service-inventory.json`.",
    "- Agent-friendly discovery and docs files: `llms.txt`, `llms-full.txt`, `trust-center.md`, and `query-index.json`.",
    "- An OpenAPI description for the public GET surface at `documentation/api/api.yaml`.",
    "- Shared CSS, `robots.txt`, `sitemap.xml`, and provenance metadata in `_source.json`.",
    "",
    "What is intentionally excluded:",
    "- Controlled-access authorization data.",
    "- Private operating runbooks, logging, routing, or validation records.",
    "- Any backend or cloud-specific runtime.",
    "",
    "Use `fedramp_generate_ads_bundle` if you also need the internal controlled/private scaffolding.",
    "",
    `Provider name: ${metadata.providerName}`,
    `Offering name: ${metadata.offeringName}`,
    `Primary domain: ${metadata.primaryDomain}`,
    `Support email: ${metadata.supportEmail}`,
    `Official process: ${plan.process.name} [${plan.process.shortName}]`,
    `Consolidated Rules version: ${source.provenance.version}`,
    "",
    "Suggested deployment targets:",
    "- AWS: upload the generated files to S3, front them with CloudFront, and attach your customer-owned ACM certificate.",
    "- Azure: upload the generated files to Azure Storage Static Website, then front them with Front Door or Azure CDN.",
    "- GCP: upload the generated files to Cloud Storage and front them with an HTTPS load balancer or CDN.",
    "",
    "Deployment notes:",
    "- This output is static by design. No application server is required.",
    "- Keep the generated file paths intact so the relative links and `sitemap.xml` remain valid.",
    `- ${PUBLIC_JSON_HOSTING_NOTE}`,
    "- Replace all TODO fields before publishing to a public domain.",
    "- Review and approve every public statement, endpoint, and JSON field before hosting the site publicly.",
    "- Remove the draft banner, noindex meta tag, and `Disallow: /` robots posture only after that approval step is complete.",
    "- Review `_source.json` and keep it if you want provenance for internal traceability.",
    "",
    "Public files:",
    "- `index.html`",
    "- `services/index.html`",
    "- `access/index.html`",
    "- `history/index.html`",
    "- `authorization-data.json`",
    "- `service-inventory.json`",
    "- `query-index.json`",
    "- `documentation/api/api.yaml`",
    "- `trust-center.md`",
    "- `llms.txt`",
    "- `llms-full.txt`",
    "- `assets/site.css`",
    "",
    "Grounding:",
    `- Source repo: ${source.provenance.repo}`,
    `- Source path: ${source.provenance.path}`,
    `- Source branch: ${source.provenance.branch}`,
    `- Source blob SHA: ${source.provenance.blobSha ?? "Unavailable"}`,
    `- Upstream last updated: ${source.provenance.upstreamLastUpdated}`,
    `- Cache status during generation: ${source.cacheStatus}`,
  ];

  return `${lines.join("\n")}\n`;
}
