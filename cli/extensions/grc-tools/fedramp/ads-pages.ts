import type { AdsSource, AdsPackagePlan, AdsSiteMetadata } from "./ads-model.js";
import type { ArtifactPlanItem } from "./artifact-model.js";
import { formatProvenanceNote } from "./provenance.js";

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function pageHref(prefix: string, path: string): string {
  return `${prefix}${path}`;
}

function navLink(prefix: string, href: string, label: string, active: boolean): string {
  return `<a href="${escapeHtml(pageHref(prefix, href))}" class="site-nav-link${active ? " is-active" : ""}">${escapeHtml(label)}</a>`;
}

function renderArtifactList(items: ArtifactPlanItem[]): string {
  if (items.length === 0) {
    return "<p class=\"empty-copy\">No public-facing items were inferred from the current official source text for this scope.</p>";
  }

  return `<ul class="artifact-list">${items
    .map(
      (item) =>
        `<li><h3>${escapeHtml(item.name)}</h3><p>${escapeHtml(item.rationale)}</p><p class="artifact-meta">${escapeHtml(item.format)} · Grounded by ${escapeHtml(item.groundedBy.join(", ") || "linked official text")}</p></li>`,
    )
    .join("")}</ul>`;
}

function renderRolloutSummary(plan: AdsPackagePlan): string {
  const relevantPhases = plan.rollout.filter((phase) =>
    phase.items.some((name) =>
      plan.publicItems.some((item) => item.name === name) ||
      plan.controlledItems.some((item) => item.name === name),
    ),
  );

  return `<ol class="rollout-list">${relevantPhases
    .map((phase) => {
      const visibleItems = phase.items.filter((name) =>
        plan.publicItems.some((item) => item.name === name) ||
        plan.controlledItems.some((item) => item.name === name),
      );
      return `<li><h3>${escapeHtml(phase.title)}</h3><p>${escapeHtml(phase.objective)}</p><ul>${visibleItems
        .map((item) => `<li>${escapeHtml(item)}</li>`)
        .join("")}</ul></li>`;
    })
    .join("")}</ol>`;
}

function buildAdsSiteDocument(
  metadata: AdsSiteMetadata,
  source: AdsSource,
  plan: AdsPackagePlan,
  options: {
    title: string;
    description: string;
    prefix: string;
    current: "home" | "services" | "access" | "history";
    main: string;
  },
): string {
  const nav = [
    navLink(options.prefix, "", "Overview", options.current === "home"),
    navLink(options.prefix, "services/", "Services", options.current === "services"),
    navLink(options.prefix, "access/", "Access", options.current === "access"),
    navLink(options.prefix, "history/", "History", options.current === "history"),
  ].join("");
  const sourceNote = formatProvenanceNote({
    repo: source.provenance.repo,
    path: source.provenance.path,
    branch: source.provenance.branch,
    blobSha: source.provenance.blobSha,
    version: source.provenance.version,
    upstreamLastUpdated: source.provenance.upstreamLastUpdated,
    cacheStatus: source.cacheStatus,
  });

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${escapeHtml(options.title)} · ${escapeHtml(metadata.siteTitle)}</title>
    <meta name="description" content="${escapeHtml(options.description)}" />
    <meta name="robots" content="noindex,nofollow,noarchive" />
    <link rel="stylesheet" href="${escapeHtml(pageHref(options.prefix, "assets/site.css"))}" />
  </head>
  <body>
    <div class="site-shell">
      <header class="topbar">
        <div class="brand-row">
          <div class="brand-meta">
            <span class="eyebrow">Certification Data Sharing // Public Trust Center</span>
            <h1 class="brand-title">${escapeHtml(metadata.siteTitle)}</h1>
            <p class="brand-copy">A portable public trust-center scaffold grounded in the official FedRAMP GitHub Consolidated Rules source. Replace the TODO fields with your customer-facing service posture, scope, and access narrative.</p>
          </div>
          <div class="meta-strip">
            <span class="meta-pill">Draft · Human approval required</span>
            <span class="meta-pill">Provider · ${escapeHtml(metadata.providerName)}</span>
            <span class="meta-pill">Offering · ${escapeHtml(metadata.offeringName)}</span>
            <span class="meta-pill">Applies to · ${escapeHtml(plan.appliesTo.toUpperCase())}</span>
          </div>
        </div>
        <nav class="site-nav" aria-label="Trust center navigation">${nav}</nav>
      </header>
      <section class="panel">
        <span class="section-kicker">Approval gate</span>
        <h2 class="section-title">Draft scaffold. Review before publication.</h2>
        <p class="section-copy">This generated trust-center site is intentionally marked draft-unapproved. A human owner should verify every public statement, endpoint, and file before hosting it on a public domain or removing the noindex posture.</p>
      </section>
      ${options.main}
      <footer class="footer-panel">
        <p class="footer-copy">This site only covers the public layer. Controlled-access and private operational materials should stay outside the public host and can be scaffolded separately with grclanker's ADS bundle generator. The generated output is draft-only until a human approves it for publication.</p>
        <div class="footer-links">
          <a href="${escapeHtml(pageHref(options.prefix, "authorization-data.json"))}">authorization-data.json</a>
          <a href="${escapeHtml(pageHref(options.prefix, "service-inventory.json"))}">service-inventory.json</a>
          <a href="${escapeHtml(pageHref(options.prefix, "query-index.json"))}">query-index.json</a>
          <a href="${escapeHtml(pageHref(options.prefix, "documentation/api/api.yaml"))}">api.yaml</a>
          <a href="${escapeHtml(pageHref(options.prefix, "llms.txt"))}">llms.txt</a>
          <a href="${escapeHtml(pageHref(options.prefix, "_source.json"))}">_source.json</a>
          <a href="mailto:${escapeHtml(metadata.supportEmail)}">${escapeHtml(metadata.supportEmail)}</a>
        </div>
        <p class="provenance">${escapeHtml(sourceNote)}</p>
      </footer>
    </div>
  </body>
</html>
`;
}

export function buildAdsOverviewPage(
  metadata: AdsSiteMetadata,
  source: AdsSource,
  plan: AdsPackagePlan,
): string {
  const main = `<main>
    <section class="hero-grid">
      <article class="panel">
        <span class="section-kicker">Public summary</span>
        <h2 class="section-title">Publish the minimum agency-facing truth without waiting on a portal rebuild.</h2>
        <p class="lede">Replace this page with your actual offering summary, boundary statement, FedRAMP status, and links to customer-facing authorization materials. The structure is already aligned to the official ADS process, but the facts still need to come from your team.</p>
        <div class="action-row">
          <a class="action-link primary" href="authorization-data.json">Machine-readable data</a>
          <a class="action-link secondary" href="services/">Scope and services</a>
          <a class="action-link secondary" href="access/">Access guidance</a>
        </div>
      </article>
      <aside class="panel stats-grid" aria-label="Trust center facts">
        <div class="stat"><span class="stat-label">Primary domain</span><div class="stat-value">${escapeHtml(metadata.primaryDomain)}</div></div>
        <div class="stat"><span class="stat-label">Support contact</span><div class="stat-value"><a href="mailto:${escapeHtml(metadata.supportEmail)}">${escapeHtml(metadata.supportEmail)}</a></div></div>
        <div class="stat"><span class="stat-label">Official process</span><div class="stat-value">${escapeHtml(plan.process.name)} [${escapeHtml(plan.process.shortName)}]</div></div>
        <div class="stat"><span class="stat-label">Marketplace URL</span><div class="stat-value">TODO</div></div>
      </aside>
    </section>

    <div class="section-grid">
      <section class="panel">
        <span class="section-kicker">Public artifacts</span>
        <h2 class="section-title">What this public site should expose</h2>
        <p class="section-copy">These public-facing surfaces were inferred from the official FedRAMP process text. Keep them customer-readable, current, and stable enough for agencies to cite.</p>
        ${renderArtifactList(plan.publicItems)}
      </section>
      <aside class="panel">
        <span class="section-kicker">Rollout order</span>
        <h2 class="section-title">Suggested publication sequence</h2>
        <p class="section-copy">Start with the public baseline, then add controlled retrieval. The private runbooks stay out of this site.</p>
        ${renderRolloutSummary(plan)}
      </aside>
      <section class="panel">
        <span class="section-kicker">Narrative</span>
        <h2 class="section-title">Replace this with your offering summary</h2>
        <p class="section-copy">TODO: describe the offering in plain language, explain the current authorization posture, and clarify which services and customer responsibilities are included in the public summary.</p>
        <p class="section-copy">TODO: add a short statement about how agencies or customers can retrieve deeper authorization materials without exposing controlled or private content on this host.</p>
      </section>
      <aside class="panel">
        <span class="section-kicker">Public endpoints</span>
        <h2 class="section-title">Machine-readable and agent-friendly files</h2>
        <ul class="endpoint-list">
          <li><h3><a href="authorization-data.json">authorization-data.json</a></h3><p>Public authorization-data skeleton for machine-readable retrieval.</p></li>
          <li><h3><a href="service-inventory.json">service-inventory.json</a></h3><p>Service inventory and scope skeleton that should stay synchronized with the human-readable services page.</p></li>
          <li><h3><a href="query-index.json">query-index.json</a></h3><p>Canonical machine-readable index of the public resources this trust center is willing to expose broadly.</p></li>
          <li><h3><a href="documentation/api/api.yaml">documentation/api/api.yaml</a></h3><p>OpenAPI contract for the public GET surface so orgs and tools can target the published data intentionally.</p></li>
          <li><h3><a href="llms.txt">llms.txt</a></h3><p>Agent-friendly discovery index that points organizations and agents to the public files without guesswork.</p></li>
          <li><h3><a href="llms-full.txt">llms-full.txt</a></h3><p>Full text bundle of the public trust-center docs and endpoints for “load it all at once” agent workflows.</p></li>
          <li><h3><a href="_source.json">_source.json</a></h3><p>Generation provenance tying this scaffold back to the official Consolidated Rules source snapshot.</p></li>
        </ul>
      </aside>
    </div>
  </main>`;

  return buildAdsSiteDocument(metadata, source, plan, {
    title: "Overview",
    description: `${metadata.siteTitle} public summary and machine-readable ADS endpoints.`,
    prefix: "",
    current: "home",
    main,
  });
}

export function buildAdsServicesPage(
  metadata: AdsSiteMetadata,
  source: AdsSource,
  plan: AdsPackagePlan,
): string {
  const main = `<main class="content-grid">
    <section class="panel">
      <span class="section-kicker">Scope</span>
      <h2 class="section-title">Services and minimum assessment scope</h2>
      <p class="section-copy">This page is where you publish the public service inventory, included components, and customer-responsibility framing. Keep the language synchronized with <a href="../service-inventory.json">service-inventory.json</a>.</p>
      <table class="history-table">
        <thead>
          <tr><th>Service</th><th>Model</th><th>In scope</th><th>Notes</th></tr>
        </thead>
        <tbody>
          <tr><td>TODO</td><td>TODO</td><td>Yes</td><td>TODO</td></tr>
          <tr><td>TODO</td><td>TODO</td><td>No</td><td>TODO</td></tr>
        </tbody>
      </table>
    </section>
    <div class="section-grid">
      <section class="panel">
        <span class="section-kicker">Shared responsibility</span>
        <h2 class="section-title">Clarify who operates what</h2>
        <p class="section-copy">TODO: explain the provider-managed security boundary, the customer-managed responsibilities, and any assumptions that would affect agency reviewers or customer deployment teams.</p>
        <ul class="checklist">
          <li>TODO: boundary statement</li>
          <li>TODO: customer-managed configurations</li>
          <li>TODO: service dependencies and exclusions</li>
        </ul>
      </section>
      <aside class="panel">
        <span class="section-kicker">Grounding</span>
        <h2 class="section-title">Why this page exists</h2>
        <p class="section-copy">This page is scaffolded from the official ADS process artifacts inferred for public publication. Update it whenever the service inventory, scope, or customer-responsibility model changes.</p>
        ${renderArtifactList(plan.publicItems.filter((item) => item.name.toLowerCase().includes("service inventory")))}
      </aside>
    </div>
  </main>`;

  return buildAdsSiteDocument(metadata, source, plan, {
    title: "Services",
    description: `${metadata.siteTitle} service inventory and scope summary.`,
    prefix: "../",
    current: "services",
    main,
  });
}

export function buildAdsAccessPage(
  metadata: AdsSiteMetadata,
  source: AdsSource,
  plan: AdsPackagePlan,
): string {
  const main = `<main class="content-grid">
    <section class="panel">
      <span class="section-kicker">Access</span>
      <h2 class="section-title">Public endpoints and controlled retrieval</h2>
      <p class="section-copy">Use this page to explain what is openly published, what requires controlled retrieval, and how agencies or necessary parties should request deeper authorization data. The public query surface should stop at the files explicitly linked here.</p>
      <ul class="endpoint-list">
        <li><h3><a href="../authorization-data.json">authorization-data.json</a></h3><p>Public machine-readable summary intended for broad retrieval.</p></li>
        <li><h3><a href="../service-inventory.json">service-inventory.json</a></h3><p>Public service and scope summary intended to stay aligned with the public site narrative.</p></li>
        <li><h3><a href="../query-index.json">query-index.json</a></h3><p>Machine-readable map of the public resources orgs and agents can query safely.</p></li>
        <li><h3><a href="../documentation/api/api.yaml">documentation/api/api.yaml</a></h3><p>OpenAPI contract describing the public read-only endpoints exposed by this trust center.</p></li>
        <li><h3>Controlled retrieval path</h3><p>TODO: document the request channel, reviewer expectations, and response model for deeper authorization materials.</p></li>
      </ul>
    </section>
    <div class="section-grid">
      <section class="panel">
        <span class="section-kicker">Request flow</span>
        <h2 class="section-title">Replace this with your real access procedure</h2>
        <ol class="rollout-list">
          <li><h3>Step 1</h3><p>TODO: identify the request intake path and required requester information.</p></li>
          <li><h3>Step 2</h3><p>TODO: describe validation, approval, and delivery expectations.</p></li>
          <li><h3>Step 3</h3><p>TODO: explain expiration, renewal, or follow-up rules.</p></li>
        </ol>
      </section>
      <aside class="panel">
        <span class="section-kicker">Controlled artifacts</span>
        <h2 class="section-title">Not public, but planned</h2>
        <p class="section-copy">These artifact categories belong in the controlled-access lane, not on the public host itself.</p>
        ${renderArtifactList(plan.controlledItems)}
      </aside>
    </div>
  </main>`;

  return buildAdsSiteDocument(metadata, source, plan, {
    title: "Access",
    description: `${metadata.siteTitle} public and controlled access guidance.`,
    prefix: "../",
    current: "access",
    main,
  });
}

export function buildAdsHistoryPage(
  metadata: AdsSiteMetadata,
  source: AdsSource,
  plan: AdsPackagePlan,
): string {
  const main = `<main class="content-grid">
    <section class="panel">
      <span class="section-kicker">History</span>
      <h2 class="section-title">Version history and update notes</h2>
      <p class="section-copy">Use this page to document what changed, when it changed, and where a reviewer should go to compare current and prior public authorization summaries.</p>
      <table class="history-table">
        <thead>
          <tr><th>Version</th><th>Effective date</th><th>Summary</th><th>Delta link</th></tr>
        </thead>
        <tbody>
          <tr><td>TODO</td><td>TODO</td><td>TODO</td><td>TODO</td></tr>
        </tbody>
      </table>
    </section>
    <div class="section-grid">
      <section class="panel">
        <span class="section-kicker">Update policy</span>
        <h2 class="section-title">State the public refresh cadence</h2>
        <ul class="checklist">
          <li>TODO: expected refresh cadence for human-readable summary</li>
          <li>TODO: expected refresh cadence for machine-readable files</li>
          <li>TODO: retention period for prior versions</li>
        </ul>
      </section>
      <aside class="panel">
        <span class="section-kicker">Grounding</span>
        <h2 class="section-title">Why the history surface matters</h2>
        ${renderArtifactList(plan.publicItems.filter((item) => item.name.toLowerCase().includes("version history")))}
      </aside>
    </div>
  </main>`;

  return buildAdsSiteDocument(metadata, source, plan, {
    title: "History",
    description: `${metadata.siteTitle} change history and publication retention notes.`,
    prefix: "../",
    current: "history",
    main,
  });
}

export function buildAds404Page(metadata: AdsSiteMetadata): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Not found · ${escapeHtml(metadata.siteTitle)}</title>
    <link rel="stylesheet" href="assets/site.css" />
  </head>
  <body>
    <div class="site-shell">
      <main class="panel">
        <span class="section-kicker">404</span>
        <h1 class="section-title">This trust-center path is not published.</h1>
        <p class="section-copy">Return to the overview, then use the public navigation to find the current summary, access guidance, or history pages.</p>
        <div class="action-row">
          <a class="action-link primary" href="./">Back to overview</a>
        </div>
      </main>
    </div>
  </body>
</html>
`;
}

export function buildAdsRobotsTxt(metadata: AdsSiteMetadata): string {
  return `# Draft scaffold: block indexing until a human approves publication\nUser-agent: *\nDisallow: /\nSitemap: ${metadata.baseUrl}/sitemap.xml\n`;
}

export function buildAdsSitemapXml(metadata: AdsSiteMetadata): string {
  const pages = ["", "/services/", "/access/", "/history/"];
  const urls = pages
    .map(
      (path) =>
        `  <url>\n    <loc>${escapeHtml(`${metadata.baseUrl}${path}`)}</loc>\n  </url>`,
    )
    .join("\n");
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls}\n</urlset>\n`;
}
