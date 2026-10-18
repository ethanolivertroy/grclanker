---
title: FedRAMP Readiness
description: Look up FedRAMP rules, assess readiness for a process or KSI, plan its artifacts, and draft a Certification Data Sharing bundle and trust-center site.
---

The FedRAMP tools read the official [FedRAMP Consolidated Rules](https://github.com/FedRAMP/rules) and answer in FedRAMP's own IDs. They need no credentials. Eight tools look up and plan. The two generators write draft files to a local directory and never publish anything.

This guide follows the order most teams work in: look up the rules, assess readiness for one process or key security indicator (KSI), plan the artifacts, then generate a starter bundle and a draft trust-center site.

## Run it

Start `grclanker` and ask in plain words. The agent calls the matching tools:

```text
Which version of the FedRAMP Consolidated Rules are you using?
What does FedRAMP require for Certification Data Sharing under 20x?
Give me a provider readiness brief for Vulnerability Detection and Response.
Plan the artifacts we need for Secure Configuration Guide.
Generate a draft trust-center site for Acme Platform at trust.acme.example.
```

The [audit](/docs/workflows/audit/) and [assess](/docs/workflows/assess/) workflows call the same tools when FedRAMP is in scope, for example `grclanker assess "FedRAMP 20x readiness for the payments service"`.

## Tools

| Tool | Behavior |
| --- | --- |
| `fedramp_check_sources` | Reports the rules version, source path, cache status, and whether the supporting narrative repository is reachable. |
| `fedramp_search_frmr` | Searches definitions, processes, requirements, and KSIs, with optional section and program filters. |
| `fedramp_get_process` | Resolves one process, such as CDS, IVV, SCG, VDR, or CCM, with its purpose, rule subsets, requirement counts, and sample requirements. |
| `fedramp_get_requirement` | Resolves one requirement or recommendation by ID or unique name. |
| `fedramp_get_ksi` | Resolves a KSI domain or one indicator by ID or name. |
| `fedramp_assess_readiness` | Turns a process or KSI into a prioritized checklist with likely artifacts and workstreams. |
| `fedramp_plan_process_artifacts` | Turns a process or KSI into public, controlled-access, and private artifacts with a rollout order. |
| `fedramp_plan_ads_package` | Builds the artifact plan for Certification Data Sharing, grouped by layer. |
| `fedramp_generate_ads_bundle` | Writes a starter bundle of public, controlled-access, and private template files. |
| `fedramp_generate_ads_site` | Writes a static, public-only trust-center site as a draft that needs human approval. |

FedRAMP renamed Authorization Data Sharing (ADS) to Certification Data Sharing (CDS). The generator tools keep `ads` in their names, and a query for `ADS` still resolves to CDS.

## Where the rules come from

Every answer comes from `fedramp-consolidated-rules.json` in the [FedRAMP/rules](https://github.com/FedRAMP/rules) repository on GitHub. Each response ends with a source line naming the file, branch, rules version, upstream update date, and cache status.

The parsed rules are cached at `~/.grclanker/.state/fedramp/catalog.json` for 24 hours. The source check is cached in `sources.json` beside it for 6 hours. Set [`GRCLANKER_HOME`](/docs/getting-started/configuration/#environment-variables) to move the cache along with the rest of grclanker's state.

The cache status is one of:

- `live`: fetched from GitHub on this call
- `cached`: read from the cache
- `stale`: GitHub was unreachable, so an expired cache was served, with a note saying why

To force a fresh copy, ask for a source check with a refresh:

```text
fedramp_check_sources {"refresh":true}
```

The source check also reports whether the supporting narrative repository, [FedRAMP/2026-markdown](https://github.com/FedRAMP/2026-markdown), is reachable. The lookups do not depend on it.

The [FedRAMP Official Sources](/docs/fedramp/) pages on this site are a reviewed snapshot of the same rules file. The tools read the live file, so their rules version can be newer than the snapshot.

## Look up rules

Use search when you know a topic but not an ID. Use the `get` tools when you know the ID or exact name:

```text
fedramp_search_frmr {"query":"accepted vulnerability","section":"definition"}
fedramp_get_process {"query":"VDR"}
fedramp_get_requirement {"query":"CDS-CSO-PUB"}
fedramp_get_ksi {"query":"KSI-CNA-EIS"}
```

Search looks at IDs, names, and statement text. Exact matches rank first, then matches at the start of a field, then matches anywhere, then results that contain every word of the query. `section` narrows results to `definition`, `process`, `requirement`, or `ksi`. `limit` defaults to 10 and accepts 1 to 50.

A requirement lookup returns the full statement, its keyword (such as MUST or SHOULD), the rule subset, checklist items, terms, notes, and dated updates. A KSI lookup returns the indicator text for each certification class and the Rev5 controls it maps to, such as `si-7.1`.

If a query matches more than one item, the tool asks you to narrow it down and lists candidates. Former short names still resolve to the current process:

| Former name | Current process |
| --- | --- |
| `ADS`, Authorization Data Sharing | `CDS`, Certification Data Sharing |
| `FSI`, FedRAMP Security Inbox | `AFC`, Addressing FedRAMP Communication |
| `ICP`, Incident Communications Procedures | `IEC`, Incident Evaluation and Communication |
| `PVA`, Persistent Validation and Assessment | `IVV`, Independent Verification and Validation |
| `UCM`, Using Cryptographic Modules | `CMU`, Cryptographic Module Use |

### Filter by program

Every rule applies to 20x, Rev5, or both. The `applies_to` argument filters by program:

| `applies_to` | Includes |
| --- | --- |
| `any` | Every rule |
| `20x` | 20x rules and rules for both programs |
| `rev5` | Rev5 rules and rules for both programs |
| `both` | Only rules marked for both programs |

Search, readiness, and process artifact planning default to `any`. The CDS package plan, bundle, and site default to `20x`.

## Assess readiness

`fedramp_assess_readiness` accepts a process, a KSI domain, or one indicator:

```text
fedramp_assess_readiness {"query":"CDS","applies_to":"20x","audience":"provider","limit":5}
```

For a process, the brief lists:

- a priority checklist, where each item shows its keyword, requirement ID, program, rule subset, and statement
- likely artifacts to have ready
- operational workstreams, such as trust-center operations or access logging
- linked KSI indicators, when the rules link any to the process

The artifacts and workstreams are inferred from the wording of the official requirements. Treat them as a starting list, not as FedRAMP requirements.

For a KSI domain, the brief starts with the domain's theme and its indicators. For one indicator, it starts with the indicator text and its Rev5 controls. KSIs belong to 20x, so these briefs always apply to 20x. A checklist appears only when the rules link the KSI to a process.

### How the checklist is ordered

`limit` sets the checklist length. It defaults to 8 and accepts 1 to 50. Each requirement gets a score, and the highest scores come first:

- Keyword strength outweighs everything else. Any MUST or MUST NOT ranks above any SHOULD or SHOULD NOT, which ranks above MAY. For a rule that varies by certification class, the strongest keyword in any class counts.
- Rules for both programs score slightly higher than 20x-only rules, which score slightly higher than Rev5-only rules.
- The audience adds weight. `provider`, the default, favors provider responsibilities and rules for using a trust center. `trust-center` favors the FedRAMP-Compatible Trust Center rules, then rules for using a trust center. `any` adds none.
- Statements that mention programmatic access, publicly sharing, operating persistently, quarterly work, notifying, logging access, or an inventory get a small boost.

Among rules with the same keyword strength, the audience weight can outrank the program. Ties sort by requirement ID.

## Plan artifacts

`fedramp_plan_process_artifacts` maps a process or KSI to concrete artifacts:

```text
fedramp_plan_process_artifacts {"query":"SCG","audience":"provider"}
```

The plan draws from 11 artifact templates. A template appears only when the wording of an official requirement or linked indicator calls for it, and each item names up to four requirement IDs that ground it.

| Artifact | Surface | Phase | Format |
| --- | --- | --- | --- |
| Human-readable authorization summary page | Public | Foundation | Web page |
| Machine-readable authorization data feed | Public | Foundation | JSON feed or API payload |
| Service inventory and assessment-scope page | Public | Foundation | Catalog page |
| Secure configuration guide and shared-responsibility guidance | Public | Foundation | Guide page or PDF |
| Cryptographic module inventory and references | Controlled access | Foundation | Inventory appendix |
| Controlled authorization-data API and access guide | Controlled access | Access | API docs and access instructions |
| Version history and change-log archive | Controlled access | Access | Version archive |
| Vulnerability response evidence bundle | Controlled access | Operations | Evidence bundle |
| Access inventory and authorization-data audit logs | Private | Operations | Operational records |
| Notification routing and escalation runbook | Private | Operations | Runbook |
| Continuous validation cadence records | Private | Operations | Automation evidence |

The rollout order groups the selected artifacts by phase and skips any phase with nothing in it:

1. Foundation: publish the public baseline, so the offering is legible without a private request loop.
2. Access: enable controlled retrieval of deeper authorization data for agencies and other necessary parties.
3. Operations: back the published surface with internal runbooks, logs, and recurring evidence.

`fedramp_plan_ads_package` runs the same planning for Certification Data Sharing and groups the items into public trust-center, controlled authorization-data, and private operating layers. It defaults to `applies_to` `20x` and `audience` `trust-center`:

```text
fedramp_plan_ads_package {}
```

## Generate the starter bundle

`fedramp_generate_ads_bundle` writes template files for all three layers:

```text
fedramp_generate_ads_bundle {"output_dir":"./export/fedramp"}
```

The first run writes `./export/fedramp/ads-starter-bundle`:

| File | Layer | Contents |
| --- | --- | --- |
| `README.md` | None | The plan, rollout order, and hosting notes |
| `_source.json` | None | Provenance: process, program, audience, plan items, and rules version |
| `public/trust-center-summary.md` | Public | Summary, included services, customer responsibilities, and scope notes |
| `public/authorization-data.json` | Public | Machine-readable authorization data skeleton |
| `public/service-inventory.json` | Public | Service list and shared-responsibility summary skeleton |
| `controlled/access-instructions.md` | Controlled access | Access model, endpoints, request steps, and returned data |
| `controlled/version-history.md` | Controlled access | Version archive and retention notes |
| `private/operating-runbook.md` | Private | Owners, regular tasks, and escalation conditions |
| `private/access-log-schema.json` | Private | Field schema and retention period for access logs |
| `private/notification-routing.md` | Private | Monitored channels and a trigger matrix |
| `private/continuous-validation.md` | Private | Validation checks and evidence capture |

Each template names the requirement IDs it answers. Fill in every `TODO`, then check each layer against your actual trust-center and authorization-data workflow.

## Generate the draft trust-center site

`fedramp_generate_ads_site` writes a static site that needs no application server:

```text
fedramp_generate_ads_site {"provider_name":"Acme Cloud","offering_name":"Acme Platform","primary_domain":"trust.acme.example","support_email":"security@acme.example"}
```

Any value you leave out gets a placeholder: Example Provider, Example Cloud Service, `trust.example.com`, and `security@example.com`. A scheme or trailing slash on `primary_domain` is removed.

The first run writes `./export/fedramp/ads-public-site`:

| File | Purpose |
| --- | --- |
| `index.html`, `services/index.html`, `access/index.html`, `history/index.html` | Summary, services, access guidance, and version history pages |
| `404.html`, `assets/site.css` | Not-found page and shared styles |
| `authorization-data.json`, `service-inventory.json` | Public machine-readable data |
| `query-index.json`, `trust-center.md`, `llms.txt`, `llms-full.txt` | Discovery files for tools and agents |
| `documentation/api/api.yaml` | OpenAPI description of the public GET surface |
| `robots.txt`, `sitemap.xml` | Crawler controls |
| `APPROVAL_REQUIRED.md` | Review checklist and approval record |
| `README.md`, `_source.json` | Hosting notes and provenance |

The site carries only public content. Controlled-access data and private operating records stay out of it; use the starter bundle for those.

The site starts as a draft. The four content pages show a draft banner and carry a `noindex,nofollow,noarchive` robots meta tag, and `robots.txt` disallows all crawling.

## Before you publish

Keep the site private and unhosted until a named owner works through `APPROVAL_REQUIRED.md`:

- Confirm the provider name, offering name, domain, and support contact.
- Resolve every `TODO` in the HTML, Markdown, JSON, and YAML files.
- Confirm no controlled-access or private information reached the public files.
- Confirm the organization is willing to publish each JSON field and page section.
- Confirm the public query surface is only the files meant for it: the two data files, `query-index.json`, `trust-center.md`, the two `llms` files, and `documentation/api/api.yaml`.
- Confirm the host serves the JSON files with `Content-Type: application/json` and `X-Content-Type-Options: nosniff`, and allows cross-origin reads, as FRC-CSO-JSN requires.
- Confirm the summary, access guidance, and version history match the latest approved public posture.
- Record the reviewer, date, and scope in the approval record.

Only then remove the draft banner, the `noindex` tag, and the `Disallow: /` rule, and publish to a host your organization owns. The README covers AWS (S3 with CloudFront), Azure (Storage static website with Front Door or Azure CDN), and GCP (Cloud Storage behind an HTTPS load balancer or CDN). Keep the file paths intact so links and the sitemap still work.

`README.md`, `APPROVAL_REQUIRED.md`, and `_source.json` are working files for your team, not part of the public query surface. Leave them off the host unless you mean to publish them.

## Output safety

Both generators write under `./export/fedramp` in the working directory unless `output_dir` names another root.

- Each run claims a new directory. A rerun writes `ads-starter-bundle-2`, then `-3`, and never overwrites an earlier draft. After 100 drafts with the same name, the generator stops until you move or delete old ones.
- Directories are created with mode `0700` and files with mode `0600`, so only your user can read them.
- The generators refuse to write through a symlink or outside the output root.

## Troubleshooting

- **The supporting source shows as unavailable with a 403.** The repository check uses the unauthenticated GitHub API, which allows 60 requests an hour. The rules file comes from `raw.githubusercontent.com` and still loads. Only metadata such as the blob SHA shows as unavailable until the limit resets.
- **The cache status is `stale`.** GitHub could not be reached, so the last cached copy was used. Run `fedramp_check_sources {"refresh":true}` once the network is back.
- **A query matched multiple items.** Use the full ID, such as `CDS-CSO-PUB` or `KSI-CNA-EIS`, or one of the candidate names from the error.
- **A generator refuses the output directory.** The path is a symlink or an existing file. Pass a plain directory in `output_dir`.

## Related

- [FedRAMP Official Sources](/docs/fedramp/) lists every process and KSI domain in the current snapshot.
- [OSCAL Workspaces](/docs/guides/oscal-workspaces/) turns control implementations into an OSCAL system security plan.
- [SCF Crosswalks](/docs/guides/scf-crosswalks/) maps the Rev5 controls a KSI references to other frameworks.
