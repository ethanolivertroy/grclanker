---
title: Google Cloud Platform
description: Read-only GCP security inspector covering IAM, logging, organization guardrails, data protection, and network security with multi-framework mappings.
---

The GCP integration implements the `gcp-sec-inspector` spec as native grclanker tools. It inspects an organization (or a single project) through documented Google Cloud REST APIs and scores 23 controls.

Every finding maps to FedRAMP, CMMC 2.0, SOC 2, CIS GCP, PCI-DSS, DISA STIG, IRAP, and ISMAP. Every request is read-only.

## What it inspects

- **IAM:** privileged bindings, service account key age and count, cross-project service account access, default service account privilege.
- **Logging and detection:** Admin Activity and Data Access audit visibility, log sinks, log bucket retention, Security Command Center visibility (reported for context, never scored).
- **Organization guardrails:** domain-restricted sharing, service account key constraints, serial port and Shielded VM policies, OS Login, Binary Authorization, instance hardening.
- **Data protection:** uniform bucket-level access, public IAM exposure, KMS rotation, CMEK on buckets and disks, Cloud DNS DNSSEC, API key restrictions, VPC Service Controls.
- **Network security:** internet-open firewall rules on administrative ports, VPC flow logs, Private Google Access, Cloud NAT and external IPs, load balancer SSL policies, Cloud Armor coverage.

## Setup and authentication

### Scope

- `GCP_ORGANIZATION_ID` (alias `GCP_ORG_ID`): Organization to inventory. Projects are enumerated through Cloud Asset Inventory under this organization.
- `GCP_PROJECT_ID`, `GOOGLE_CLOUD_PROJECT`, or `GCLOUD_PROJECT`: Single-project fallback when no organization is configured, or a focus project for effective org policy reads.
  - When none is set, the integration uses the `project_id` from the credential file that the chain below loads, but only if that file is a service account key.
  - An access token (argument or environment) means no file is loaded, so set a project variable or `organization_id` in that case.

Every tool also accepts `organization_id` and `project_id` arguments that take precedence over the environment.

### Credentials

The credential chain is evaluated in this order:

1. `access_token` argument, then `GCP_ACCESS_TOKEN` (also `GOOGLE_OAUTH_ACCESS_TOKEN` or `GOOGLE_ACCESS_TOKEN`)
2. `credentials_file` argument, then `GCP_CREDENTIALS_FILE`, then `GOOGLE_APPLICATION_CREDENTIALS`
3. The Application Default Credentials file:
   - `~/.config/gcloud/application_default_credentials.json`, honoring `CLOUDSDK_CONFIG`
   - `%APPDATA%\gcloud\application_default_credentials.json` on Windows
4. `gcloud auth print-access-token`

Credential files may be a service account key (`type: service_account`) or an authorized user ADC file (`type: authorized_user`).

- **Service account key:** Exchanged with the documented OAuth 2.0 service account JWT flow. An RS256 assertion is signed with `node:crypto` and posted to the key's `token_uri` with `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` and the `https://www.googleapis.com/auth/cloud-platform` scope.
- **Authorized user file:** Uses the refresh token grant.

No SDK or extra dependency is required.

```bash
export GCP_ORGANIZATION_ID=123456789012
export GCP_CREDENTIALS_FILE=/path/to/audit-sa-key.json
```

### Required IAM roles

Grant the audit principal these roles at the organization node so every project is covered. Each entry pairs a role with its surfaces:

- `roles/cloudasset.viewer`: Project inventory, IAM policy search, CryptoKey assets.
- `roles/iam.securityReviewer`: Service accounts and keys.
- `roles/logging.viewer`: Audit entries, sinks, log buckets, logging settings.
- `roles/orgpolicy.policyViewer`: Effective organization policies.
- `roles/resourcemanager.organizationViewer`: Organization metadata.
- `roles/compute.viewer`: Firewalls, subnetworks, routers, instances, disks, SSL policies, proxies, backend services, project metadata.
- A role carrying `storage.buckets.list`: Bucket inventory. A custom read-only role is recommended.
- `roles/dns.reader`: Managed zones.
- `roles/serviceusage.apiKeysViewer`: API keys.
- `roles/accesscontextmanager.policyReader`: Access policies and service perimeters.
- `roles/binaryauthorization.policyViewer`: Binary Authorization policy.
- `roles/securitycenter.findingsViewer`: Security Command Center visibility (optional).

### Enabled APIs

The projects you inventory must have the relevant APIs enabled:

- `cloudasset`
- `cloudresourcemanager`
- `iam`
- `logging`
- `compute`
- `storage`
- `dns`
- `apikeys`
- `accesscontextmanager`
- `binaryauthorization`
- `cloudkms`
- `securitycenter` (optional)

When an API is disabled in a project, the dependent finding is rendered `manual` for that project, never `pass`.

## Tools

- `gcp_check_access`: Probe the core surfaces and report which are readable. Notable arguments: `organization_id`, `project_id`, `access_token`, `credentials_file`.
- `gcp_assess_identity`: Controls 1, 2, 13, 14. Notable arguments: `stale_days` (90), `max_keys` (200), `project_limit`.
- `gcp_assess_logging_detection`: Control 5 plus Security Command Center visibility. Notable arguments: `max_findings` (200), `project_limit`.
- `gcp_assess_org_guardrails`: Controls 6, 8, 11, 12, 23. Notable arguments: `max_assets` (2000), `project_limit`.
- `gcp_assess_data_protection`: Controls 3, 7, 15, 16, 17, 20, 21. Notable arguments: `max_assets` (2000), `project_limit`.
- `gcp_assess_network_security`: Controls 4, 9, 10, 18, 19, 22. Notable arguments: `max_assets` (2000), `project_limit`.
- `gcp_export_audit_bundle`: Run everything and write the shared bundle layout. Notable arguments: `output_dir` (`./export/gcp`) plus every option above.

### Project cap and pagination

`project_limit` (alias `max_projects`, default 20) caps how many projects are inventoried. When the cap truncates the inventory, every dependent finding is downgraded to `warn` with seen and total counts, so a partial view can never pass.

Every paginated list follows `nextPageToken` until the API stops returning one. A list that exits early for any other reason is recorded as truncated and downgrades its findings the same way:

- The per-list item cap was reached.
- The cursor repeated itself.
- The page budget of 250 pages was spent.

The summary then reads `N seen, total unknown`.

### Unreadable inventories

Every finding also tracks each inventory it depends on. When any of them is unreadable (403, 401, or an error), for the whole scope or for one project, the finding drops below `pass`. This happens even if its primary inventory was read completely.

- The finding is `manual` when the unreadable inventory is the one the finding scores, and `warn` otherwise.
- The summary names the dataset and the endpoint, for example:
  - `Partial view: Cloud Routers unreadable for 1 of 2 projects (second-project) via compute.googleapis.com/compute/v1/projects/{project}/aggregated/routers (403 Forbidden)`
- `evidence.unreadable_inventories` lists every entry with its scope and error.

A count or list that would have been derived from an unreadable inventory is rendered as `null`, never as zero or an empty list.

- The rule holds whether that inventory is the one the finding scores or a dependent one.
- The same rule applies to the assessment-level `summary` counters: `sampled_projects` is `null` when the project inventory itself was unreadable.
- A summary sentence names the unreadable dataset instead of counting it: `instance overrides could not be checked because Compute Engine instances were unreadable`, never `none of 0 instances overrides it`.

### Collection-status fields

The collection-status fields follow the same rule. These fields are `null` whenever the scan they describe was denied or never ran:

- On a finding: `evidence.truncated`, `denied_projects`, and `unreachable_scopes`.
- In the assessment summaries: `projects_truncated`, `sources_truncated`, and `findings_truncated`.

`false`, `0`, or `[]` is written only when that scan ran to completion, so no status ever says complete about a call that did not happen.

A read that was skipped because its upstream discovery failed is recorded with `status: "not_collected"` rather than `"unreadable"`. Its wording names the upstream call with the status that call actually returned. For example, with no project to resolve an effective org policy against, GCP-ORG-02 through GCP-ORG-05 read:

`effective org policy constraints/iam.allowedPolicyMemberDomains not collected for the scope (cloudresourcemanager.googleapis.com/v1/projects/{project}:getEffectiveOrgPolicy was not called): no project could be enumerated because project inventory was unreadable via cloudasset.googleapis.com/v1/{scope}:searchAllResources (403 Forbidden)`

An HTTP status is never attributed to an endpoint that was not requested.

In `core_data/`, a dataset that was denied or never collected is written as a `{status, dataset, endpoint, scope, error, data: null}` marker in place of the rows, never as `[]`. The same entry appears in the snapshot's `unreadable_inventories`.

## Status semantics

- `pass`: Both of these hold:
  - Every inventoried resource satisfied the check.
  - Every inventory the finding depends on was complete (no cap, no truncated page, no denied project, no unreadable dependent inventory).
- `warn`: Any of these applies:
  - A violation on a lower-impact check.
  - A partial inventory (project cap, truncated page, denied or API-disabled project, a dependent inventory unreadable in part or in whole).
  - Items missing a required date.
  - A dry-run or unresolved configuration.
- `fail`: A documented violation was found in a complete inventory.
- `manual`: Any of these applies:
  - The inventory the finding scores was forbidden or errored.
  - The inventory was empty where emptiness is not compliant by intent.
  - The API is disabled.
  - The control is outside the configured scope.

For `manual`, the summary names the dataset, the endpoint, and the evidence to collect.

Emptiness passes only for two findings:

- `GCP-IAM-02`: No user-managed keys across a non-empty set of service accounts whose key lists were all readable.
- `GCP-DATA-06`: No API keys in projects where the API Keys API answered.

`GCP-DATA-07` fails on emptiness (no access policy means no perimeter). Every other finding renders `manual` on an empty inventory.

## Control coverage

Each entry names the control, then the tool and findings that cover it, then the semantics.

- **1 Service Account Key Rotation** (`gcp_assess_identity`, `GCP-IAM-02`, `GCP-IAM-03`): Fail when a user-managed key exceeds `stale_days`. Undated keys warn. User-managed keys present warn.
- **2 Overprivileged IAM Roles** (`gcp_assess_identity`, `GCP-IAM-01`): Fail on owner/editor-style bindings. Unused permission analysis is not evaluated.
- **3 Public Resource Exposure** (`gcp_assess_data_protection`, `GCP-DATA-02`): Fail when any IAM policy in scope binds `allUsers` or `allAuthenticatedUsers`.
- **4 VPC Firewall Rules** (`gcp_assess_network_security`, `GCP-NET-01`): Fail on enabled ingress rules from `0.0.0.0/0` or `::/0` allowing TCP 22 or 3389 (or all ports).
- **5 Audit Logging Configuration** (`gcp_assess_logging_detection`, `GCP-LOG-01` to `GCP-LOG-04`):
  - Admin Activity entries (warn).
  - Data Access entries (fail).
  - At least one enabled sink per project, with `disabled: true` sinks excluded and named in evidence (fail).
  - Configurable log bucket retention below 90 days (fail).
  - `GCP-LOG-05` is visibility only.
- **6 Organization Policy Constraints** (`gcp_assess_org_guardrails`, `GCP-ORG-01` to `GCP-ORG-04`):
  - Organization visibility
  - `iam.allowedPolicyMemberDomains`
  - `iam.disableServiceAccountKeyCreation`
  - `iam.disableServiceAccountKeyUpload`
- **7 KMS Key Rotation** (`gcp_assess_data_protection`, `GCP-DATA-03`): Fail when an `ENCRYPT_DECRYPT` key lacks `rotationPeriod` or `nextRotationTime`, or rotates slower than 365 days. Overdue rotation warns.
- **8 Binary Authorization** (`gcp_assess_org_guardrails`, `GCP-ORG-07`):
  - Fail unless each of these has `evaluationMode` `REQUIRE_ATTESTATION` or `ALWAYS_DENY`:
    - `defaultAdmissionRule`
    - Every `clusterAdmissionRules` entry
    - Every `kubernetesNamespaceAdmissionRules` entry
    - Every `kubernetesServiceAccountAdmissionRules` entry
    - Every `istioServiceIdentityAdmissionRules` entry
  - Dry-run enforcement warns.
  - Attestors are not evaluated.
- **9 VPC Flow Logs** (`gcp_assess_network_security`, `GCP-NET-02`): Fail when an eligible subnetwork has neither `logConfig.enable=true` nor `enableFlowLogs=true`.
- **10 Cloud NAT Configuration** (`gcp_assess_network_security`, `GCP-NET-04`):
  - Warn when a subnetwork is not covered by a Cloud NAT in its network and region (`sourceSubnetworkIpRangesToNat`, with `LIST_OF_SUBNETWORKS` covering only the listed `subnetworks[]`).
  - Warn when instances carry IPv4 `accessConfigs` or IPv6 `ipv6AccessConfigs`.
- **11 OS Login Enforcement** (`gcp_assess_org_guardrails`, `GCP-ORG-06`):
  - Pass only when every sampled project with Compute Engine sets `enable-oslogin=TRUE` in `commonInstanceMetadata` and no instance overrides it.
  - An existing project or instance without that setting fails and is named, even when `constraints/compute.requireOsLogin` is enforced. That is because the constraint protects new projects and blocks future disabling, but never enables OS Login on existing resources.
  - The constraint is reported in the summary. An unreadable constraint warns the finding.
  - 2FA is not evaluated.
- **12 Serial Port Disabled** (`gcp_assess_org_guardrails`, `GCP-ORG-05`, `GCP-ORG-08`): Org policy `compute.disableSerialPortAccess` plus instance `serial-port-enable` metadata.
- **13 Default Service Account Usage** (`gcp_assess_identity`, `GCP-IAM-05`): Fail when a default compute or App Engine service account holds an owner/editor-style role.
- **14 Cross-Project Access** (`gcp_assess_identity`, `GCP-IAM-04`): Warn on service account bindings that cross project boundaries.
- **15 Uniform Bucket-Level Access** (`gcp_assess_data_protection`, `GCP-DATA-01`): Fail when `iamConfiguration.uniformBucketLevelAccess.enabled` is not true.
- **16 Customer-Managed Encryption Keys** (`gcp_assess_data_protection`, `GCP-DATA-04`): Warn when buckets lack `encryption.defaultKmsKeyName` or disks lack `diskEncryptionKey.kmsKeyName`.
- **17 DNS Security (DNSSEC)** (`gcp_assess_data_protection`, `GCP-DATA-05`): Fail when a public managed zone has `dnssecConfig.state` other than `on` or signs with `rsasha1`.
- **18 Load Balancer SSL Policies** (`gcp_assess_network_security`, `GCP-NET-05`):
  - Fail when an HTTPS proxy has no SSL policy, `minTlsVersion` below `TLS_1_2`, or the `COMPATIBLE` profile.
  - `CUSTOM` warns.
  - Policies are matched by full global or regional path, never by bare name.
- **19 Cloud Armor WAF** (`gcp_assess_network_security`, `GCP-NET-06`): Warn when an external `HTTP`, `HTTPS`, `HTTP2`, or `H2C` backend service has no `securityPolicy`.
- **20 API Key Restrictions** (`gcp_assess_data_protection`, `GCP-DATA-06`): Fail when a key lacks `restrictions.apiTargets` or an application restriction.
- **21 VPC Service Controls** (`gcp_assess_data_protection`, `GCP-DATA-07`): Fail when no access policy exists. Warn when no perimeter is enforced with resources and restricted services.
- **22 Private Google Access** (`gcp_assess_network_security`, `GCP-NET-03`): Warn when an eligible subnetwork lacks `privateIpGoogleAccess=true`.
- **23 Shielded VM Configuration** (`gcp_assess_org_guardrails`, `GCP-ORG-05`, `GCP-ORG-08`): Org policy `compute.requireShieldedVm` plus instance `shieldedInstanceConfig` (Secure Boot, vTPM, integrity monitoring).

## Framework mappings

Every finding carries the spec mapping table entries for its controls. The export bundle writes one report per framework under `compliance/frameworks/`:

| Report | Framework |
|--------|-----------|
| `fedramp.md` | FedRAMP / NIST 800-53 |
| `cmmc.md` | CMMC 2.0 Level 2 |
| `soc2.md` | SOC 2 Trust Services Criteria |
| `cis_gcp.md` | CIS Google Cloud Platform Benchmark |
| `pci_dss.md` | PCI-DSS 4.0 |
| `disa_stig.md` | DISA STIG SRG |
| `irap.md` | IRAP / ISM |
| `ismap.md` | ISMAP |

## Export bundle layout

```
<org-or-project>-audit/
  QUICK_REFERENCE.md
  README.md
  metadata.json
  core_data/            projected snapshots: identifiers plus the documented fields each control reads;
                        a denied or never-collected dataset is a {status, endpoint, error, data: null} marker, never []
  analysis/             findings.json, category_summaries.json, one JSON and markdown per category
  compliance/           executive_summary.md, unified_compliance_matrix.md, frameworks/<framework>.md
  _errors.log           only when collection partially failed
<org-or-project>-audit.zip
```

Reruns allocate `-2`, `-3`, and so on. The zip name derives from the allocated directory, so nothing is overwritten. Output paths are resolved with traversal and symlink-parent protection.

### Projected snapshots

Snapshots and finding evidence never contain whole API resources. Each collected object is projected to its identifiers and the documented fields the verdict reads. For example, a Compute instance becomes its name, the resolved `enable-oslogin` and `serial-port-enable` flags, and the three `shieldedInstanceConfig` booleans.

As a result, these are never written:

- Metadata values such as `startup-script` or `ssh-keys`
- Labels, annotations, descriptions, and filters
- API key `keyString` values
- IAP client secrets
- Disk `rawKey` material

A regression test seeds a distinct fake secret into every collected object and exports a bundle. It asserts that none of those secrets appears in any file under the output directory or in any entry of the zip.

### Error text

Error text follows the same rule as snapshots and finding evidence. A failed request is described by its HTTP status, method, and endpoint (without the query string), plus one of these:

- The documented `google.rpc.Status` fields: `error.status`, a scrubbed `error.message`, and each `error.details[]` entry's `@type` name and `reason`.
- For any other body, `non-JSON error body (<content type>; N bytes)`.

The body itself is never copied into an error.

A 2xx whose body is not a JSON object is an unreadable surface, never an empty inventory:

- An HTML page renders `200 OK: non-JSON response body (<content type>; N bytes) (GET <endpoint>)`.
- An empty or whitespace body renders `200 OK: empty response body (<content type>; N bytes) (GET <endpoint>)`.

Dependent findings are then manual or warn, and the access probe reports the surface not readable. Every surface this client reads documents a JSON object body. The proto3 JSON mapping encodes an all-default response and `google.protobuf.Empty` as `{}`.

### Error scrubbing

Every error string is built at one point, `GcpApiError`, and scrubbed there. `describeError` covers anything thrown outside the client. The scrub removes:

- The configured credentials and exchanged token, by exact match.
- `Bearer` and `Basic` values.
- `ya29.`, `AIza`, `GOCSPX-`, and `1//` shapes.
- JWT assertions.
- `Cookie` and `Set-Cookie` values.
- Credential name-value pairs (api key, access, refresh, and id tokens, client secret, private key, password, session).
- Embedded URL query strings and fragments.
- In error text only, bare 16+ character runs with a digit or mixed case that are not made of words.
  - Identifiers in snake_case, camelCase, and PascalCase, such as `PreconditionFailure` and `LocalizedMessage`, survive.

Credential files follow the same rule:

- A malformed service account or ADC file is reported as `invalid JSON in <path>`.
- A read failure is reported as `unable to read <path> (<code>)` with the Node system error code.

The parser or filesystem message is never reported, since V8 quotes the characters around a fault. For a broken `private_key` line, those characters are key material.

The bundle writer applies the same rules once more to every file, `.md` files and `_errors.log` included. This pass runs without the long-token rule so project IDs, key names, and resource names survive as evidence.

### Leak tests

A regression walk fails every `GCP_INVENTORIES` surface in turn with:

- A `502 text/html` page carrying bearer, session-cookie, and API-key canaries.
- A `403` whose `error.message` embeds a tokenised URL.
- A `500` whose message carries a long token.
- A thrown network error carrying request headers.

It asserts that no canary reaches any finding, summary, `unreadable_inventories` entry, `core_data` marker, errors array, bundle file, zip entry, or thrown error while every failure is still disclosed with its status, endpoint, and content type and length or documented fields.

A second export plants a shapeless configured token and an `AIza` key in the organization display name. It asserts that neither reaches any bundle file or zip entry, which binds the writer's second layer.

## Live smoke test

```bash
npm --prefix cli run test:gcp:live
```

The script prints a skip message and exits 0 when no credential hint exists. That means no organization or project variable, no token, no credentials file, and no ADC file.

Otherwise it runs `gcp_check_access` followed by every assess tool with a small project and asset cap.

## Limitations and manual controls

- All 23 spec controls have automated findings. These sub-aspects are not evaluated and remain manual:
  - Unused permission analysis (control 2)
  - Unused firewall rules (control 4)
  - Binary Authorization attestor configuration (control 8)
  - OS Login 2FA (control 11)
- Security Command Center is visibility only. `GCP-LOG-05` never scores a control, and the findings feed is sampled, not exhaustive.
- KMS keys are read from Cloud Asset Inventory (`cloudkms.googleapis.com/CryptoKey`) rather than per-location Cloud KMS list calls. As a result, the Cloud Asset API must be enabled and the asset feed reflects its documented freshness.
- Public exposure relies on the Cloud Asset Inventory IAM policy search at organization scope (`policy:(allUsers OR allAuthenticatedUsers)`). The search covers every asset type CAI indexes. Object ACLs on non-uniform buckets are not inspected.
- Compute `aggregatedList` responses that report `unreachables[]` or a scope with `warning.code` `UNREACHABLE` mark the inventory as partial. Every compute-backed finding then downgrades to `warn` and names the unreachable scopes.
- Effective organization policies are computed against the first inventoried project.
  - When the project cap truncates the inventory, or the project inventory itself is unreadable while a project ID is configured, org-policy findings are downgraded to `warn` and name the project inventory endpoint.
  - An unreadable constraint renders its finding `manual`.
- Security Command Center visibility (`GCP-LOG-05`) is `manual` when the source list is unreadable, and `warn` when the findings feed is unreadable or truncated. The findings count is then rendered as `null`, never as zero.
- Single-project scope (no organization ID) renders `GCP-ORG-01` and `GCP-DATA-07` as `manual` because organization metadata and access policies are organization resources.

## Endpoint reference

- `POST oauth2.googleapis.com/token` (JWT bearer, refresh token)
  - Fields read: `access_token`, `expires_in`
  - Documentation: [Service account flow](https://developers.google.com/identity/protocols/oauth2/service-account#httprest), [Refresh token](https://developers.google.com/identity/protocols/oauth2/web-server#offline)
- `GET cloudresourcemanager/v1/organizations/{org}`
  - Fields read: `name`, `displayName`
  - Documentation: [organizations.get](https://cloud.google.com/resource-manager/reference/rest/v1/organizations/get)
- `POST cloudresourcemanager/v1/projects/{p}:getEffectiveOrgPolicy`
  - Fields read: `booleanPolicy.enforced`, `listPolicy.allValues`, `listPolicy.allowedValues`, `listPolicy.deniedValues`, `restoreDefault`
  - Documentation: [getEffectiveOrgPolicy](https://cloud.google.com/resource-manager/reference/rest/v1/projects/getEffectiveOrgPolicy), [Policy](https://cloud.google.com/resource-manager/reference/rest/v1/Policy)
- `GET cloudasset/v1/{scope}:searchAllResources`
  - Fields read: `assetTypes`, `pageSize` (500 max), `pageToken`; `results[].name` (project identifier parsed from the [documented full resource name](https://cloud.google.com/asset-inventory/docs/resource-name-format)), `results[].displayName`, `results[].state`
  - Documentation: [searchAllResources](https://cloud.google.com/asset-inventory/docs/reference/rest/v1/TopLevel/searchAllResources)
- `GET cloudasset/v1/{scope}:searchAllIamPolicies`
  - Fields read: `query`, `pageSize` (500 max), `pageToken`; `results[].resource`, `results[].assetType`, `results[].policy.bindings[].role`, `results[].policy.bindings[].members[]`
  - Documentation: [searchAllIamPolicies](https://cloud.google.com/asset-inventory/docs/reference/rest/v1/TopLevel/searchAllIamPolicies), [Query syntax](https://cloud.google.com/asset-inventory/docs/searching-iam-policies#how_to_construct_a_query)
- `GET cloudasset/v1/{parent}/assets`
  - Fields read: `contentType=RESOURCE`, `assetTypes`, `pageSize` (1000 max), `pageToken`; `assets[].resource.data`
  - Documentation: [assets.list](https://cloud.google.com/asset-inventory/docs/reference/rest/v1/assets/list), [Asset types](https://cloud.google.com/asset-inventory/docs/supported-asset-types)
- `GET iam/v1/projects/{p}/serviceAccounts`
  - Fields read: `pageSize` (100 max); `accounts[].email`
  - Documentation: [serviceAccounts.list](https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts/list)
- `GET iam/v1/projects/{p}/serviceAccounts/{sa}/keys?keyTypes=USER_MANAGED`
  - Fields read: `keys[].name`, `keys[].validAfterTime`, `keys[].disabled`
  - Documentation: [keys.list](https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts.keys/list)
- `GET logging/v2/projects/{p}/settings`
  - Fields read: Readability probe only. The Settings resource is stored in the snapshot.
  - Documentation: [getSettings](https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects/getSettings)
- `GET logging/v2/projects/{p}/sinks`
  - Fields read: `sinks[].name`, `destination`, `disabled`. A sink with `disabled: true` exports nothing and does not count toward coverage.
  - Documentation: [sinks.list](https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects.sinks/list), [LogSink](https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects.sinks#LogSink)
- `GET logging/v2/projects/{p}/locations/-/buckets`
  - Fields read: `buckets[].name`, `buckets[].retentionDays`
  - Documentation: [buckets.list](https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects.locations.buckets/list)
- `POST logging/v2/entries:list`
  - Fields read: `resourceNames`, `filter`, `orderBy`, `pageSize`; `entries[]`
  - Documentation: [entries.list](https://cloud.google.com/logging/docs/reference/v2/rest/v2/entries/list)
- `GET securitycenter/v1/organizations/{org}/sources`
  - Fields read: `sources[]`
  - Documentation: [sources.list](https://cloud.google.com/security-command-center/docs/reference/rest/v1/organizations.sources/list)
- `GET securitycenter/v1/organizations/{org}/sources/-/findings`
  - Fields read: `pageSize` (1000 max); `listFindingsResults[]`
  - Documentation: [findings.list](https://cloud.google.com/security-command-center/docs/reference/rest/v1/organizations.sources.findings/list)
- `GET storage/v1/b?project={p}`
  - Fields read: `maxResults` (1000 max); `items[].name`, `items[].iamConfiguration.uniformBucketLevelAccess.enabled`, `items[].encryption.defaultKmsKeyName`
  - Documentation: [buckets.list](https://cloud.google.com/storage/docs/json_api/v1/buckets/list), [Bucket](https://cloud.google.com/storage/docs/json_api/v1/buckets)
- CryptoKey via `assets.list`
  - Fields read: `name`, `purpose`, `rotationPeriod`, `nextRotationTime`, `primary.state`
  - Documentation: [CryptoKey](https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys#CryptoKey)
- `GET compute/v1/projects/{p}/global/firewalls`
  - Fields read: `maxResults` (500 max); `items[].name`, `direction`, `disabled`, `sourceRanges[]`, `allowed[].IPProtocol`, `allowed[].ports[]`, `network`
  - Documentation: [firewalls.list](https://cloud.google.com/compute/docs/reference/rest/v1/firewalls/list)
- `GET compute/v1/projects/{p}/aggregated/subnetworks`
  - Fields read: `unreachables[]`, `items{}.warning.code`; `items{}.subnetworks[].name`, `selfLink`, `region`, `network`, `purpose`, `logConfig.enable`, `enableFlowLogs`, `privateIpGoogleAccess`
  - Documentation: [subnetworks.aggregatedList](https://cloud.google.com/compute/docs/reference/rest/v1/subnetworks/aggregatedList)
- `GET compute/v1/projects/{p}/aggregated/routers`
  - Fields read: `unreachables[]`, `items{}.warning.code`; `items{}.routers[].network`, `region`, `nats[].sourceSubnetworkIpRangesToNat`, `nats[].subnetworks[].name`
  - Documentation: [routers.aggregatedList](https://cloud.google.com/compute/docs/reference/rest/v1/routers/aggregatedList)
- `GET compute/v1/projects/{p}/aggregated/sslPolicies`
  - Fields read: `unreachables[]`, `items{}.warning.code`; `items{}.sslPolicies[].name`, `selfLink`, `region`, `minTlsVersion`, `profile`, `customFeatures[]` (kept in evidence for manual review of `CUSTOM` profiles)
  - Documentation: [sslPolicies.aggregatedList](https://cloud.google.com/compute/docs/reference/rest/v1/sslPolicies/aggregatedList), [SSL policy concepts](https://cloud.google.com/load-balancing/docs/ssl-policies-concepts)
- `GET compute/v1/projects/{p}/aggregated/targetHttpsProxies`
  - Fields read: `unreachables[]`, `items{}.warning.code`; `items{}.targetHttpsProxies[].name`, `sslPolicy`
  - Documentation: [targetHttpsProxies.aggregatedList](https://cloud.google.com/compute/docs/reference/rest/v1/targetHttpsProxies/aggregatedList)
- `GET compute/v1/projects/{p}/aggregated/backendServices`
  - Fields read: `unreachables[]`, `items{}.warning.code`; `items{}.backendServices[].name`, `loadBalancingScheme`, `protocol`, `securityPolicy`
  - Documentation: [backendServices.aggregatedList](https://cloud.google.com/compute/docs/reference/rest/v1/backendServices/aggregatedList)
- `GET compute/v1/projects/{p}/aggregated/disks`
  - Fields read: `unreachables[]`, `items{}.warning.code`; `items{}.disks[].name`, `diskEncryptionKey.kmsKeyName`
  - Documentation: [disks.aggregatedList](https://cloud.google.com/compute/docs/reference/rest/v1/disks/aggregatedList)
- `GET compute/v1/projects/{p}/aggregated/instances`
  - Fields read: `items{}.instances[].name`, `metadata.items[]`, `shieldedInstanceConfig.enableSecureBoot`, `enableVtpm`, `enableIntegrityMonitoring`, `networkInterfaces[].accessConfigs[]`, `networkInterfaces[].ipv6AccessConfigs[]`; `unreachables[]`, `items{}.warning.code`
  - Documentation: [instances.aggregatedList](https://cloud.google.com/compute/docs/reference/rest/v1/instances/aggregatedList)
- `GET compute/v1/projects/{p}`
  - Fields read: `commonInstanceMetadata.items[].key`, `commonInstanceMetadata.items[].value` (`enable-oslogin`, `serial-port-enable`)
  - Documentation: [projects.get](https://cloud.google.com/compute/docs/reference/rest/v1/projects/get), [OS Login metadata](https://cloud.google.com/compute/docs/oslogin/set-up-oslogin), [Serial console metadata](https://cloud.google.com/compute/docs/troubleshooting/troubleshooting-using-serial-console)
- `GET dns/v1/projects/{p}/managedZones`
  - Fields read: `managedZones[].name`, `visibility`, `dnssecConfig.state`, `dnssecConfig.defaultKeySpecs[].algorithm`
  - Documentation: [managedZones.list](https://cloud.google.com/dns/docs/reference/rest/v1/managedZones/list)
- `GET apikeys/v2/projects/{p}/locations/global/keys`
  - Fields read: `keys[].name`, `displayName`, `deleteTime`, `restrictions.apiTargets[]`, `restrictions.browserKeyRestrictions`, `serverKeyRestrictions`, `androidKeyRestrictions`, `iosKeyRestrictions`
  - Documentation: [keys.list](https://cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys/list)
- `GET accesscontextmanager/v1/accessPolicies?parent=organizations/{org}`
  - Fields read: `accessPolicies[].name`
  - Documentation: [accessPolicies.list](https://cloud.google.com/access-context-manager/docs/reference/rest/v1/accessPolicies/list)
- `GET accesscontextmanager/v1/{policy}/servicePerimeters`
  - Fields read: `servicePerimeters[].name`, `status.resources[]`, `status.restrictedServices[]`, `spec`
  - Documentation: [servicePerimeters.list](https://cloud.google.com/access-context-manager/docs/reference/rest/v1/accessPolicies.servicePerimeters/list)
- `GET binaryauthorization/v1/projects/{p}/policy`
  - Fields read: `evaluationMode` and `enforcementMode` on `defaultAdmissionRule` and on every entry of `clusterAdmissionRules`, `kubernetesNamespaceAdmissionRules`, `kubernetesServiceAccountAdmissionRules`, `istioServiceIdentityAdmissionRules`
  - Documentation: [projects.getPolicy](https://cloud.google.com/binary-authorization/docs/reference/rest/v1/projects/getPolicy)
