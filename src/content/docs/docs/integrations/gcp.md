---
title: Google Cloud Platform
description: Read-only GCP security inspector covering IAM, logging, organization guardrails, data protection, and network security with multi-framework mappings.
---

The GCP integration implements the `gcp-sec-inspector` spec as native grclanker tools. It inspects an organization (or a single project) through documented Google Cloud REST APIs, scores 23 controls, and maps every finding to FedRAMP, CMMC 2.0, SOC 2, CIS GCP, PCI-DSS, DISA STIG, IRAP, and ISMAP. Every request is read-only.

## What it inspects

- IAM: privileged bindings, service account key age and count, cross-project service account access, default service account privilege
- Logging and detection: Admin Activity and Data Access audit visibility, log sinks, log bucket retention, Security Command Center visibility (reported for context, never scored)
- Organization guardrails: domain-restricted sharing, service account key constraints, serial port and Shielded VM policies, OS Login, Binary Authorization, instance hardening
- Data protection: uniform bucket-level access, public IAM exposure, KMS rotation, CMEK on buckets and disks, Cloud DNS DNSSEC, API key restrictions, VPC Service Controls
- Network security: internet-open firewall rules on administrative ports, VPC flow logs, Private Google Access, Cloud NAT and external IPs, load balancer SSL policies, Cloud Armor coverage

## Setup and authentication

### Scope

| Variable | Purpose |
|----------|---------|
| `GCP_ORGANIZATION_ID` (alias `GCP_ORG_ID`) | Organization to inventory. Projects are enumerated through Cloud Asset Inventory under this organization. |
| `GCP_PROJECT_ID` or `GOOGLE_CLOUD_PROJECT` | Single-project fallback when no organization is configured, or a focus project for effective org policy reads. |

Every tool also accepts `organization_id` and `project_id` arguments that take precedence over the environment.

### Credentials

The credential chain is evaluated in this order:

1. `access_token` argument, then `GCP_ACCESS_TOKEN` (also `GOOGLE_OAUTH_ACCESS_TOKEN` or `GOOGLE_ACCESS_TOKEN`)
2. `credentials_file` argument, then `GCP_CREDENTIALS_FILE`, then `GOOGLE_APPLICATION_CREDENTIALS`
3. The Application Default Credentials file (`~/.config/gcloud/application_default_credentials.json`, honoring `CLOUDSDK_CONFIG`)
4. `gcloud auth print-access-token`

Credential files may be a service account key (`type: service_account`) or an authorized user ADC file (`type: authorized_user`). Service account keys are exchanged with the documented OAuth 2.0 service account JWT flow: an RS256 assertion signed with `node:crypto` and posted to the key's `token_uri` with `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` and the `https://www.googleapis.com/auth/cloud-platform` scope. Authorized user files use the refresh token grant. No SDK or extra dependency is required.

```bash
export GCP_ORGANIZATION_ID=123456789012
export GCP_CREDENTIALS_FILE=/path/to/audit-sa-key.json
```

### Required IAM roles

Grant the audit principal at the organization node so every project is covered:

| Role | Surfaces |
|------|----------|
| `roles/cloudasset.viewer` | Project inventory, IAM policy search, CryptoKey assets |
| `roles/iam.securityReviewer` | Service accounts and keys |
| `roles/logging.viewer` | Audit entries, sinks, log buckets, logging settings |
| `roles/orgpolicy.policyViewer` | Effective organization policies |
| `roles/resourcemanager.organizationViewer` | Organization metadata |
| `roles/compute.viewer` | Firewalls, subnetworks, routers, instances, disks, SSL policies, proxies, backend services, project metadata |
| A role carrying `storage.buckets.list` (a custom read-only role is recommended) | Bucket inventory |
| `roles/dns.reader` | Managed zones |
| `roles/serviceusage.apiKeysViewer` | API keys |
| `roles/accesscontextmanager.policyReader` | Access policies and service perimeters |
| `roles/binaryauthorization.policyViewer` | Binary Authorization policy |
| `roles/securitycenter.findingsViewer` | Security Command Center visibility (optional) |

### Enabled APIs

The projects you inventory must have the relevant APIs enabled: `cloudasset`, `cloudresourcemanager`, `iam`, `logging`, `compute`, `storage`, `dns`, `apikeys`, `accesscontextmanager`, `binaryauthorization`, `cloudkms`, and optionally `securitycenter`. When an API is disabled in a project the dependent finding is rendered `manual` for that project, never `pass`.

## Tools

| Tool | Purpose | Notable arguments |
|------|---------|-------------------|
| `gcp_check_access` | Probe the core surfaces and report which are readable | `organization_id`, `project_id`, `access_token`, `credentials_file` |
| `gcp_assess_identity` | Controls 1, 2, 13, 14 | `stale_days` (90), `max_keys` (200), `project_limit` |
| `gcp_assess_logging_detection` | Control 5 plus Security Command Center visibility | `max_findings` (200), `project_limit` |
| `gcp_assess_org_guardrails` | Controls 6, 8, 11, 12, 23 | `max_assets` (2000), `project_limit` |
| `gcp_assess_data_protection` | Controls 3, 7, 15, 16, 17, 20, 21 | `max_assets` (2000), `project_limit` |
| `gcp_assess_network_security` | Controls 4, 9, 10, 18, 19, 22 | `max_assets` (2000), `project_limit` |
| `gcp_export_audit_bundle` | Run everything and write the shared bundle layout | `output_dir` (`./export/gcp`) plus every option above |

`project_limit` (alias `max_projects`, default 20) caps how many projects are inventoried. When the cap truncates the inventory, every dependent finding is downgraded to `warn` with seen and total counts, so a partial view can never pass.

## Status semantics

| Status | Meaning |
|--------|---------|
| `pass` | Every inventoried resource satisfied the check and the inventory was complete (no cap, no truncated page, no denied project). |
| `warn` | A violation on a lower-impact check, a partial inventory (project cap, truncated page, denied or API-disabled project), items missing a required date, or a dry-run or unresolved configuration. |
| `fail` | A documented violation was found in a complete inventory. |
| `manual` | The endpoint was forbidden or errored, the inventory was empty where emptiness is not compliant by intent, the API is disabled, or the control is outside the configured scope. The summary names the cause and the evidence to collect. |

Emptiness passes only for two findings: `GCP-IAM-02` (no user-managed keys across a non-empty set of service accounts) and `GCP-DATA-06` (no API keys in projects where the API Keys API answered). `GCP-DATA-07` fails on emptiness (no access policy means no perimeter). Every other finding renders `manual` on an empty inventory.

## Control coverage

| # | Control | Tool | Finding | Semantics |
|---|---------|------|---------|-----------|
| 1 | Service Account Key Rotation | `gcp_assess_identity` | `GCP-IAM-02`, `GCP-IAM-03` | fail when a user-managed key exceeds `stale_days`; undated keys warn; user-managed keys present warn |
| 2 | Overprivileged IAM Roles | `gcp_assess_identity` | `GCP-IAM-01` | fail on owner/editor-style bindings; unused permission analysis is not evaluated |
| 3 | Public Resource Exposure | `gcp_assess_data_protection` | `GCP-DATA-02` | fail when any IAM policy in scope binds `allUsers` or `allAuthenticatedUsers` |
| 4 | VPC Firewall Rules | `gcp_assess_network_security` | `GCP-NET-01` | fail on enabled ingress rules from `0.0.0.0/0` or `::/0` allowing TCP 22 or 3389 (or all ports) |
| 5 | Audit Logging Configuration | `gcp_assess_logging_detection` | `GCP-LOG-01` to `GCP-LOG-04` | Admin Activity entries (warn), Data Access entries (fail), sinks (fail), configurable log bucket retention below 90 days (fail); `GCP-LOG-05` is visibility only |
| 6 | Organization Policy Constraints | `gcp_assess_org_guardrails` | `GCP-ORG-01` to `GCP-ORG-04` | organization visibility, `iam.allowedPolicyMemberDomains`, `iam.disableServiceAccountKeyCreation`, `iam.disableServiceAccountKeyUpload` |
| 7 | KMS Key Rotation | `gcp_assess_data_protection` | `GCP-DATA-03` | fail when an `ENCRYPT_DECRYPT` key lacks `rotationPeriod` or `nextRotationTime`, or rotates slower than 365 days; overdue rotation warns |
| 8 | Binary Authorization | `gcp_assess_org_guardrails` | `GCP-ORG-07` | fail unless `defaultAdmissionRule.evaluationMode` is `REQUIRE_ATTESTATION` or `ALWAYS_DENY`; dry-run enforcement warns; attestors are not evaluated |
| 9 | VPC Flow Logs | `gcp_assess_network_security` | `GCP-NET-02` | fail when an eligible subnetwork lacks `logConfig.enable=true` |
| 10 | Cloud NAT Configuration | `gcp_assess_network_security` | `GCP-NET-04` | warn when a subnetwork region has no Cloud Router NAT or instances carry external access configs |
| 11 | OS Login Enforcement | `gcp_assess_org_guardrails` | `GCP-ORG-06` | pass when `constraints/compute.requireOsLogin` is enforced with no instance override, or every project sets `enable-oslogin=TRUE`; 2FA is not evaluated |
| 12 | Serial Port Disabled | `gcp_assess_org_guardrails` | `GCP-ORG-05`, `GCP-ORG-08` | org policy `compute.disableSerialPortAccess` plus instance `serial-port-enable` metadata |
| 13 | Default Service Account Usage | `gcp_assess_identity` | `GCP-IAM-05` | fail when a default compute or App Engine service account holds an owner/editor-style role |
| 14 | Cross-Project Access | `gcp_assess_identity` | `GCP-IAM-04` | warn on service account bindings that cross project boundaries |
| 15 | Uniform Bucket-Level Access | `gcp_assess_data_protection` | `GCP-DATA-01` | fail when `iamConfiguration.uniformBucketLevelAccess.enabled` is not true |
| 16 | Customer-Managed Encryption Keys | `gcp_assess_data_protection` | `GCP-DATA-04` | warn when buckets lack `encryption.defaultKmsKeyName` or disks lack `diskEncryptionKey.kmsKeyName` |
| 17 | DNS Security (DNSSEC) | `gcp_assess_data_protection` | `GCP-DATA-05` | fail when a public managed zone has `dnssecConfig.state` other than `on` or signs with `rsasha1` |
| 18 | Load Balancer SSL Policies | `gcp_assess_network_security` | `GCP-NET-05` | fail when an HTTPS proxy has no SSL policy, `minTlsVersion` below `TLS_1_2`, or the `COMPATIBLE` profile; `CUSTOM` warns |
| 19 | Cloud Armor WAF | `gcp_assess_network_security` | `GCP-NET-06` | warn when an external HTTP(S) backend service has no `securityPolicy` |
| 20 | API Key Restrictions | `gcp_assess_data_protection` | `GCP-DATA-06` | fail when a key lacks `restrictions.apiTargets` or an application restriction |
| 21 | VPC Service Controls | `gcp_assess_data_protection` | `GCP-DATA-07` | fail when no access policy exists; warn when no perimeter is enforced with resources and restricted services |
| 22 | Private Google Access | `gcp_assess_network_security` | `GCP-NET-03` | warn when an eligible subnetwork lacks `privateIpGoogleAccess=true` |
| 23 | Shielded VM Configuration | `gcp_assess_org_guardrails` | `GCP-ORG-05`, `GCP-ORG-08` | org policy `compute.requireShieldedVm` plus instance `shieldedInstanceConfig` (Secure Boot, vTPM, integrity monitoring) |

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
  core_data/            raw snapshots with secrets redacted
  analysis/             findings.json, category_summaries.json, one JSON and markdown per category
  compliance/           executive_summary.md, unified_compliance_matrix.md, frameworks/<framework>.md
  _errors.log           only when collection partially failed
<org-or-project>-audit.zip
```

Reruns allocate `-2`, `-3`, and so on; the zip name derives from the allocated directory so nothing is overwritten. Output paths are resolved with traversal and symlink-parent protection.

## Live smoke test

```bash
npm --prefix cli run test:gcp:live
```

The script prints a skip message and exits 0 when no credential hint exists (no organization or project variable, no token, no credentials file, no ADC file). Otherwise it runs `gcp_check_access` followed by every assess tool with a small project and asset cap.

## Limitations and manual controls

- All 23 spec controls have automated findings. Sub-aspects that are not evaluated and remain manual: unused permission analysis (control 2), unused firewall rules (control 4), Binary Authorization attestor configuration (control 8), and OS Login 2FA (control 11).
- Security Command Center is visibility only. `GCP-LOG-05` never scores a control and the findings feed is sampled, not exhaustive.
- KMS keys are read from Cloud Asset Inventory (`cloudkms.googleapis.com/CryptoKey`) rather than per-location Cloud KMS list calls, so the Cloud Asset API must be enabled and the asset feed reflects its documented freshness.
- Public exposure relies on the Cloud Asset Inventory IAM policy search at organization scope (`policy:(allUsers OR allAuthenticatedUsers)`), which covers every asset type CAI indexes; object ACLs on non-uniform buckets are not inspected.
- Effective organization policies are computed against the first inventoried project. When the project cap truncates the inventory, org-policy findings are downgraded to `warn`.
- Single-project scope (no organization ID) renders `GCP-ORG-01` and `GCP-DATA-07` as `manual` because organization metadata and access policies are organization resources.

## Endpoint reference

| Endpoint | Documentation | Fields read |
|----------|---------------|-------------|
| `POST oauth2.googleapis.com/token` (JWT bearer, refresh token) | [Service account flow](https://developers.google.com/identity/protocols/oauth2/service-account#httprest), [Refresh token](https://developers.google.com/identity/protocols/oauth2/web-server#offline) | `access_token`, `expires_in` |
| `GET cloudresourcemanager/v1/organizations/{org}` | [organizations.get](https://cloud.google.com/resource-manager/reference/rest/v1/organizations/get) | `name`, `displayName` |
| `POST cloudresourcemanager/v1/projects/{p}:getEffectiveOrgPolicy` | [getEffectiveOrgPolicy](https://cloud.google.com/resource-manager/reference/rest/v1/projects/getEffectiveOrgPolicy), [Policy](https://cloud.google.com/resource-manager/reference/rest/v1/Policy) | `booleanPolicy.enforced`, `listPolicy.allValues`, `listPolicy.allowedValues`, `listPolicy.deniedValues`, `restoreDefault` |
| `GET cloudasset/v1/{scope}:searchAllResources` | [searchAllResources](https://cloud.google.com/asset-inventory/docs/reference/rest/v1/TopLevel/searchAllResources) | `assetTypes`, `pageSize` (500 max), `pageToken`; `results[].name`, `results[].displayName`, `results[].state` |
| `GET cloudasset/v1/{scope}:searchAllIamPolicies` | [searchAllIamPolicies](https://cloud.google.com/asset-inventory/docs/reference/rest/v1/TopLevel/searchAllIamPolicies), [Query syntax](https://cloud.google.com/asset-inventory/docs/searching-iam-policies#how_to_construct_a_query) | `query`, `pageSize` (500 max), `pageToken`; `results[].resource`, `results[].assetType`, `results[].policy.bindings[].role`, `results[].policy.bindings[].members[]` |
| `GET cloudasset/v1/{parent}/assets` | [assets.list](https://cloud.google.com/asset-inventory/docs/reference/rest/v1/assets/list), [Asset types](https://cloud.google.com/asset-inventory/docs/supported-asset-types) | `contentType=RESOURCE`, `assetTypes`, `pageSize` (1000 max), `pageToken`; `assets[].resource.data` |
| `GET iam/v1/projects/{p}/serviceAccounts` | [serviceAccounts.list](https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts/list) | `pageSize` (100 max); `accounts[].email` |
| `GET iam/v1/projects/{p}/serviceAccounts/{sa}/keys?keyTypes=USER_MANAGED` | [keys.list](https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts.keys/list) | `keys[].name`, `keys[].validAfterTime`, `keys[].disabled` |
| `GET logging/v2/projects/{p}/settings` | [getSettings](https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects/getSettings) | readability probe only; the Settings resource is stored in the snapshot |
| `GET logging/v2/projects/{p}/sinks` | [sinks.list](https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects.sinks/list) | `sinks[]` (presence per project) |
| `GET logging/v2/projects/{p}/locations/-/buckets` | [buckets.list](https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects.locations.buckets/list) | `buckets[].name`, `buckets[].retentionDays` |
| `POST logging/v2/entries:list` | [entries.list](https://cloud.google.com/logging/docs/reference/v2/rest/v2/entries/list) | `resourceNames`, `filter`, `orderBy`, `pageSize`; `entries[]` |
| `GET securitycenter/v1/organizations/{org}/sources` | [sources.list](https://cloud.google.com/security-command-center/docs/reference/rest/v1/organizations.sources/list) | `sources[]` |
| `GET securitycenter/v1/organizations/{org}/sources/-/findings` | [findings.list](https://cloud.google.com/security-command-center/docs/reference/rest/v1/organizations.sources.findings/list) | `pageSize` (1000 max); `listFindingsResults[]` |
| `GET storage/v1/b?project={p}` | [buckets.list](https://cloud.google.com/storage/docs/json_api/v1/buckets/list), [Bucket](https://cloud.google.com/storage/docs/json_api/v1/buckets) | `maxResults` (1000 max); `items[].name`, `items[].iamConfiguration.uniformBucketLevelAccess.enabled`, `items[].encryption.defaultKmsKeyName` |
| CryptoKey via `assets.list` | [CryptoKey](https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys#CryptoKey) | `name`, `purpose`, `rotationPeriod`, `nextRotationTime`, `primary.state` |
| `GET compute/v1/projects/{p}/global/firewalls` | [firewalls.list](https://cloud.google.com/compute/docs/reference/rest/v1/firewalls/list) | `maxResults` (500 max); `items[].name`, `direction`, `disabled`, `sourceRanges[]`, `allowed[].IPProtocol`, `allowed[].ports[]`, `network` |
| `GET compute/v1/projects/{p}/aggregated/subnetworks` | [subnetworks.aggregatedList](https://cloud.google.com/compute/docs/reference/rest/v1/subnetworks/aggregatedList) | `items{}.subnetworks[].name`, `region`, `network`, `purpose`, `logConfig.enable`, `privateIpGoogleAccess` |
| `GET compute/v1/projects/{p}/aggregated/routers` | [routers.aggregatedList](https://cloud.google.com/compute/docs/reference/rest/v1/routers/aggregatedList) | `items{}.routers[].network`, `region`, `nats[]` |
| `GET compute/v1/projects/{p}/aggregated/sslPolicies` | [sslPolicies.aggregatedList](https://cloud.google.com/compute/docs/reference/rest/v1/sslPolicies/aggregatedList), [SSL policy concepts](https://cloud.google.com/load-balancing/docs/ssl-policies-concepts) | `items{}.sslPolicies[].name`, `minTlsVersion`, `profile` |
| `GET compute/v1/projects/{p}/aggregated/targetHttpsProxies` | [targetHttpsProxies.aggregatedList](https://cloud.google.com/compute/docs/reference/rest/v1/targetHttpsProxies/aggregatedList) | `items{}.targetHttpsProxies[].name`, `sslPolicy` |
| `GET compute/v1/projects/{p}/aggregated/backendServices` | [backendServices.aggregatedList](https://cloud.google.com/compute/docs/reference/rest/v1/backendServices/aggregatedList) | `items{}.backendServices[].name`, `loadBalancingScheme`, `protocol`, `securityPolicy` |
| `GET compute/v1/projects/{p}/aggregated/disks` | [disks.aggregatedList](https://cloud.google.com/compute/docs/reference/rest/v1/disks/aggregatedList) | `items{}.disks[].name`, `diskEncryptionKey.kmsKeyName` |
| `GET compute/v1/projects/{p}/aggregated/instances` | [instances.aggregatedList](https://cloud.google.com/compute/docs/reference/rest/v1/instances/aggregatedList) | `items{}.instances[].name`, `metadata.items[]`, `shieldedInstanceConfig.enableSecureBoot`, `enableVtpm`, `enableIntegrityMonitoring`, `networkInterfaces[].accessConfigs[]` |
| `GET compute/v1/projects/{p}` | [projects.get](https://cloud.google.com/compute/docs/reference/rest/v1/projects/get), [OS Login metadata](https://cloud.google.com/compute/docs/oslogin/set-up-oslogin), [Serial console metadata](https://cloud.google.com/compute/docs/troubleshooting/troubleshooting-using-serial-console) | `commonInstanceMetadata.items[].key`, `commonInstanceMetadata.items[].value` (`enable-oslogin`, `serial-port-enable`) |
| `GET dns/v1/projects/{p}/managedZones` | [managedZones.list](https://cloud.google.com/dns/docs/reference/rest/v1/managedZones/list) | `managedZones[].name`, `visibility`, `dnssecConfig.state`, `dnssecConfig.defaultKeySpecs[].algorithm` |
| `GET apikeys/v2/projects/{p}/locations/global/keys` | [keys.list](https://cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys/list) | `keys[].name`, `displayName`, `deleteTime`, `restrictions.apiTargets[]`, `restrictions.browserKeyRestrictions`, `serverKeyRestrictions`, `androidKeyRestrictions`, `iosKeyRestrictions` |
| `GET accesscontextmanager/v1/accessPolicies?parent=organizations/{org}` | [accessPolicies.list](https://cloud.google.com/access-context-manager/docs/reference/rest/v1/accessPolicies/list) | `accessPolicies[].name` |
| `GET accesscontextmanager/v1/{policy}/servicePerimeters` | [servicePerimeters.list](https://cloud.google.com/access-context-manager/docs/reference/rest/v1/accessPolicies.servicePerimeters/list) | `servicePerimeters[].name`, `status.resources[]`, `status.restrictedServices[]`, `spec` |
| `GET binaryauthorization/v1/projects/{p}/policy` | [projects.getPolicy](https://cloud.google.com/binary-authorization/docs/reference/rest/v1/projects/getPolicy) | `defaultAdmissionRule.evaluationMode`, `defaultAdmissionRule.enforcementMode` |
