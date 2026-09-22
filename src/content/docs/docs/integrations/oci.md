---
title: "Oracle Cloud Infrastructure"
description: "Read-only OCI security inspector: IAM, Cloud Guard, audit retention, networking, bastions, vault keys, Object Storage, IMDSv2, and volume encryption, mapped to eight frameworks."
---

# Oracle Cloud Infrastructure (OCI)

The OCI tool family inspects a tenancy read-only through the official OCI CLI and produces framework-mapped findings. It implements the `specs/oci-sec-inspector.spec.md` control set (23 of 25 controls automated or explicitly manual across 21 findings, see the coverage table).

## What it inspects

- Identity: password policy, console MFA, API key / customer secret key / auth token age, broad IAM policies, compartment hierarchy
- Logging and detection: Cloud Guard enablement, targets, open problems, responder recipes, audit log retention, audit event visibility, Events rules for identity, policy, and network changes
- Tenancy guardrails: security list and NSG world ingress to sensitive ports, internet gateways, bastion TTL / CIDR allow lists and active sessions, vault key strength (algorithm, length, curve) and rotation, bucket public access and pre-authenticated requests
- Compute and storage: IMDSv2-only instances, customer-managed keys on block and boot volumes

## Setup and authentication

1. Install the OCI CLI (`oci`) and confirm `oci --version` works. Installation guide: https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/cliinstall.htm
2. Configure an API-key profile in `~/.oci/config` (`tenancy`, `user`, `fingerprint`, `key_file`, `region`). Config file reference: https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm
3. Optionally set `OCI_CONFIG_FILE`, `OCI_CLI_PROFILE`, `OCI_REGION`, `OCI_TENANCY_OCID`, or `OCI_COMPARTMENT_OCID`; tool arguments override environment, which overrides the config profile.

Only API-key profiles are supported in this release. Session token (`security_token_file`), instance principal, resource principal, and delegation token modes are deferred (see Limitations).

Recommended read-only IAM policy for the inspecting group:

```
Allow group SecurityInspectors to inspect all-resources in tenancy
Allow group SecurityInspectors to read audit-events in tenancy
Allow group SecurityInspectors to read cloud-guard-family in tenancy
Allow group SecurityInspectors to read bastion-family in tenancy
Allow group SecurityInspectors to read vaults in tenancy
Allow group SecurityInspectors to read keys in tenancy
Allow group SecurityInspectors to read buckets in tenancy
Allow group SecurityInspectors to read volume-family in tenancy
Allow group SecurityInspectors to read instance-family in tenancy
```

A surface the principal cannot read renders its control as MANUAL with the failing command in the summary; it never passes.

## Tools

| Tool | Purpose | Key arguments |
|------|---------|---------------|
| `oci_check_access` | Probes ten read surfaces (compartments, users, authentication policy, audit configuration, audit events, Cloud Guard configuration, security lists, vaults, Object Storage, compute) | `profile`, `region`, `tenancy_ocid`, `compartment_ocid` |
| `oci_assess_identity` | Findings OCI-IAM-01..06 | `stale_days` (90), `max_keys` (200), `max_policies` (500), `max_compartments` (25) |
| `oci_assess_logging_detection` | Findings OCI-LOG-01..06 | `lookback_days` (7), `max_compartments` |
| `oci_assess_tenancy_guardrails` | Findings OCI-GRD-01..06 | `max_compartments`, `max_buckets` (100), `max_keys` (200, ENABLED vault keys fetched with `kms management key get`) |
| `oci_assess_compute_and_storage` | Findings OCI-CMP-01..03 | `max_compartments` |
| `oci_export_audit_bundle` | Runs everything and writes the evidence bundle plus zip | `output_dir` (`./export/oci`) plus the arguments above |

## Status semantics

- `pass`: judged from a readable, complete inventory using documented fields.
- `warn`: judged, but the view is incomplete (compartment or item cap hit, a compartment denied, undated items, failed sub-reads such as a denied `key get`) or a lower-risk issue exists.
- `fail`: a documented field contradicts the control.
- `manual`: the surface was unreadable (for example the documented `NotAuthorizedOrNotFound` response), out of scope (nothing to inspect), or the setting is not exposed by the API. Never treat manual as compliant.

Compartment-scoped resources (policies, event rules, networking, bastions, vaults, buckets, instances, volumes) are listed per accessible compartment up to `max_compartments`; hitting the cap or losing a compartment withholds `pass` and reports seen versus total counts. A demoted summary names the CLI command that failed and the compartments it could not read (for example `Partial view: network security-list list denied or unreadable in 1 compartment(s): prod`), and a finding that reads more than one inventory demotes when any of them is incomplete, even if the failure is also listed in the errors array.

## Control coverage

| # | Spec control | Tool | Finding | Semantics |
|---|--------------|------|---------|-----------|
| 1 | IAM password policy | identity | OCI-IAM-01 | pass when `minimumPasswordLength` >= 14 and all four character classes are required; expiration is split into OCI-IAM-06 |
| 1 | Password expiration | identity | OCI-IAM-06 | always manual: the IAM `PasswordPolicy` datatype has no expiration field |
| 2 | MFA enforcement | identity | OCI-IAM-02 | pass when every ACTIVE console-capable user has `isMfaActivated=true`; no users or no console users is manual |
| 3, 4, 5 | API key, customer secret key, auth token rotation | identity | OCI-IAM-03 | fail on any ACTIVE credential older than `stale_days`; undated items or cap hit at most warn (folded, per-kind evidence) |
| 6 | Policy least privilege | identity | OCI-IAM-04 | warn on tenancy-wide `manage` statements; empty policy list is manual |
| 7 | Compartment structure | identity | OCI-IAM-05 | fail when no ACTIVE non-root compartment exists |
| 8 | Cloud Guard enabled | logging | OCI-LOG-01 | pass when configuration `status=ENABLED` and at least one ACTIVE target |
| 9 | Cloud Guard open problems | logging | OCI-LOG-02 | pass only when Cloud Guard is ENABLED and no OPEN problems; CRITICAL/HIGH `riskLevel` fails |
| 10 | Responder recipe activation | logging | OCI-LOG-03 | pass when an ACTIVE recipe has a rule with `details.isEnabled=true` |
| 11 | Audit log retention | logging | OCI-LOG-06 | pass when `retentionPeriodDays` >= 365 |
| 12 | Event rules | logging | OCI-LOG-05 | pass when an enabled ACTIVE rule condition references identity, policy, or network event types; empty fails |
| 13 | Security list ingress | guardrails | OCI-GRD-01 | fail when a rule allows `0.0.0.0/0` or `::/0` to ports 22, 3389, 1433, 3306, 5432 (protocol 6 or all, range containment) |
| 14 | NSG rules | guardrails | OCI-GRD-02 | same test on INGRESS `SecurityRule`s with `isValid` recorded per rule; no NSGs passes only beside a complete, readable security list inventory (a security list compartment denied or capped demotes to warn and names it; none readable is manual) |
| 15 | Internet gateway exposure | guardrails | OCI-GRD-03 | warn when any gateway has `isEnabled=true`; no gateways passes only beside a complete, readable security list inventory (same demotion as OCI-GRD-02) |
| 16, 17 | Bastion controls and sessions | guardrails | OCI-GRD-04 | fail when a bastion combines a world allow list (`0.0.0.0/0` or `::/0`) with TTL > 3h or when an ACTIVE session is older than 8h; warn on TTL > 3h or an empty/world allow list alone (folded) |
| 18, 19 | Vault key rotation and algorithm strength | guardrails | OCI-GRD-05 | fail when the newest ENABLED key version is older than 365 days, or `Key.keyShape` (from `kms management key get`) is AES below 32 bytes (AES-256), RSA below 512 bytes (RSA-4096), ECDSA without a documented `curveId` (NIST_P256, NIST_P384, NIST_P521 all pass), or outside the AES/RSA/ECDSA enum; a denied key get caps the verdict at warn (some keys read) or manual (none read) (folded) |
| 20, 21 | Bucket public access and PARs | guardrails | OCI-GRD-06 | fail on `publicAccessType` other than `NoPublicAccess`; PARs expiring more than 30 days out warn (folded) |
| 22 | Block and boot volume CMK | compute and storage | OCI-CMP-02, OCI-CMP-03 | fail when a live volume has no `kmsKeyId` |
| 23 | IMDSv2 | compute and storage | OCI-CMP-01 | fail when a live instance lacks `instanceOptions.areLegacyImdsEndpointsDisabled=true` |
| 24 | Budget alert rules | not shipped | none | deferred |
| 25 | OS Management patching | not shipped | none | deferred |

The audit event visibility finding OCI-LOG-04 is supporting evidence, not a spec control.

## Framework mappings

Every finding carries the spec mapping table values for FedRAMP, CMMC L2, SOC 2, CIS OCI, PCI-DSS, DISA STIG, IRAP ISM, and ISMAP. The bundle writes one report per framework under `compliance/`.

## Evidence bundle

`oci_export_audit_bundle` writes `<tenancy>-<region>-audit/` under the output root (reruns allocate `-2`, `-3`, never overwrite) and a zip named after that directory:

- `QUICK_REFERENCE.md`, `README.md`, `metadata.json`
- `core_data/`: `access.json`, `compartments.json` (no credentials)
- `analysis/`: `findings.json`, one JSON per assessment, `summary.md`
- `compliance/`: `executive_summary.md`, `unified_compliance_matrix.md`, one report per framework
- `_errors.log`: only when collection partially failed

Secret hygiene: nothing credential-bearing is written. Findings redact sensitive fields at creation (`accessUri`, `keyValue`, `token`, `key`, `secret*`, `*password*`, `privateKey`, `keyMaterial`, `wrappedKey`, `plaintext`, `ciphertext`, `authorization`, `userData`, and similar names keep the field name with a `[redacted]` marker), PEM blocks, `/p/<token>/n/` PAR URIs, the OCI request-signing `Signature` header parameter list, standalone `keyId`/`signingKeyId`/`signature` values in assignment or JSON-colon form, and `token`, `secret`, `password`, `pass_phrase`, `key_file`, and `access_uri` assignments are scrubbed from every string including CLI error text (KMS `kmsKeyId` values and `--key-id` arguments are left readable because verdicts depend on them), `core_data/compartments.json` is projected to `id`, `compartmentId`, `name`, `lifecycleState`, and the config file path is replaced with `[redacted]` in `metadata.json` and `core_data/access.json`. A regression test writes a bundle from fixtures carrying `FAKE_` secrets in every collected object and asserts none appears in any bundle file or zip entry.

Cap exits: every capped loop (`max_compartments`, `max_keys`, `max_policies`, `max_buckets`) records the cap hit, reports seen versus total in the summary and evidence (`credentials_total` is `null` when the credential cap stopped enumeration), and withholds `pass`.

CLI error text: when an `oci` command fails, its stderr and stdout are never echoed into a finding, an errors array, or a bundle file. A documented `ServiceError` block contributes only its `status`, `code`, `opc-request-id`, and scrubbed `message` (for example `oci iam user list exited 1 with ServiceError status=404 code=NotAuthorizedOrNotFound opc-request-id=... message=...`); anything else (an HTML gateway page, a traceback, plain text) is described by the command words, exit code, and byte counts (`oci iam user list exited 1; 236 bytes of stderr and 0 bytes of stdout withheld (no documented ServiceError block)`). Every error string passes through `scrubErrorText` once, where it is created and before the message cap is applied; it drops embedded URL queries and fragments, Bearer, Basic, cookie, api key, session, access, refresh, and id token, client secret, password, `Signature`, and `keyId` values, and any unlabeled token of 16 or more characters that contains a digit or a `+` in free text, while OCIDs, `kmsKeyId`, `masterKeyId`, and `--key-id` stay readable. When the bundle is written, the sink applies a second, data-mode layer (`redactSensitiveText`: the same patterns with the long-token rule off) to every finding summary and errors array entry, so identifiers such as a compartment named `prod-us-east-2026` survive in `_errors.log` and the executive summary while `token=` shapes are still redacted there. An `opc-request-id` value is disclosed only when it matches a documented layout (the CLI's `32hex(/32hex){0,2}` form or the UUID form from `usingapi.htm`); anything else behind the label is dropped. Residuals: a value in a documented layout that is deliberately placed directly behind an `opc-request-id=` label stays readable (no OCI secret has the bare 32-hex shape; the identity-domain OAuth client secret has the UUID shape), which is exfiltration rather than accidental echo; a 16-plus character token with no digit or `+` is not caught by the long-token rule; the tool output's errors arrays and summary statuses carry compartment names (and, in one informational line, vault display names) verbatim as tenant data, with the sink redacting assignment shapes inside them for the bundle.

## Live smoke

```
npm --prefix cli run test:oci:live
```

Skips with exit 0 when no `~/.oci/config`, `OCI_CONFIG_FILE`, or `OCI_TENANCY_OCID` is present or the `oci` binary is missing; otherwise runs the access check and every assess tool against the configured profile.

## Limitations and manual controls

- Password expiration (control 1) is manual: not exposed by the IAM `PasswordPolicy` datatype.
- Vault key strength (control 19) is judged from `Key.keyShape.length` in bytes (AES 16/24/32, RSA 256/384/512, ECDSA 32/48/66 per the `KeyShape` datatype). ECDSA keys pass on any documented `curveId` because the spec control names only the AES-256 and RSA-4096 floors; tighten `judgeKeyShape` if your baseline requires P-384 or above.
- Controls 24 (budgets and alert rules) and 25 (OS Management Hub patching) are deferred.
- Auth modes other than API-key profiles are deferred. Controls 3-5, 16-17, 18-19, and 20-21 stay folded into one finding each with per-kind evidence.
- SARIF and JSON-CLI output formats from the spec are out of scope; findings are available as JSON in `analysis/findings.json`.

## Surfaces

Every CLI command and output field is cited in `OCI_SURFACE_DOCS` in `cli/extensions/grc-tools/oci.ts`. Summary:

| Command | Fields read | Reference |
|---------|-------------|-----------|
| `oci iam compartment list --compartment-id-in-subtree true --access-level ACCESSIBLE --include-root true --all` | `id`, `compartmentId`, `name`, `lifecycleState` | [ListCompartments](https://docs.oracle.com/en-us/iaas/api/#/en/identity/20160918/Compartment/ListCompartments) |
| `oci iam user list --all` | `id`, `name`, `lifecycleState`, `isMfaActivated`, `capabilities.canUseConsolePassword` | [ListUsers](https://docs.oracle.com/en-us/iaas/api/#/en/identity/20160918/User/ListUsers) |
| `oci iam authentication-policy get` | `passwordPolicy.*` | [PasswordPolicy](https://docs.oracle.com/en-us/iaas/api/#/en/identity/20160918/datatypes/PasswordPolicy) |
| `oci iam user api-key list`, `oci iam customer-secret-key list`, `oci iam auth-token list` | `fingerprint`/`id`, `timeCreated`, `lifecycleState` | [ApiKey](https://docs.oracle.com/en-us/iaas/api/#/en/identity/20160918/datatypes/ApiKey), [CustomerSecretKeySummary](https://docs.oracle.com/en-us/iaas/api/#/en/identity/20160918/datatypes/CustomerSecretKeySummary), [AuthToken](https://docs.oracle.com/en-us/iaas/api/#/en/identity/20160918/datatypes/AuthToken) |
| `oci iam policy list --all` (per compartment) | `name`, `statements`, `lifecycleState` | [ListPolicies](https://docs.oracle.com/en-us/iaas/api/#/en/identity/20160918/Policy/ListPolicies) |
| `oci iam availability-domain list` | `name` | [ListAvailabilityDomains](https://docs.oracle.com/en-us/iaas/api/#/en/identity/20160918/AvailabilityDomain/ListAvailabilityDomains) |
| `oci audit config get` | `retentionPeriodDays` | [GetConfiguration](https://docs.oracle.com/en-us/iaas/api/#/en/audit/20190901/Configuration/GetConfiguration) |
| `oci audit event list --all` | `eventId`, `eventTime` | [ListEvents](https://docs.oracle.com/en-us/iaas/api/#/en/audit/20190901/AuditEvent/ListEvents) |
| `oci cloud-guard configuration get` | `status`, `reportingRegion` | [GetConfiguration](https://docs.oracle.com/en-us/iaas/api/#/en/cloud-guard/20200131/Configuration/GetConfiguration) |
| `oci cloud-guard target list`, `problem list --lifecycle-detail OPEN`, `responder-recipe list` (subtree, ACCESSIBLE, `--all`) | `lifecycleState`, `lifecycleDetail`, `riskLevel`, `responderRules[].details.isEnabled` | [ListTargets](https://docs.oracle.com/en-us/iaas/api/#/en/cloud-guard/20200131/TargetSummary/ListTargets), [ListProblems](https://docs.oracle.com/en-us/iaas/api/#/en/cloud-guard/20200131/ProblemSummary/ListProblems), [ListResponderRecipes](https://docs.oracle.com/en-us/iaas/api/#/en/cloud-guard/20200131/ResponderRecipeSummary/ListResponderRecipes) |
| `oci events rule list --all` (per compartment) | `condition`, `isEnabled`, `lifecycleState` | [ListRules](https://docs.oracle.com/en-us/iaas/api/#/en/events/20181201/RuleSummary/ListRules) |
| `oci network security-list list`, `nsg list`, `nsg rules list --nsg-id --direction INGRESS`, `internet-gateway list` (per compartment, `--all`) | `ingressSecurityRules[]`, `SecurityRule.direction/source/protocol/isValid/tcpOptions`, `isEnabled` | [ListSecurityLists](https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/SecurityList/ListSecurityLists), [ListNetworkSecurityGroupSecurityRules](https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/SecurityRule/ListNetworkSecurityGroupSecurityRules), [ListInternetGateways](https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/InternetGateway/ListInternetGateways) |
| `oci bastion bastion list`, `bastion get`, `session list` | `maxSessionTtlInSeconds`, `clientCidrBlockAllowList`, `SessionSummary.lifecycleState/timeCreated/sessionTtlInSeconds` | [GetBastion](https://docs.oracle.com/en-us/iaas/api/#/en/bastion/20210331/Bastion/GetBastion), [ListSessions](https://docs.oracle.com/en-us/iaas/api/#/en/bastion/20210331/SessionSummary/ListSessions) |
| `oci kms management vault list`, `key list --endpoint`, `key-version list --endpoint` | `managementEndpoint`, `KeySummary.id/displayName/lifecycleState`, `KeyVersionSummary.timeCreated/lifecycleState` | [ListVaults](https://docs.oracle.com/en-us/iaas/api/#/en/key/release/VaultSummary/ListVaults), [ListKeys](https://docs.oracle.com/en-us/iaas/api/#/en/key/release/KeySummary/ListKeys), [ListKeyVersions](https://docs.oracle.com/en-us/iaas/api/#/en/key/release/KeyVersionSummary/ListKeyVersions) |
| `oci kms management key get --key-id --endpoint` (per ENABLED key, capped by `max_keys`) | `Key.keyShape.algorithm`, `Key.keyShape.length` (bytes), `Key.keyShape.curveId`, `lifecycleState` | [GetKey](https://docs.oracle.com/en-us/iaas/api/#/en/key/release/Key/GetKey), [KeyShape](https://docs.oracle.com/en-us/iaas/api/#/en/key/release/datatypes/KeyShape), [CLI key get](https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/kms/management/key/get.html) |
| `oci os ns get`, `os bucket list`, `os bucket get`, `os preauth-request list` | `Bucket.publicAccessType`, `PreauthenticatedRequestSummary.timeExpires` | [GetBucket](https://docs.oracle.com/en-us/iaas/api/#/en/objectstorage/20160918/Bucket/GetBucket), [ListPreauthenticatedRequests](https://docs.oracle.com/en-us/iaas/api/#/en/objectstorage/20160918/PreauthenticatedRequestSummary/ListPreauthenticatedRequests) |
| `oci compute instance list --all` (per compartment) | `lifecycleState`, `instanceOptions.areLegacyImdsEndpointsDisabled` | [ListInstances](https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/Instance/ListInstances) |
| `oci bv volume list --all`, `oci bv boot-volume list --availability-domain --all` (per compartment) | `lifecycleState`, `kmsKeyId` | [ListVolumes](https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/Volume/ListVolumes), [ListBootVolumes](https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/BootVolume/ListBootVolumes) |

The CLI `--all` flag follows `opc-next-page` pagination to completion. No `--query` projections are used.
