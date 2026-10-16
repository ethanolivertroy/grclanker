---
title: "Oracle Cloud Infrastructure"
description: "Read-only OCI security inspector covering IAM, Cloud Guard, audit retention, networking, vault keys, Object Storage, and IMDSv2, mapped to eight frameworks."
---

# Oracle Cloud Infrastructure (OCI)

The OCI tool family inspects a tenancy read-only through the official OCI CLI and produces framework-mapped findings.

It implements the `specs/oci-sec-inspector.spec.md` control set. Of its 25 controls, 23 are automated or explicitly manual, across 21 findings (see Control coverage).

## What it inspects

- **Identity**
  - Password policy
  - Console MFA
  - API key, customer secret key, and auth token age
  - Broad IAM policies
  - Compartment hierarchy
- **Logging and detection**
  - Cloud Guard enablement, targets, open problems, and responder recipes
  - Audit log retention
  - Audit event visibility
  - Events rules for identity, policy, and network changes
- **Tenancy guardrails**
  - Security list and NSG world ingress to sensitive ports
  - Internet gateways
  - Bastion TTL, CIDR allow lists, and active sessions
  - Vault key strength (algorithm, length, curve) and rotation
  - Bucket public access and pre-authenticated requests
- **Compute and storage**
  - IMDSv2-only instances
  - Customer-managed keys on block and boot volumes

## Setup and authentication

1. Install the OCI CLI (`oci`) and confirm `oci --version` works. Installation guide: https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/cliinstall.htm
2. Configure an API-key profile in `~/.oci/config` (`tenancy`, `user`, `fingerprint`, `key_file`, `region`). Config file reference: https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm
3. Optionally set `OCI_CONFIG_FILE`, `OCI_CLI_PROFILE`, `OCI_REGION`, `OCI_TENANCY_OCID`, or `OCI_COMPARTMENT_OCID`.

Tool arguments (`config_file`, `profile`, `region`, `tenancy_ocid`, `compartment_ocid`) override environment, which overrides the config profile.

Without any of these variables or arguments, the tools:

- Read `~/.oci/config` profile `DEFAULT`.
- Take `region` and `tenancy` from that profile. Region falls back to `us-ashburn-1`.
- Use the tenancy as the starting compartment.

A tenancy OCID is required from one of the three sources.

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

A surface the principal cannot read renders its control as MANUAL, with the failing command in the summary. The control never passes.

## Tools

- `oci_check_access`: Probes ten read surfaces (compartments, users, authentication policy, audit configuration, audit events, Cloud Guard configuration, security lists, vaults, Object Storage, compute).
  - Key arguments: `profile`, `region`, `tenancy_ocid`, `compartment_ocid`.
- `oci_assess_identity`: Findings OCI-IAM-01..06.
  - Key arguments: `stale_days` (90), `max_keys` (200), `max_policies` (500), `max_compartments` (25).
- `oci_assess_logging_detection`: Findings OCI-LOG-01..06.
  - Key arguments: `lookback_days` (7), `max_compartments`.
- `oci_assess_tenancy_guardrails`: Findings OCI-GRD-01..06.
  - Key arguments: `max_compartments`, `max_buckets` (100), `max_keys` (200, ENABLED vault keys fetched with `kms management key get`).
- `oci_assess_compute_and_storage`: Findings OCI-CMP-01..03.
  - Key arguments: `max_compartments`.
- `oci_export_audit_bundle`: Runs everything and writes the evidence bundle plus zip.
  - Key arguments: `output_dir` (`./export/oci`) plus the arguments above.

## Status semantics

- `pass`: Judged from a readable, complete inventory using documented fields.
- `warn`: Judged, but the view is incomplete or a lower-risk issue exists.
  - Incomplete view: Compartment or item cap hit, a compartment denied, undated items, failed sub-reads such as a denied `key get`.
- `fail`: A documented field contradicts the control.
- `manual`: The surface was unreadable, out of scope, or the setting is not exposed by the API. Never treat manual as compliant.
  - Unreadable: For example, the documented `NotAuthorizedOrNotFound` response.
  - Out of scope: Nothing to inspect.

Compartment-scoped resources (policies, event rules, networking, bastions, vaults, buckets, instances, volumes) are listed per accessible compartment, up to `max_compartments`. Hitting the cap or losing a compartment withholds `pass` and reports seen versus total counts.

A demoted summary names the CLI command that failed and the compartments it could not read, for example `Partial view: network security-list list denied or unreadable in 1 compartment(s): prod`.

A finding that reads more than one inventory demotes when any of them is incomplete, even if the failure is also listed in the errors array.

## Control coverage

Each entry names the spec control number and name, then the tool and finding that cover it, then the status semantics.

- **1 IAM password policy** (identity, OCI-IAM-01): Pass when `minimumPasswordLength` >= 14 and all four character classes are required. Expiration is split into OCI-IAM-06.
- **1 Password expiration** (identity, OCI-IAM-06): Always manual. The IAM `PasswordPolicy` datatype has no expiration field.
- **2 MFA enforcement** (identity, OCI-IAM-02): Pass when every ACTIVE console-capable user has `isMfaActivated=true`. No users or no console users is manual.
- **3, 4, 5 API key, customer secret key, auth token rotation** (identity, OCI-IAM-03)
  - Fail on any ACTIVE credential older than `stale_days`.
  - At most warn on undated items or a cap hit.
  - Folded, with per-kind evidence.
- **6 Policy least privilege** (identity, OCI-IAM-04): Warn on tenancy-wide `manage` statements. An empty policy list is manual.
- **7 Compartment structure** (identity, OCI-IAM-05): Fail when no ACTIVE non-root compartment exists.
- **8 Cloud Guard enabled** (logging, OCI-LOG-01): Pass when configuration `status=ENABLED` and at least one ACTIVE target exists.
- **9 Cloud Guard open problems** (logging, OCI-LOG-02): Pass only when Cloud Guard is ENABLED and there are no OPEN problems. A CRITICAL or HIGH `riskLevel` fails.
- **10 Responder recipe activation** (logging, OCI-LOG-03): Pass when an ACTIVE recipe has a rule with `details.isEnabled=true`.
- **11 Audit log retention** (logging, OCI-LOG-06): Pass when `retentionPeriodDays` >= 365.
- **12 Event rules** (logging, OCI-LOG-05): Pass when an enabled ACTIVE rule condition references identity, policy, or network event types. Empty fails.
- **13 Security list ingress** (guardrails, OCI-GRD-01): Fail when a rule allows `0.0.0.0/0` or `::/0` to ports 22, 3389, 1433, 3306, 5432 (protocol 6 or all, range containment).
- **14 NSG rules** (guardrails, OCI-GRD-02)
  - Same test on INGRESS `SecurityRule`s, with `isValid` recorded per rule.
  - No NSGs passes only beside a complete, readable security list inventory.
    - A security list compartment denied or capped demotes to warn and names it.
    - None readable is manual.
- **15 Internet gateway exposure** (guardrails, OCI-GRD-03)
  - Warn when any gateway has `isEnabled=true`.
  - No gateways passes only beside a complete, readable security list inventory (same demotion as OCI-GRD-02).
- **16, 17 Bastion controls and sessions** (guardrails, OCI-GRD-04)
  - Fail when a bastion combines a world allow list (`0.0.0.0/0` or `::/0`) with TTL > 3h.
  - Fail when an ACTIVE session is older than 8h.
  - Warn on TTL > 3h or an empty/world allow list alone.
  - Folded.
- **18, 19 Vault key rotation and algorithm strength** (guardrails, OCI-GRD-05)
  - Fail when the newest ENABLED key version is older than 365 days.
  - Fail when `Key.keyShape` (from `kms management key get`) is:
    - AES below 32 bytes (AES-256)
    - RSA below 512 bytes (RSA-4096)
    - ECDSA without a documented `curveId` (NIST_P256, NIST_P384, NIST_P521 all pass)
    - Outside the AES/RSA/ECDSA enum
  - A denied key get caps the verdict at warn (some keys read) or manual (none read).
  - Folded.
- **20, 21 Bucket public access and PARs** (guardrails, OCI-GRD-06)
  - Fail on `publicAccessType` other than `NoPublicAccess`.
  - PARs expiring more than 30 days out warn.
  - Folded.
- **22 Block and boot volume CMK** (compute and storage, OCI-CMP-02, OCI-CMP-03): Fail when a live volume has no `kmsKeyId`.
- **23 IMDSv2** (compute and storage, OCI-CMP-01): Fail when a live instance lacks `instanceOptions.areLegacyImdsEndpointsDisabled=true`.
- **24 Budget alert rules** (not shipped, none): Deferred.
- **25 OS Management patching** (not shipped, none): Deferred.

The audit event visibility finding OCI-LOG-04 is supporting evidence, not a spec control.

## Framework mappings

Every finding carries the spec mapping table values for FedRAMP, CMMC L2, SOC 2, CIS OCI, PCI-DSS, DISA STIG, IRAP ISM, and ISMAP. The bundle writes one report per framework under `compliance/`.

## Evidence bundle

`oci_export_audit_bundle` writes `<tenancy>-<region>-audit/` under the output root, plus a zip named after that directory. Reruns allocate `-2` through `-9`, never overwrite, and fail once all nine names are taken.

Bundle contents:

- `QUICK_REFERENCE.md`, `README.md`, `metadata.json`
- `core_data/`: `access.json`, `compartments.json` (no credentials)
- `analysis/`: `findings.json`, one JSON per assessment, `summary.md`
- `compliance/`: `executive_summary.md`, `unified_compliance_matrix.md`, one report per framework
- `_errors.log`: Only when collection partially failed

### Secret hygiene

Nothing credential-bearing is written. Redaction rules:

- Findings redact sensitive fields at creation. `accessUri`, `keyValue`, `token`, `key`, `secret*`, `*password*`, `privateKey`, `keyMaterial`, `wrappedKey`, `plaintext`, `ciphertext`, `authorization`, `userData`, and similar names keep the field name with a `[redacted]` marker.
- The following are scrubbed from every string, including CLI error text:
  - PEM blocks
  - `/p/<token>/n/` PAR URIs
  - The OCI request-signing `Signature` header parameter list
  - Standalone `keyId`/`signingKeyId`/`signature` values in assignment or JSON-colon form
  - `token`, `secret`, `password`, `pass_phrase`, `key_file`, and `access_uri` assignments
- KMS `kmsKeyId` values and `--key-id` arguments are left readable because verdicts depend on them.
- `core_data/compartments.json` is projected to `id`, `compartmentId`, `name`, `lifecycleState`.
- The config file path is replaced with `[redacted]` in `metadata.json` and `core_data/access.json`.

A regression test writes a bundle from fixtures carrying `FAKE_` secrets in every collected object. The test asserts none appears in any bundle file or zip entry.

### Cap exits

Every capped loop (`max_compartments`, `max_keys`, `max_policies`, `max_buckets`):

- Records the cap hit.
- Reports seen versus total in the summary and evidence. `credentials_total` is `null` when the credential cap stopped enumeration.
- Withholds `pass`.

### CLI error text

When an `oci` command fails, its stderr and stdout are never echoed into a finding, an errors array, or a bundle file.

- A documented `ServiceError` block contributes only its `status`, `code`, `opc-request-id`, and scrubbed `message` (for example `oci iam user list exited 1 with ServiceError status=404 code=NotAuthorizedOrNotFound opc-request-id=... message=...`).
- Anything else (an HTML gateway page, a traceback, plain text) is described by the command words, exit code, and byte counts (`oci iam user list exited 1; 236 bytes of stderr and 0 bytes of stdout withheld (no documented ServiceError block)`).

Every error string passes through `scrubErrorText` once, where it is created and before the message cap is applied. `scrubErrorText` drops:

- Embedded URL queries and fragments
- Bearer, Basic, cookie, api key, session, access, refresh, and id token, client secret, password, `Signature`, and `keyId` values
- Any unlabeled token of 16 or more characters that contains a digit or a `+` in free text

OCIDs, `kmsKeyId`, `masterKeyId`, and `--key-id` stay readable.

When the bundle is written, the sink applies a second, data-mode layer to every finding summary and errors array entry. That layer is `redactSensitiveText`: the same patterns with the long-token rule off.

As a result, identifiers such as a compartment named `prod-us-east-2026` survive in `_errors.log` and the executive summary, while `token=` shapes are still redacted there.

An `opc-request-id` value is disclosed only when it matches a documented layout: the CLI's `32hex(/32hex){0,2}` form or the UUID form from `usingapi.htm`. Anything else behind the label is dropped.

Residuals:

- A value in a documented layout that is deliberately placed directly behind an `opc-request-id=` label stays readable. Such placement is exfiltration rather than accidental echo.
  - No OCI secret has the bare 32-hex shape.
  - The identity-domain OAuth client secret has the UUID shape.
- A 16-plus character token with no digit or `+` is not caught by the long-token rule.
- The tool output's errors arrays and summary statuses carry compartment names (and, in one informational line, vault display names) verbatim as tenant data. For the bundle, the sink redacts assignment shapes inside them.

### Silent success

An `oci` command that exits 0 must print the documented `{ "data": ... }` JSON document.

Each of these is recorded as an unreadable surface, never as an empty inventory:

- Empty stdout
- Whitespace-only stdout
- Stdout that is non-JSON (a gateway page passed through)
- A JSON document without a `data` member

In each case:

- The marker names the command and the observed state, for example:
  - `oci iam compartment list exited 0 with empty stdout (no JSON document)`
  - `... exited 0 with whitespace-only stdout (6 bytes, no JSON document)`
  - `... exited 0 with a JSON document that has no data member (48 bytes)`
  - `... exited 0 but printed 236 bytes of non-JSON stdout (withheld)`
- Stdout is never echoed.
- No status code is named.
- The access check reports the surface `not_readable`.
- Dependent findings render `manual` or `warn` with `null` counts.

The OCI CLI has printed nothing for an empty list on some versions (oracle/oci-cli issue 204). But no docs.oracle.com page documents that behaviour for any command, so no command's empty stdout is treated as a documented empty result.

A tenancy whose list is genuinely empty on such a CLI version renders `manual`, and the operator confirms the empty inventory by hand.

## Live smoke

```
npm --prefix cli run test:oci:live
```

The smoke test skips with exit 0 when no `~/.oci/config`, `OCI_CONFIG_FILE`, or `OCI_TENANCY_OCID` is present, or when the `oci` binary is missing. Otherwise it runs the access check and every assess tool against the configured profile.

## Limitations and manual controls

- Password expiration (control 1) is manual: not exposed by the IAM `PasswordPolicy` datatype.
- Vault key strength (control 19) is judged from `Key.keyShape.length` in bytes (AES 16/24/32, RSA 256/384/512, ECDSA 32/48/66 per the `KeyShape` datatype).
  - ECDSA keys pass on any documented `curveId` because the spec control names only the AES-256 and RSA-4096 floors.
  - Tighten `judgeKeyShape` if your baseline requires P-384 or above.
- Controls 24 (budgets and alert rules) and 25 (OS Management Hub patching) are deferred.
- Auth modes other than API-key profiles are deferred.
- Controls 3-5, 16-17, 18-19, and 20-21 stay folded into one finding each with per-kind evidence.
- SARIF and JSON-CLI output formats from the spec are out of scope. Findings are available as JSON in `analysis/findings.json`.

## Surfaces

Every CLI command and output field is cited in `OCI_SURFACE_DOCS` in `cli/extensions/grc-tools/oci.ts`. Summary:

- `oci iam compartment list --compartment-id-in-subtree true --access-level ACCESSIBLE --include-root true --all`
  - Fields read: `id`, `compartmentId`, `name`, `lifecycleState`
  - Reference: [ListCompartments](https://docs.oracle.com/en-us/iaas/api/#/en/identity/20160918/Compartment/ListCompartments)
- `oci iam user list --all`
  - Fields read: `id`, `name`, `lifecycleState`, `isMfaActivated`, `capabilities.canUseConsolePassword`
  - Reference: [ListUsers](https://docs.oracle.com/en-us/iaas/api/#/en/identity/20160918/User/ListUsers)
- `oci iam authentication-policy get`
  - Fields read: `passwordPolicy.*`
  - Reference: [PasswordPolicy](https://docs.oracle.com/en-us/iaas/api/#/en/identity/20160918/datatypes/PasswordPolicy)
- `oci iam user api-key list`, `oci iam customer-secret-key list`, `oci iam auth-token list`
  - Fields read: `fingerprint`/`id`, `timeCreated`, `lifecycleState`
  - References: [ApiKey](https://docs.oracle.com/en-us/iaas/api/#/en/identity/20160918/datatypes/ApiKey), [CustomerSecretKeySummary](https://docs.oracle.com/en-us/iaas/api/#/en/identity/20160918/datatypes/CustomerSecretKeySummary), [AuthToken](https://docs.oracle.com/en-us/iaas/api/#/en/identity/20160918/datatypes/AuthToken)
- `oci iam policy list --all` (per compartment)
  - Fields read: `name`, `statements`, `lifecycleState`
  - Reference: [ListPolicies](https://docs.oracle.com/en-us/iaas/api/#/en/identity/20160918/Policy/ListPolicies)
- `oci iam availability-domain list`
  - Fields read: `name`
  - Reference: [ListAvailabilityDomains](https://docs.oracle.com/en-us/iaas/api/#/en/identity/20160918/AvailabilityDomain/ListAvailabilityDomains)
- `oci audit config get`
  - Fields read: `retentionPeriodDays`
  - Reference: [GetConfiguration](https://docs.oracle.com/en-us/iaas/api/#/en/audit/20190901/Configuration/GetConfiguration)
- `oci audit event list --all`
  - Fields read: `eventId`, `eventTime`
  - Reference: [ListEvents](https://docs.oracle.com/en-us/iaas/api/#/en/audit/20190901/AuditEvent/ListEvents)
- `oci cloud-guard configuration get`
  - Fields read: `status`, `reportingRegion`
  - Reference: [GetConfiguration](https://docs.oracle.com/en-us/iaas/api/#/en/cloud-guard/20200131/Configuration/GetConfiguration)
- `oci cloud-guard target list`, `problem list --lifecycle-detail OPEN`, `responder-recipe list` (subtree, ACCESSIBLE, `--all`)
  - Fields read: `lifecycleState`, `lifecycleDetail`, `riskLevel`, `responderRules[].details.isEnabled`
  - References: [ListTargets](https://docs.oracle.com/en-us/iaas/api/#/en/cloud-guard/20200131/TargetSummary/ListTargets), [ListProblems](https://docs.oracle.com/en-us/iaas/api/#/en/cloud-guard/20200131/ProblemSummary/ListProblems), [ListResponderRecipes](https://docs.oracle.com/en-us/iaas/api/#/en/cloud-guard/20200131/ResponderRecipeSummary/ListResponderRecipes)
- `oci events rule list --all` (per compartment)
  - Fields read: `condition`, `isEnabled`, `lifecycleState`
  - Reference: [ListRules](https://docs.oracle.com/en-us/iaas/api/#/en/events/20181201/RuleSummary/ListRules)
- `oci network security-list list`, `nsg list`, `nsg rules list --nsg-id --direction INGRESS`, `internet-gateway list` (per compartment, `--all`)
  - Fields read: `ingressSecurityRules[]`, `SecurityRule.direction/source/protocol/isValid/tcpOptions`, `isEnabled`
  - References: [ListSecurityLists](https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/SecurityList/ListSecurityLists), [ListNetworkSecurityGroupSecurityRules](https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/SecurityRule/ListNetworkSecurityGroupSecurityRules), [ListInternetGateways](https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/InternetGateway/ListInternetGateways)
- `oci bastion bastion list`, `bastion get`, `session list`
  - Fields read: `maxSessionTtlInSeconds`, `clientCidrBlockAllowList`, `SessionSummary.lifecycleState/timeCreated/sessionTtlInSeconds`
  - References: [GetBastion](https://docs.oracle.com/en-us/iaas/api/#/en/bastion/20210331/Bastion/GetBastion), [ListSessions](https://docs.oracle.com/en-us/iaas/api/#/en/bastion/20210331/SessionSummary/ListSessions)
- `oci kms management vault list`, `key list --endpoint`, `key-version list --endpoint`
  - Fields read: `managementEndpoint`, `KeySummary.id/displayName/lifecycleState`, `KeyVersionSummary.timeCreated/lifecycleState`
  - References: [ListVaults](https://docs.oracle.com/en-us/iaas/api/#/en/key/release/VaultSummary/ListVaults), [ListKeys](https://docs.oracle.com/en-us/iaas/api/#/en/key/release/KeySummary/ListKeys), [ListKeyVersions](https://docs.oracle.com/en-us/iaas/api/#/en/key/release/KeyVersionSummary/ListKeyVersions)
- `oci kms management key get --key-id --endpoint` (per ENABLED key, capped by `max_keys`)
  - Fields read: `Key.keyShape.algorithm`, `Key.keyShape.length` (bytes), `Key.keyShape.curveId`, `lifecycleState`
  - References: [GetKey](https://docs.oracle.com/en-us/iaas/api/#/en/key/release/Key/GetKey), [KeyShape](https://docs.oracle.com/en-us/iaas/api/#/en/key/release/datatypes/KeyShape), [CLI key get](https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/kms/management/key/get.html)
- `oci os ns get`, `os bucket list`, `os bucket get`, `os preauth-request list`
  - Fields read: `Bucket.publicAccessType`, `PreauthenticatedRequestSummary.timeExpires`
  - References: [GetBucket](https://docs.oracle.com/en-us/iaas/api/#/en/objectstorage/20160918/Bucket/GetBucket), [ListPreauthenticatedRequests](https://docs.oracle.com/en-us/iaas/api/#/en/objectstorage/20160918/PreauthenticatedRequestSummary/ListPreauthenticatedRequests)
- `oci compute instance list --all` (per compartment)
  - Fields read: `lifecycleState`, `instanceOptions.areLegacyImdsEndpointsDisabled`
  - Reference: [ListInstances](https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/Instance/ListInstances)
- `oci bv volume list --all`, `oci bv boot-volume list --availability-domain --all` (per compartment)
  - Fields read: `lifecycleState`, `kmsKeyId`
  - References: [ListVolumes](https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/Volume/ListVolumes), [ListBootVolumes](https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/BootVolume/ListBootVolumes)

The CLI `--all` flag follows `opc-next-page` pagination to completion. No `--query` projections are used.
