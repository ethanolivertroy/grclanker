---
title: Tool Catalog
description: Bundled grclanker GRC and compute tools grouped by domain.
---

`grclanker tools` lists the same bundled extension registration surface the agent uses at runtime. Use `grclanker tools <name>` for detailed parameter help, or `grclanker tools --json` for automation.

Current bundled surface:

- 241 domain tools
- 7 compute backend tools

## Compute Backend

| Tool | Purpose |
|---|---|
| `bash` | bash (compute backend) |
| `edit` | edit (compute backend) |
| `find` | find (compute backend) |
| `grep` | grep (compute backend) |
| `ls` | ls (compute backend) |
| `read` | read (compute backend) |
| `write` | write (compute backend) |

## Ansible AAP

| Tool | Purpose |
|---|---|
| `ansible_assess_host_coverage` | Assess Ansible AAP host coverage |
| `ansible_assess_job_health` | Assess Ansible AAP job health |
| `ansible_assess_platform_security` | Assess Ansible AAP platform security |
| `ansible_check_access` | Check Ansible AAP audit access |
| `ansible_export_audit_bundle` | Export Ansible AAP audit bundle |

## AWS

| Tool | Purpose |
|---|---|
| `aws_assess_data_protection` | Assess AWS data protection |
| `aws_assess_identity` | Assess AWS identity posture |
| `aws_assess_logging_detection` | Assess AWS logging and detection |
| `aws_assess_network_security` | Assess AWS network security |
| `aws_assess_org_guardrails` | Assess AWS organization guardrails |
| `aws_check_access` | Check AWS audit access |
| `aws_export_audit_bundle` | Export AWS audit bundle |

## Azure

| Tool | Purpose |
|---|---|
| `azure_assess_data_protection` | Assess Azure data and endpoint protection |
| `azure_assess_identity` | Assess Azure identity posture |
| `azure_assess_monitoring` | Assess Azure monitoring posture |
| `azure_assess_network_and_policy` | Assess Azure network and policy posture |
| `azure_assess_subscription_guardrails` | Assess Azure subscription guardrails |
| `azure_check_access` | Check Azure audit access |
| `azure_export_audit_bundle` | Export Azure audit bundle |

## Box

| Tool | Purpose |
|---|---|
| `box_assess_data_governance` | Assess Box data governance |
| `box_assess_identity_access` | Assess Box identity and access |
| `box_assess_sharing_collaboration` | Assess Box sharing and collaboration |
| `box_assess_shield_monitoring` | Assess Box Shield and monitoring |
| `box_check_access` | Check Box audit access |
| `box_export_audit_bundle` | Export Box audit bundle |

## Cloudflare

| Tool | Purpose |
|---|---|
| `cloudflare_assess_identity` | Assess Cloudflare identity posture |
| `cloudflare_assess_traffic_controls` | Assess Cloudflare traffic controls |
| `cloudflare_assess_zone_security` | Assess Cloudflare zone security |
| `cloudflare_check_access` | Check Cloudflare audit access |
| `cloudflare_export_audit_bundle` | Export Cloudflare audit bundle |

## CMVP

| Tool | Purpose |
|---|---|
| `cmvp_get_module` | Get FIPS Module by Certificate Number |
| `cmvp_search_historical` | Search Historical/Expired FIPS Modules |
| `cmvp_search_in_process` | Search FIPS Modules In Process |
| `cmvp_search_modules` | Search FIPS Validated Modules |

## CrowdStrike

| Tool | Purpose |
|---|---|
| `crowdstrike_assess_access_governance` | Assess CrowdStrike access governance and exclusions |
| `crowdstrike_assess_device_firewall` | Assess CrowdStrike device control and firewall |
| `crowdstrike_assess_prevention_policies` | Assess CrowdStrike prevention policies |
| `crowdstrike_assess_response_readiness` | Assess CrowdStrike response readiness |
| `crowdstrike_assess_sensor_coverage` | Assess CrowdStrike sensor coverage |
| `crowdstrike_check_access` | Check CrowdStrike Falcon audit access |
| `crowdstrike_export_audit_bundle` | Export CrowdStrike audit bundle |

## Datadog

| Tool | Purpose |
|---|---|
| `datadog_assess_access_controls` | Assess Datadog key, sharing, and network controls |
| `datadog_assess_data_protection` | Assess Datadog audit trail and log protection |
| `datadog_assess_identity` | Assess Datadog identity posture |
| `datadog_assess_security_monitoring` | Assess Datadog Cloud SIEM and CSM posture |
| `datadog_check_access` | Check Datadog audit access |
| `datadog_export_audit_bundle` | Export Datadog audit bundle |

## Duo

| Tool | Purpose |
|---|---|
| `duo_assess_admin_access` | Assess Duo admin access |
| `duo_assess_authentication` | Assess Duo authentication posture |
| `duo_assess_integrations` | Assess Duo integrations |
| `duo_assess_monitoring` | Assess Duo monitoring |
| `duo_check_access` | Check Duo audit access |
| `duo_export_audit_bundle` | Export Duo audit bundle |

## Elastic

| Tool | Purpose |
|---|---|
| `elastic_assess_access_control` | Assess Elastic role-based access control |
| `elastic_assess_cluster_hardening` | Assess Elastic cluster hardening |
| `elastic_assess_identity` | Assess Elastic identity and authentication |
| `elastic_assess_kibana` | Assess Kibana spaces, roles, and Fleet |
| `elastic_assess_transport_security` | Assess Elastic TLS posture |
| `elastic_check_access` | Check Elastic audit access |
| `elastic_export_audit_bundle` | Export Elastic audit bundle |

## FedRAMP

| Tool | Purpose |
|---|---|
| `fedramp_assess_readiness` | Assess FedRAMP readiness |
| `fedramp_check_sources` | Check official FedRAMP sources |
| `fedramp_generate_ads_bundle` | Generate ADS starter bundle |
| `fedramp_generate_ads_site` | Generate ADS public trust-center site |
| `fedramp_get_ksi` | Get official FedRAMP KSI |
| `fedramp_get_process` | Get official FedRAMP process |
| `fedramp_get_requirement` | Get official FedRAMP requirement |
| `fedramp_plan_ads_package` | Plan ADS trust-center package |
| `fedramp_plan_process_artifacts` | Plan FedRAMP process artifacts |
| `fedramp_search_frmr` | Search official FedRAMP Consolidated Rules data |

## GCP

| Tool | Purpose |
|---|---|
| `gcp_assess_data_protection` | Assess GCP data protection |
| `gcp_assess_identity` | Assess GCP identity posture |
| `gcp_assess_logging_detection` | Assess GCP logging and detection |
| `gcp_assess_network_security` | Assess GCP network security |
| `gcp_assess_org_guardrails` | Assess GCP organization guardrails |
| `gcp_check_access` | Check GCP audit access |
| `gcp_export_audit_bundle` | Export GCP audit bundle |

## GitHub

| Tool | Purpose |
|---|---|
| `github_assess_actions_security` | Assess GitHub Actions security |
| `github_assess_code_security` | Assess GitHub code security |
| `github_assess_integrations` | Assess GitHub integrations |
| `github_assess_org_access` | Assess GitHub org access |
| `github_assess_repo_protection` | Assess GitHub repo protection |
| `github_check_access` | Check GitHub audit access |
| `github_export_audit_bundle` | Export GitHub audit bundle |

## Google Workspace

| Tool | Purpose |
|---|---|
| `gws_assess_admin_access` | Assess Google Workspace admin access |
| `gws_assess_identity` | Assess Google Workspace identity posture |
| `gws_assess_integrations` | Assess Google Workspace integrations |
| `gws_assess_monitoring` | Assess Google Workspace monitoring |
| `gws_check_access` | Check Google Workspace audit access |
| `gws_export_audit_bundle` | Export Google Workspace audit bundle |

## Google Workspace Operator

| Tool | Purpose |
|---|---|
| `gws_ops_check_cli` | Check Google Workspace CLI operator bridge |
| `gws_ops_collect_evidence_bundle` | Collect Google Workspace operator evidence bundle |
| `gws_ops_investigate_alerts` | Investigate Google Workspace alerts with gws |
| `gws_ops_review_tokens` | Review Google Workspace token activity with gws |
| `gws_ops_trace_admin_activity` | Trace Google Workspace admin activity with gws |

## KEV / EPSS

| Tool | Purpose |
|---|---|
| `kevs_check_ransomware` | Check Ransomware-Linked Vulnerabilities |
| `kevs_get_epss` | Get EPSS Exploit Probability |
| `kevs_recent` | List Recently Added KEV Entries |
| `kevs_search` | Search Known Exploited Vulnerabilities |

## KnowBe4

| Tool | Purpose |
|---|---|
| `knowbe4_assess_account_governance` | Assess KnowBe4 account governance |
| `knowbe4_assess_phishing_program` | Assess KnowBe4 phishing program |
| `knowbe4_assess_training_program` | Assess KnowBe4 training program |
| `knowbe4_assess_user_risk` | Assess KnowBe4 user risk and coverage |
| `knowbe4_check_access` | Check KnowBe4 audit access |
| `knowbe4_export_audit_bundle` | Export KnowBe4 audit bundle |

## LaunchDarkly

| Tool | Purpose |
|---|---|
| `launchdarkly_assess_access_control` | Assess LaunchDarkly access control |
| `launchdarkly_assess_environment_governance` | Assess LaunchDarkly environment governance |
| `launchdarkly_assess_flag_hygiene` | Assess LaunchDarkly flag hygiene |
| `launchdarkly_assess_identity` | Assess LaunchDarkly identity posture |
| `launchdarkly_assess_monitoring_integrations` | Assess LaunchDarkly monitoring and integrations |
| `launchdarkly_check_access` | Check LaunchDarkly audit access |
| `launchdarkly_export_audit_bundle` | Export LaunchDarkly audit bundle |

## MuleSoft

| Tool | Purpose |
|---|---|
| `mulesoft_assess_api_gateway` | Assess MuleSoft API gateway policies |
| `mulesoft_assess_audit_monitoring` | Assess MuleSoft audit logging and alerts |
| `mulesoft_assess_identity_access` | Assess MuleSoft identity and access |
| `mulesoft_assess_runtime_infrastructure` | Assess MuleSoft runtime infrastructure |
| `mulesoft_check_access` | Check MuleSoft Anypoint audit access |
| `mulesoft_export_audit_bundle` | Export MuleSoft audit bundle |

## New Relic

| Tool | Purpose |
|---|---|
| `newrelic_assess_access_control` | Assess New Relic access control and API keys |
| `newrelic_assess_alerting` | Assess New Relic alerting and notifications |
| `newrelic_assess_data_governance` | Assess New Relic data governance |
| `newrelic_assess_identity` | Assess New Relic identity posture |
| `newrelic_check_access` | Check New Relic audit access |
| `newrelic_export_audit_bundle` | Export New Relic audit bundle |

## OCI

| Tool | Purpose |
|---|---|
| `oci_assess_compute_and_storage` | Assess OCI compute and storage |
| `oci_assess_identity` | Assess OCI identity posture |
| `oci_assess_logging_detection` | Assess OCI logging and detection |
| `oci_assess_tenancy_guardrails` | Assess OCI tenancy guardrails |
| `oci_check_access` | Check OCI audit access |
| `oci_export_audit_bundle` | Export OCI audit bundle |

## Okta

| Tool | Purpose |
|---|---|
| `okta_assess_admin_access` | Assess Okta admin access |
| `okta_assess_authentication` | Assess Okta authentication posture |
| `okta_assess_integrations` | Assess Okta integrations |
| `okta_assess_monitoring` | Assess Okta monitoring |
| `okta_check_access` | Check Okta audit access |
| `okta_export_audit_bundle` | Export Okta audit bundle |

## OSCAL

| Tool | Purpose |
|---|---|
| `oscal_assemble_ssp` | Assemble SSP from markdown |
| `oscal_check_trestle` | Check OSCAL trestle setup |
| `oscal_create_model` | Create OSCAL model |
| `oscal_generate_ssp_markdown` | Generate SSP markdown |
| `oscal_import_model` | Import OSCAL model |
| `oscal_init_workspace` | Initialize OSCAL workspace |
| `oscal_validate_model` | Validate OSCAL model |

## PagerDuty

| Tool | Purpose |
|---|---|
| `pagerduty_assess_access_control` | Assess PagerDuty access control |
| `pagerduty_assess_audit_logging` | Assess PagerDuty audit logging |
| `pagerduty_assess_incident_response` | Assess PagerDuty incident response configuration |
| `pagerduty_assess_integration_security` | Assess PagerDuty integration security |
| `pagerduty_assess_oncall_coverage` | Assess PagerDuty on-call coverage |
| `pagerduty_check_access` | Check PagerDuty audit access |
| `pagerduty_export_audit_bundle` | Export PagerDuty audit bundle |

## Palo Alto Networks

| Tool | Purpose |
|---|---|
| `paloalto_assess_cloud_posture` | Assess Prisma Cloud posture |
| `paloalto_assess_device_hardening` | Assess PAN-OS device hardening and access |
| `paloalto_assess_firewall_policy` | Assess PAN-OS firewall policy |
| `paloalto_assess_threat_prevention` | Assess PAN-OS threat prevention |
| `paloalto_check_access` | Check Palo Alto audit access |
| `paloalto_export_audit_bundle` | Export Palo Alto audit bundle |

## Qualys

| Tool | Purpose |
|---|---|
| `qualys_assess_administration` | Assess Qualys administration hygiene |
| `qualys_assess_asset_inventory` | Assess Qualys asset inventory |
| `qualys_assess_scan_coverage` | Assess Qualys scan coverage |
| `qualys_assess_vulnerability_management` | Assess Qualys vulnerability management |
| `qualys_check_access` | Check Qualys audit access |
| `qualys_export_audit_bundle` | Export Qualys audit bundle |

## Salesforce

| Tool | Purpose |
|---|---|
| `salesforce_assess_data_protection` | Assess Salesforce data protection |
| `salesforce_assess_identity_access` | Assess Salesforce identity and access |
| `salesforce_assess_monitoring_integrations` | Assess Salesforce monitoring and integrations |
| `salesforce_assess_platform_security` | Assess Salesforce platform security settings |
| `salesforce_check_access` | Check Salesforce audit access |
| `salesforce_export_audit_bundle` | Export Salesforce audit bundle |

## SCF

| Tool | Purpose |
|---|---|
| `scf_get_control` | Get SCF control bundle |
| `scf_get_crosswalk` | Get SCF framework crosswalk |
| `scf_get_evidence_request` | Get SCF evidence request |
| `scf_search_controls` | Search SCF controls |

## ServiceNow

| Tool | Purpose |
|---|---|
| `servicenow_assess_access_control` | Assess ServiceNow access control rules |
| `servicenow_assess_identity_access` | Assess ServiceNow identity and access |
| `servicenow_assess_operations_governance` | Assess ServiceNow operations governance |
| `servicenow_assess_platform_hardening` | Assess ServiceNow platform hardening |
| `servicenow_check_access` | Check ServiceNow audit access |
| `servicenow_export_audit_bundle` | Export ServiceNow audit bundle |

## Slack

| Tool | Purpose |
|---|---|
| `slack_assess_admin_access` | Assess Slack admin access |
| `slack_assess_channel_governance` | Assess Slack channel governance |
| `slack_assess_identity` | Assess Slack identity posture |
| `slack_assess_integrations` | Assess Slack integrations |
| `slack_assess_monitoring` | Assess Slack monitoring |
| `slack_check_access` | Check Slack audit access |
| `slack_export_audit_bundle` | Export Slack audit bundle |

## Snowflake

| Tool | Purpose |
|---|---|
| `snowflake_assess_access_control` | Assess Snowflake access control |
| `snowflake_assess_data_protection` | Assess Snowflake data protection |
| `snowflake_assess_monitoring_and_lifecycle` | Assess Snowflake monitoring and lifecycle |
| `snowflake_assess_network_and_authentication` | Assess Snowflake network and authentication |
| `snowflake_check_access` | Check Snowflake audit access |
| `snowflake_export_audit_bundle` | Export Snowflake audit bundle |

## Splunk

| Tool | Purpose |
|---|---|
| `splunk_assess_access_control` | Assess Splunk authorization and access control |
| `splunk_assess_audit_monitoring` | Assess Splunk audit logging |
| `splunk_assess_authentication` | Assess Splunk authentication and identity |
| `splunk_assess_data_protection` | Assess Splunk data protection |
| `splunk_assess_platform_hardening` | Assess Splunk platform hardening |
| `splunk_check_access` | Check Splunk audit access |
| `splunk_export_audit_bundle` | Export Splunk audit bundle |

## Sumo Logic

| Tool | Purpose |
|---|---|
| `sumologic_assess_access_control` | Assess Sumo Logic access control |
| `sumologic_assess_content_sharing` | Assess Sumo Logic content sharing and alerting |
| `sumologic_assess_data_governance` | Assess Sumo Logic data governance |
| `sumologic_assess_identity` | Assess Sumo Logic identity posture |
| `sumologic_check_access` | Check Sumo Logic audit access |
| `sumologic_export_audit_bundle` | Export Sumo Logic audit bundle |

## Tenable

| Tool | Purpose |
|---|---|
| `tenable_assess_access_control` | Assess Tenable access control |
| `tenable_assess_scan_program` | Assess Tenable scan program |
| `tenable_assess_sensor_coverage` | Assess Tenable sensor and asset coverage |
| `tenable_assess_vulnerability_management` | Assess Tenable vulnerability management |
| `tenable_check_access` | Check Tenable audit access |
| `tenable_export_audit_bundle` | Export Tenable audit bundle |

## Vanta

| Tool | Purpose |
|---|---|
| `vanta_check_access` | Check Vanta auditor access |
| `vanta_export_audit` | Export Vanta audit evidence |
| `vanta_list_audits` | List Vanta audits |

## Veracode

| Tool | Purpose |
|---|---|
| `veracode_assess_access_controls` | Assess Veracode access controls |
| `veracode_assess_findings_hygiene` | Assess Veracode findings hygiene |
| `veracode_assess_policy_compliance` | Assess Veracode policy compliance |
| `veracode_assess_sca_posture` | Assess Veracode SCA posture |
| `veracode_assess_scan_coverage` | Assess Veracode scan coverage |
| `veracode_check_access` | Check Veracode audit access |
| `veracode_export_audit_bundle` | Export Veracode audit bundle |

## Webex

| Tool | Purpose |
|---|---|
| `webex_assess_collaboration_governance` | Assess Webex collaboration governance |
| `webex_assess_identity` | Assess Webex identity posture |
| `webex_assess_meeting_hybrid_security` | Assess Webex meeting and hybrid security |
| `webex_check_access` | Check Webex audit access |
| `webex_export_audit_bundle` | Export Webex audit bundle |

## Zendesk

| Tool | Purpose |
|---|---|
| `zendesk_assess_access_control` | Assess Zendesk access control |
| `zendesk_assess_authentication` | Assess Zendesk authentication |
| `zendesk_assess_data_protection` | Assess Zendesk data protection |
| `zendesk_assess_integrations` | Assess Zendesk integrations |
| `zendesk_check_access` | Check Zendesk audit access |
| `zendesk_export_audit_bundle` | Export Zendesk audit bundle |

## Zoom

| Tool | Purpose |
|---|---|
| `zoom_assess_collaboration_governance` | Assess Zoom collaboration governance |
| `zoom_assess_identity` | Assess Zoom identity posture |
| `zoom_assess_meeting_security` | Assess Zoom meeting security |
| `zoom_check_access` | Check Zoom audit access |
| `zoom_export_audit_bundle` | Export Zoom audit bundle |

## Zscaler

| Tool | Purpose |
|---|---|
| `zscaler_assess_zia_access_control` | Assess ZIA administrative access control |
| `zscaler_assess_zia_policy` | Assess ZIA security policy |
| `zscaler_assess_zpa` | Assess ZPA zero trust access |
| `zscaler_check_access` | Check Zscaler audit access |
| `zscaler_export_audit_bundle` | Export Zscaler audit bundle |
