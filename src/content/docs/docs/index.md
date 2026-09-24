---
title: grclanker Docs
description: Start with the bundle installer, run setup, pick local-first or hosted, then use grclanker against real GRC work and repo specs.
---

`grclanker` is an experimental open source AI GRC companion built on top of Pi.

The current release starts with CMVP, KEV, EPSS, official FedRAMP GitHub-grounded 20x and Rev5 lookups, FedRAMP readiness, ADS package planning, starter-bundle generation, portable public trust-center site generation, read-only compliance assessments for AWS, Azure, GCP, OCI, Cloudflare, Webex, Zoom, Ansible AAP, Duo, Okta, GitHub, Google Workspace, Slack, Box, CrowdStrike, Datadog, Elastic, KnowBe4, LaunchDarkly, MuleSoft, New Relic, PagerDuty, Palo Alto Networks, Qualys, Salesforce, ServiceNow, Snowflake, Splunk, Sumo Logic, Tenable, Veracode, Zendesk, and Zscaler, an optional Google Workspace CLI operator bridge, posture mapping, Vanta audit export, SCF lookups, trestle-backed OSCAL helpers, and spec-driven build inputs, but that is the opening surface, not the ceiling. The real flow is short:

1. Install the companion.
2. Run `grclanker setup`.
3. Choose local-first or hosted.
4. Start using the current workflows and point the companion at repo specs when you want it to build.

## Start Here

- [Installation](/docs/getting-started/installation/) is the main operator page. It covers the bundle installer, skills-only install, pinned versions, package-manager fallback, and the immediate post-install setup path.
- [Setup](/docs/getting-started/setup/) goes deeper on the local-first Ollama + Gemma 4 path and the hosted alternative.
- [Configuration](/docs/getting-started/configuration/) documents `~/.grclanker/agent/settings.json`, `models.json`, and runtime state.
- [Compute Backends](/docs/getting-started/compute-backends/) documents `host`, `sandbox-runtime`, Docker, and Parallels configuration plus validation commands.
- [Cursor Agent SDK](/docs/getting-started/agent-sdk/) documents the `@cursor/july` run mode that exposes the same tools, workflow prompts, and personas as an Agent SDK agent.
- [Flue Runtime](/docs/getting-started/flue-runtime/) documents running the same GRC agent, tools, prompts, and personas under the Flue Framework with `grclanker flue run` or the official `flue run` CLI.
- [Quick Start](/docs/getting-started/quick-start/) is still available if you just want the shortest install → setup → first useful question sequence.

## Default Recommendation

If you want the path that best matches the current product direction:

1. Install with the one-line bundle.
2. Run `grclanker setup`.
3. Choose `local-first`.
4. Point the companion at Ollama on `http://localhost:11434/v1`.
5. Use `gemma4` as the first local model unless you already know you want a different local backend.

## Current Release Surface

- `/investigate` for crypto status, KEV exposure, EPSS likelihood, and ransomware linkage.
- `/audit` for framework mapping and control classification.
- `/assess` for posture readouts, risk order, and confidence notes.
- `/validate` for narrow FIPS validation questions.
- Official FedRAMP Consolidated Rules lookups and generated docs under [`/docs/fedramp/`](/docs/fedramp/).
- `fedramp_assess_readiness` when you want an operator-facing brief for a FedRAMP process or KSI instead of raw lookup data.
- `fedramp_plan_process_artifacts` and `fedramp_plan_ads_package` when you need a concrete trust-center and evidence rollout plan instead of another lookup.
- `fedramp_generate_ads_bundle` when you want grclanker to scaffold an ADS starter package you can actually start filling in.
- `fedramp_generate_ads_site` when you want a portable public trust-center site bundle customers can deploy in their own AWS, Azure, or GCP environment.
- The generated [tool catalog](/docs/tools/catalog/) lists all 241 domain tools and 7 compute backend tools, grouped the same way `grclanker tools` prints them.
- `aws_check_access`, `aws_assess_identity`, `aws_assess_logging_detection`, `aws_assess_org_guardrails`, `aws_assess_data_protection`, `aws_assess_network_security`, and `aws_export_audit_bundle` for read-only AWS account and organization posture work.
- `azure_check_access`, `azure_assess_identity`, `azure_assess_monitoring`, `azure_assess_subscription_guardrails`, `azure_assess_data_protection`, `azure_assess_network_and_policy`, and `azure_export_audit_bundle` for read-only Azure tenant and subscription posture work.
- `gcp_check_access`, `gcp_assess_identity`, `gcp_assess_logging_detection`, `gcp_assess_org_guardrails`, `gcp_assess_data_protection`, `gcp_assess_network_security`, and `gcp_export_audit_bundle` for read-only GCP organization and project posture work.
- `oci_check_access`, `oci_assess_identity`, `oci_assess_logging_detection`, `oci_assess_tenancy_guardrails`, `oci_assess_compute_and_storage`, and `oci_export_audit_bundle` for read-only OCI tenancy and compartment posture work.
- `cloudflare_check_access`, `cloudflare_assess_identity`, `cloudflare_assess_zone_security`, `cloudflare_assess_traffic_controls`, and `cloudflare_export_audit_bundle` for read-only Cloudflare account and zone posture work.
- `webex_check_access`, `webex_assess_identity`, `webex_assess_collaboration_governance`, `webex_assess_meeting_hybrid_security`, and `webex_export_audit_bundle` for read-only Webex organization posture work.
- `zoom_check_access`, `zoom_assess_identity`, `zoom_assess_collaboration_governance`, `zoom_assess_meeting_security`, and `zoom_export_audit_bundle` for read-only Zoom account posture work.
- `duo_check_access`, `duo_assess_authentication`, `duo_assess_admin_access`, `duo_assess_integrations`, `duo_assess_monitoring`, and `duo_export_audit_bundle` for read-only, multi-framework Duo posture work.
- `okta_check_access`, `okta_assess_authentication`, `okta_assess_admin_access`, `okta_assess_integrations`, `okta_assess_monitoring`, and `okta_export_audit_bundle` for read-only, multi-framework Okta posture work.
- `github_check_access`, `github_assess_org_access`, `github_assess_repo_protection`, `github_assess_actions_security`, `github_assess_code_security`, `github_assess_integrations`, and `github_export_audit_bundle` for read-only, multi-framework GitHub organization posture work.
- `gws_check_access`, `gws_assess_identity`, `gws_assess_admin_access`, `gws_assess_integrations`, `gws_assess_monitoring`, and `gws_export_audit_bundle` for read-only, multi-framework Google Workspace tenant posture work.
- `gws_ops_check_cli`, `gws_ops_investigate_alerts`, `gws_ops_trace_admin_activity`, `gws_ops_review_tokens`, and `gws_ops_collect_evidence_bundle` for optional, read-only Google Workspace CLI operator evidence collection.
- `slack_check_access`, `slack_assess_identity`, `slack_assess_admin_access`, `slack_assess_integrations`, `slack_assess_channel_governance`, `slack_assess_monitoring`, and `slack_export_audit_bundle` for read-only, multi-framework Slack Enterprise Grid posture work.
- `ansible_check_access`, `ansible_assess_job_health`, `ansible_assess_host_coverage`, `ansible_assess_platform_security`, and `ansible_export_audit_bundle` for read-only Ansible Automation Platform evidence collection.
- `box_check_access`, `box_assess_identity_access`, `box_assess_sharing_collaboration`, `box_assess_data_governance`, `box_assess_shield_monitoring`, and `box_export_audit_bundle` for read-only Box enterprise posture work.
- `crowdstrike_check_access`, `crowdstrike_assess_prevention_policies`, `crowdstrike_assess_response_readiness`, `crowdstrike_assess_device_firewall`, `crowdstrike_assess_sensor_coverage`, `crowdstrike_assess_access_governance`, and `crowdstrike_export_audit_bundle` for read-only CrowdStrike Falcon posture work.
- `datadog_check_access`, `datadog_assess_identity`, `datadog_assess_access_controls`, `datadog_assess_data_protection`, `datadog_assess_security_monitoring`, and `datadog_export_audit_bundle` for read-only Datadog organization posture work.
- `elastic_check_access`, `elastic_assess_identity`, `elastic_assess_access_control`, `elastic_assess_transport_security`, `elastic_assess_cluster_hardening`, `elastic_assess_kibana`, and `elastic_export_audit_bundle` for read-only Elasticsearch and Kibana posture work.
- `knowbe4_check_access`, `knowbe4_assess_phishing_program`, `knowbe4_assess_training_program`, `knowbe4_assess_user_risk`, `knowbe4_assess_account_governance`, and `knowbe4_export_audit_bundle` for read-only KnowBe4 KMSAT program posture work.
- `launchdarkly_check_access`, `launchdarkly_assess_identity`, `launchdarkly_assess_access_control`, `launchdarkly_assess_environment_governance`, `launchdarkly_assess_flag_hygiene`, `launchdarkly_assess_monitoring_integrations`, and `launchdarkly_export_audit_bundle` for read-only LaunchDarkly account posture work.
- `mulesoft_check_access`, `mulesoft_assess_identity_access`, `mulesoft_assess_api_gateway`, `mulesoft_assess_runtime_infrastructure`, `mulesoft_assess_audit_monitoring`, and `mulesoft_export_audit_bundle` for read-only MuleSoft Anypoint Platform posture work.
- `newrelic_check_access`, `newrelic_assess_identity`, `newrelic_assess_access_control`, `newrelic_assess_alerting`, `newrelic_assess_data_governance`, and `newrelic_export_audit_bundle` for read-only New Relic organization posture work.
- `pagerduty_check_access`, `pagerduty_assess_access_control`, `pagerduty_assess_incident_response`, `pagerduty_assess_oncall_coverage`, `pagerduty_assess_audit_logging`, `pagerduty_assess_integration_security`, and `pagerduty_export_audit_bundle` for read-only PagerDuty account posture work.
- `paloalto_check_access`, `paloalto_assess_cloud_posture`, `paloalto_assess_firewall_policy`, `paloalto_assess_threat_prevention`, `paloalto_assess_device_hardening`, and `paloalto_export_audit_bundle` for read-only Prisma Cloud and PAN-OS posture work.
- `qualys_check_access`, `qualys_assess_scan_coverage`, `qualys_assess_asset_inventory`, `qualys_assess_vulnerability_management`, `qualys_assess_administration`, and `qualys_export_audit_bundle` for read-only Qualys scanning program posture work.
- `salesforce_check_access`, `salesforce_assess_identity_access`, `salesforce_assess_platform_security`, `salesforce_assess_data_protection`, `salesforce_assess_monitoring_integrations`, and `salesforce_export_audit_bundle` for read-only Salesforce org posture work.
- `servicenow_check_access`, `servicenow_assess_identity_access`, `servicenow_assess_access_control`, `servicenow_assess_platform_hardening`, `servicenow_assess_operations_governance`, and `servicenow_export_audit_bundle` for read-only ServiceNow instance posture work.
- `snowflake_check_access`, `snowflake_assess_network_and_authentication`, `snowflake_assess_access_control`, `snowflake_assess_data_protection`, `snowflake_assess_monitoring_and_lifecycle`, and `snowflake_export_audit_bundle` for read-only Snowflake account posture work.
- `splunk_check_access`, `splunk_assess_authentication`, `splunk_assess_access_control`, `splunk_assess_data_protection`, `splunk_assess_audit_monitoring`, `splunk_assess_platform_hardening`, and `splunk_export_audit_bundle` for read-only Splunk Enterprise and Splunk Cloud Platform posture work.
- `sumologic_check_access`, `sumologic_assess_identity`, `sumologic_assess_access_control`, `sumologic_assess_data_governance`, `sumologic_assess_content_sharing`, and `sumologic_export_audit_bundle` for read-only Sumo Logic organization posture work.
- `tenable_check_access`, `tenable_assess_scan_program`, `tenable_assess_sensor_coverage`, `tenable_assess_access_control`, `tenable_assess_vulnerability_management`, and `tenable_export_audit_bundle` for read-only Tenable Vulnerability Management and Security Center posture work.
- `vanta_check_access`, `vanta_list_audits`, and `vanta_export_audit` for pulling an offline Vanta audit evidence package.
- `veracode_check_access`, `veracode_assess_scan_coverage`, `veracode_assess_policy_compliance`, `veracode_assess_findings_hygiene`, `veracode_assess_sca_posture`, `veracode_assess_access_controls`, and `veracode_export_audit_bundle` for read-only Veracode application security program posture work.
- `zendesk_check_access`, `zendesk_assess_authentication`, `zendesk_assess_access_control`, `zendesk_assess_data_protection`, `zendesk_assess_integrations`, and `zendesk_export_audit_bundle` for read-only Zendesk Support posture work.
- `zscaler_check_access`, `zscaler_assess_zia_access_control`, `zscaler_assess_zia_policy`, `zscaler_assess_zpa`, and `zscaler_export_audit_bundle` for read-only Zscaler ZIA and ZPA posture work.
- Repo specs as build inputs under [`/specs`](/specs) and [`/docs/specs/using-specs-as-inputs/`](/docs/specs/using-specs-as-inputs/).

## Important Release Note

`0.0.1` is experimental on purpose. The bundle installer and local-first runtime path are real. The feature surface, setup flow, and docs structure will keep moving quickly.

macOS and Linux are the recommended platforms right now. Windows is best-effort and not a priority for the first experimental release.
