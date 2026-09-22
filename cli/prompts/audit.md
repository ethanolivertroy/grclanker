# Compliance Audit

Run a structured compliance audit for the specified system, product, or deployment.

## Phase 1: Scope Lock

Confirm:
1. Target environment, product, or vendor
2. Framework(s) in scope
3. Evidence boundary: documentation only, live config only, or both
4. Required output format: executive summary, control matrix, or remediation plan

## Phase 2: Evidence Collection

Use the available GRC tools first:
1. Search CMVP validation status where cryptography is in scope
2. Search KEV and EPSS data for active exploit pressure
3. If FedRAMP or FedRAMP 20x is in scope, start with `fedramp_check_sources`, then use `fedramp_search_frmr`, `fedramp_get_process`, `fedramp_get_requirement`, and `fedramp_get_ksi` to ground your interpretation in the official FedRAMP GitHub sources
4. When you need a practical operator brief instead of raw source data, use `fedramp_assess_readiness` on the relevant process or KSI
5. When you need to turn a FedRAMP process into a concrete publishing and evidence plan, use `fedramp_plan_process_artifacts`
6. If the scope centers on Certification Data Sharing or trust-center rollout, use `fedramp_plan_ads_package`
7. If you want a working ADS starter scaffold instead of only a plan, use `fedramp_generate_ads_bundle`
8. If the team needs a public, customer-owned trust-center site they can deploy to AWS, Azure, or GCP, use `fedramp_generate_ads_site`
9. If the scope is an AWS account or organization, start with `aws_check_access`, then use `aws_assess_identity`, `aws_assess_logging_detection`, `aws_assess_org_guardrails`, `aws_assess_data_protection`, and `aws_assess_network_security`, or `aws_export_audit_bundle` when the deliverable needs a zipped evidence package
10. If the scope is an Azure tenant and subscription, start with `azure_check_access`, then use `azure_assess_identity`, `azure_assess_monitoring`, `azure_assess_subscription_guardrails`, `azure_assess_data_protection`, and `azure_assess_network_and_policy`, or `azure_export_audit_bundle` when the deliverable needs a zipped evidence package
11. If the scope is a GCP organization or project, start with `gcp_check_access`, then use `gcp_assess_identity`, `gcp_assess_logging_detection`, `gcp_assess_org_guardrails`, `gcp_assess_data_protection`, and `gcp_assess_network_security`, or `gcp_export_audit_bundle` when the deliverable needs a zipped evidence package
12. If the scope is an OCI tenancy or compartment, start with `oci_check_access`, then use `oci_assess_identity`, `oci_assess_logging_detection`, `oci_assess_tenancy_guardrails`, and `oci_assess_compute_and_storage`, or `oci_export_audit_bundle` when the deliverable needs a zipped evidence package
13. If the scope is a Cloudflare account or zone portfolio, start with `cloudflare_check_access`, then use `cloudflare_assess_identity`, `cloudflare_assess_zone_security`, and `cloudflare_assess_traffic_controls`, or `cloudflare_export_audit_bundle` when the deliverable needs a zipped evidence package
14. If the scope is a Duo tenant, start with `duo_check_access`, then run the focused Duo assessment that matches the question before falling back to `duo_export_audit_bundle`
15. If the scope is an Okta tenant, start with `okta_check_access`, then run the focused assessment that matches the question before falling back to `okta_export_audit_bundle`
16. If the scope is a GitHub organization, start with `github_check_access`, then run the focused GitHub assessment that matches the question before falling back to `github_export_audit_bundle`
17. If the scope is a Google Workspace tenant, start with `gws_check_access`, then run the focused GWS assessment that matches the question before falling back to `gws_export_audit_bundle`
18. If the Google Workspace task is really operator-side investigation or raw evidence collection and `gws` is installed, use `gws_ops_check_cli`, then the focused `gws_ops_*` tools for alerts, admin activity, token activity, or the separate operator evidence bundle
19. If the scope is a Slack Enterprise Grid tenant, start with `slack_check_access`, then use `slack_assess_identity`, `slack_assess_admin_access`, `slack_assess_integrations`, `slack_assess_channel_governance`, and `slack_assess_monitoring`, or `slack_export_audit_bundle` when the deliverable needs a zipped evidence package
20. If the scope is a Webex organization, start with `webex_check_access`, then use `webex_assess_identity`, `webex_assess_collaboration_governance`, and `webex_assess_meeting_hybrid_security`, or `webex_export_audit_bundle` when the deliverable needs a zipped evidence package
21. If the scope is a Zoom account, start with `zoom_check_access`, then use `zoom_assess_identity`, `zoom_assess_collaboration_governance`, and `zoom_assess_meeting_security`, or `zoom_export_audit_bundle` when the deliverable needs a zipped evidence package
22. If the scope is an Ansible Automation Platform tenant, start with `ansible_check_access`, then use `ansible_assess_job_health`, `ansible_assess_host_coverage`, and `ansible_assess_platform_security`, or `ansible_export_audit_bundle` when the deliverable needs a zipped evidence package
23. If the scope is a Box enterprise, start with `box_check_access`, then use `box_assess_identity_access`, `box_assess_sharing_collaboration`, `box_assess_data_governance`, and `box_assess_shield_monitoring`, or `box_export_audit_bundle` when the deliverable needs a zipped evidence package
24. If the scope is a CrowdStrike Falcon tenant, start with `crowdstrike_check_access`, then use `crowdstrike_assess_prevention_policies`, `crowdstrike_assess_response_readiness`, `crowdstrike_assess_device_firewall`, `crowdstrike_assess_sensor_coverage`, and `crowdstrike_assess_access_governance`, or `crowdstrike_export_audit_bundle` when the deliverable needs a zipped evidence package
25. If the scope is a Datadog organization, start with `datadog_check_access`, then use `datadog_assess_identity`, `datadog_assess_access_controls`, `datadog_assess_data_protection`, and `datadog_assess_security_monitoring`, or `datadog_export_audit_bundle` when the deliverable needs a zipped evidence package
26. If the scope is an Elasticsearch cluster or Kibana deployment, start with `elastic_check_access`, then use `elastic_assess_identity`, `elastic_assess_access_control`, `elastic_assess_transport_security`, `elastic_assess_cluster_hardening`, and `elastic_assess_kibana`, or `elastic_export_audit_bundle` when the deliverable needs a zipped evidence package
27. If the scope is a KnowBe4 KMSAT account, start with `knowbe4_check_access`, then use `knowbe4_assess_phishing_program`, `knowbe4_assess_training_program`, `knowbe4_assess_user_risk`, and `knowbe4_assess_account_governance`, or `knowbe4_export_audit_bundle` when the deliverable needs a zipped evidence package
28. If the scope is a LaunchDarkly account, start with `launchdarkly_check_access`, then use `launchdarkly_assess_identity`, `launchdarkly_assess_access_control`, `launchdarkly_assess_environment_governance`, `launchdarkly_assess_flag_hygiene`, and `launchdarkly_assess_monitoring_integrations`, or `launchdarkly_export_audit_bundle` when the deliverable needs a zipped evidence package
29. If the scope is a MuleSoft Anypoint Platform organization, start with `mulesoft_check_access`, then use `mulesoft_assess_identity_access`, `mulesoft_assess_api_gateway`, `mulesoft_assess_runtime_infrastructure`, and `mulesoft_assess_audit_monitoring`, or `mulesoft_export_audit_bundle` when the deliverable needs a zipped evidence package
30. If the scope is a New Relic organization, start with `newrelic_check_access`, then use `newrelic_assess_identity`, `newrelic_assess_access_control`, `newrelic_assess_alerting`, and `newrelic_assess_data_governance`, or `newrelic_export_audit_bundle` when the deliverable needs a zipped evidence package
31. If the scope is a PagerDuty account, start with `pagerduty_check_access`, then use `pagerduty_assess_access_control`, `pagerduty_assess_incident_response`, `pagerduty_assess_oncall_coverage`, `pagerduty_assess_audit_logging`, and `pagerduty_assess_integration_security`, or `pagerduty_export_audit_bundle` when the deliverable needs a zipped evidence package
32. If the scope is a Palo Alto Networks Prisma Cloud tenant or PAN-OS estate, start with `paloalto_check_access`, then use `paloalto_assess_cloud_posture`, `paloalto_assess_firewall_policy`, `paloalto_assess_threat_prevention`, and `paloalto_assess_device_hardening`, or `paloalto_export_audit_bundle` when the deliverable needs a zipped evidence package
33. If the scope is a Qualys scanning program, start with `qualys_check_access`, then use `qualys_assess_scan_coverage`, `qualys_assess_asset_inventory`, `qualys_assess_vulnerability_management`, and `qualys_assess_administration`, or `qualys_export_audit_bundle` when the deliverable needs a zipped evidence package
34. If the scope is a Salesforce org, start with `salesforce_check_access`, then use `salesforce_assess_identity_access`, `salesforce_assess_platform_security`, `salesforce_assess_data_protection`, and `salesforce_assess_monitoring_integrations`, or `salesforce_export_audit_bundle` when the deliverable needs a zipped evidence package
35. If the scope is a ServiceNow instance, start with `servicenow_check_access`, then use `servicenow_assess_identity_access`, `servicenow_assess_access_control`, `servicenow_assess_platform_hardening`, and `servicenow_assess_operations_governance`, or `servicenow_export_audit_bundle` when the deliverable needs a zipped evidence package
36. If the scope is a Snowflake account, start with `snowflake_check_access`, then use `snowflake_assess_network_and_authentication`, `snowflake_assess_access_control`, `snowflake_assess_data_protection`, and `snowflake_assess_monitoring_and_lifecycle`, or `snowflake_export_audit_bundle` when the deliverable needs a zipped evidence package
37. If the scope is a Splunk Enterprise or Splunk Cloud Platform deployment, start with `splunk_check_access`, then use `splunk_assess_authentication`, `splunk_assess_access_control`, `splunk_assess_data_protection`, `splunk_assess_audit_monitoring`, and `splunk_assess_platform_hardening`, or `splunk_export_audit_bundle` when the deliverable needs a zipped evidence package
38. If the scope is a Sumo Logic organization, start with `sumologic_check_access`, then use `sumologic_assess_identity`, `sumologic_assess_access_control`, `sumologic_assess_data_governance`, and `sumologic_assess_content_sharing`, or `sumologic_export_audit_bundle` when the deliverable needs a zipped evidence package
39. If the scope is a Tenable Vulnerability Management or Security Center deployment, start with `tenable_check_access`, then use `tenable_assess_scan_program`, `tenable_assess_sensor_coverage`, `tenable_assess_access_control`, and `tenable_assess_vulnerability_management`, or `tenable_export_audit_bundle` when the deliverable needs a zipped evidence package
40. If the scope is a Veracode application security program, start with `veracode_check_access`, then use `veracode_assess_scan_coverage`, `veracode_assess_policy_compliance`, `veracode_assess_findings_hygiene`, `veracode_assess_sca_posture`, and `veracode_assess_access_controls`, or `veracode_export_audit_bundle` when the deliverable needs a zipped evidence package
41. If the scope is a Zendesk Support instance, start with `zendesk_check_access`, then use `zendesk_assess_authentication`, `zendesk_assess_access_control`, `zendesk_assess_data_protection`, and `zendesk_assess_integrations`, or `zendesk_export_audit_bundle` when the deliverable needs a zipped evidence package
42. If the scope is a Zscaler ZIA or ZPA tenant, start with `zscaler_check_access`, then use `zscaler_assess_zia_access_control`, `zscaler_assess_zia_policy`, and `zscaler_assess_zpa`, or `zscaler_export_audit_bundle` when the deliverable needs a zipped evidence package
43. If the scope is a Vanta audit, start with `vanta_check_access`, then use `vanta_list_audits` and `vanta_export_audit` to pull an offline evidence package before classifying controls
44. If you need control language, crosswalk mappings, or artifact guidance, use `scf_search_controls`, `scf_get_control`, `scf_get_crosswalk`, and `scf_get_evidence_request`
45. If the deliverable needs to become a portable OSCAL artifact, start with `oscal_check_trestle`, then use `oscal_init_workspace`, `oscal_import_model` or `oscal_create_model`, and the SSP helpers as needed
46. Collect certificate numbers, CVE IDs, due dates, and source URLs inline

If evidence is missing, say exactly what is missing and what artifact would close the gap.

## Phase 3: Control Mapping

Map findings explicitly to the requested framework. At minimum, evaluate:
- **SC-13 / cryptographic protection**
- **SC-12 / key management**
- **SI-2 / flaw remediation**
- **RA-5 / vulnerability monitoring**

For each control, classify:
- Satisfied
- Partially Satisfied
- Not Satisfied
- Unable to Assess

## Phase 4: Prioritization

Rank issues by:
1. Exploitability
2. Compliance impact
3. Operational blast radius
4. Remediation effort

Use EPSS and KEV status when vulnerability data exists.

## Phase 5: Deliverable

Return:
1. **Audit summary** — what was assessed and overall posture
2. **Control-by-control findings** — with evidence
3. **Critical gaps** — highest-risk issues first
4. **Remediation plan** — concrete next actions with rough effort

Do not infer compliance without evidence. Mark unknowns as unknowns.
