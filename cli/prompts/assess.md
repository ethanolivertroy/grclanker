# Posture Assessment

Assess the overall security and compliance posture of the specified vendor, product, module, or environment.

## Phase 1: Baseline

Establish:
1. What system is being assessed
2. Which frameworks matter most
3. Whether the focus is cryptography, vulnerabilities, or general posture

## Phase 2: Signal Gathering

Use the GRC tools to gather high-signal evidence:
1. CMVP certificate status
2. Historical or expired modules
3. KEV exposure
4. EPSS likelihood for any matched CVEs
5. Ransomware linkage where applicable
6. If FedRAMP or FedRAMP 20x framing matters, use `fedramp_check_sources`, `fedramp_search_frmr`, `fedramp_get_process`, `fedramp_get_requirement`, and `fedramp_get_ksi` so the posture narrative stays grounded in the official FedRAMP GitHub sources
7. If you need a practical provider or trust-center brief for a FedRAMP process or KSI, use `fedramp_assess_readiness`
8. If you need a concrete publication and evidence plan for a FedRAMP process or KSI, use `fedramp_plan_process_artifacts`
9. If the posture work is really about ADS or trust-center rollout, use `fedramp_plan_ads_package`
10. If the team is ready for a scaffold instead of another plan, use `fedramp_generate_ads_bundle`
11. If the team needs a public ADS trust-center site they can host in AWS, Azure, or GCP, use `fedramp_generate_ads_site`
12. If the subject is an AWS account or organization, start with `aws_check_access`, then use `aws_assess_identity`, `aws_assess_logging_detection`, and `aws_assess_org_guardrails`, or `aws_export_audit_bundle` to ground posture claims in collected AWS evidence
13. If the subject is an Azure tenant and subscription, start with `azure_check_access`, then use `azure_assess_identity`, `azure_assess_monitoring`, and `azure_assess_subscription_guardrails`, or `azure_export_audit_bundle` to ground posture claims in collected Azure evidence
14. If the subject is a GCP organization or project, start with `gcp_check_access`, then use `gcp_assess_identity`, `gcp_assess_logging_detection`, and `gcp_assess_org_guardrails`, or `gcp_export_audit_bundle` to ground posture claims in collected GCP evidence
15. If the subject is an OCI tenancy or compartment, start with `oci_check_access`, then use `oci_assess_identity`, `oci_assess_logging_detection`, and `oci_assess_tenancy_guardrails`, or `oci_export_audit_bundle` to ground posture claims in collected OCI evidence
16. If the subject is a Cloudflare account or zone portfolio, start with `cloudflare_check_access`, then use `cloudflare_assess_identity`, `cloudflare_assess_zone_security`, and `cloudflare_assess_traffic_controls`, or `cloudflare_export_audit_bundle` to ground posture claims in collected Cloudflare evidence
17. If the subject is a Duo tenant, start with `duo_check_access`, then use the focused Duo assessment tools or `duo_export_audit_bundle` to ground posture claims in collected tenant evidence
18. If the subject is an Okta tenant, start with `okta_check_access`, then use the focused Okta assessment tools or `okta_export_audit_bundle` to ground posture claims in collected tenant evidence
19. If the subject is a GitHub organization, start with `github_check_access`, then use the focused GitHub assessment tools or `github_export_audit_bundle` to ground posture claims in collected org evidence
20. If the subject is a Google Workspace tenant, start with `gws_check_access`, then use the focused GWS assessment tools or `gws_export_audit_bundle` to ground posture claims in collected tenant evidence
21. If the Google Workspace task is really operator-side investigation or raw evidence collection and `gws` is installed, use `gws_ops_check_cli` and the focused `gws_ops_*` workflows instead of stretching the native posture tools past their purpose
22. If the subject is a Slack Enterprise Grid tenant, start with `slack_check_access`, then use `slack_assess_identity`, `slack_assess_admin_access`, `slack_assess_integrations`, and `slack_assess_monitoring`, or `slack_export_audit_bundle` when you need a zipped evidence package
23. If the subject is a Webex organization, start with `webex_check_access`, then use `webex_assess_identity`, `webex_assess_collaboration_governance`, and `webex_assess_meeting_hybrid_security`, or `webex_export_audit_bundle` when you need a zipped evidence package
24. If the subject is an Ansible Automation Platform tenant or automation program, start with `ansible_check_access`, then use `ansible_assess_job_health`, `ansible_assess_host_coverage`, and `ansible_assess_platform_security`, or `ansible_export_audit_bundle` when you need a zipped evidence package
25. SCF control language, crosswalks, and evidence-request guidance when framework interpretation matters
26. If the assessment needs to roll into OSCAL artifacts, use the OSCAL trestle tools to scaffold or validate the SSP, SAR, or POA&M workspace content

## Phase 3: Posture Classification

Summarize the subject as:
- Strong
- Mixed
- At Risk
- Critical

Justify the classification using evidence, not adjectives.

## Phase 4: Findings

Organize findings into:
1. **Cryptographic assurance**
2. **Exploit exposure**
3. **Framework impact**
4. **Operational risk**

Call out expired certifications, missing validation, overdue KEV remediation, and high-EPSS CVEs.

## Phase 5: Output

Return:
1. **Executive posture summary**
2. **Evidence table** — certificate numbers, CVEs, dates, and sources
3. **Top 3 risks**
4. **Top 3 next actions**
5. If requested, note the next OSCAL artifact to update: SSP, assessment results, or POA&M

Be direct. If the evidence is thin, say the assessment confidence is low.
