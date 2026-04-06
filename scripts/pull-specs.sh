#!/usr/bin/env bash
# One-time migration script: pulls spec.md from 31 individual repos,
# prepends YAML frontmatter, and saves to specs/{tool-name}.spec.md
#
# Requires: gh (GitHub CLI), base64, bash 3.2+
# Usage: cd grclanker && bash scripts/pull-specs.sh

set -euo pipefail

SPECS_DIR="$(cd "$(dirname "$0")/.." && pwd)/specs"
OWNER="hackIDLE"
SUCCESS=0
FAIL=0

mkdir -p "$SPECS_DIR"

fetch_spec() {
  local repo="$1"
  local name="$2"
  local vendor="$3"
  local category="$4"
  local outfile="$SPECS_DIR/${repo}.spec.md"

  echo "Fetching ${repo}..."

  local content
  content=$(gh api "repos/${OWNER}/${repo}/contents/spec.md" --jq '.content' 2>/dev/null | base64 -d 2>/dev/null) || {
    echo "  FAILED: ${repo}"
    FAIL=$((FAIL + 1))
    return 1
  }

  cat > "$outfile" <<FRONTMATTER
---
slug: "${repo}"
name: "${name}"
vendor: "${vendor}"
category: "${category}"
language: "go"
status: "spec-only"
version: "1.0"
source_repo: "https://github.com/${OWNER}/${repo}"
---

FRONTMATTER

  echo "$content" >> "$outfile"
  echo "  OK: ${outfile##*/}"
  SUCCESS=$((SUCCESS + 1))
}

# Cloud Infrastructure
fetch_spec "aws-sec-inspector"        "AWS Security Inspector"        "Amazon Web Services"  "cloud-infrastructure"
fetch_spec "azure-sec-inspector"      "Azure Security Inspector"      "Microsoft"            "cloud-infrastructure"
fetch_spec "gcp-sec-inspector"        "GCP Security Inspector"        "Google Cloud"         "cloud-infrastructure"
fetch_spec "oci-sec-inspector"        "OCI Security Inspector"        "Oracle"               "cloud-infrastructure"
fetch_spec "snowflake-sec-inspector"  "Snowflake Security Inspector"  "Snowflake"            "cloud-infrastructure"

# Identity & Access Management
fetch_spec "duo-sec-inspector"        "Duo Security Inspector"              "Cisco"   "identity-access-management"
fetch_spec "gws-inspector-go"         "Google Workspace Inspector"          "Google"  "identity-access-management"

# Security & Network Infrastructure
fetch_spec "crowdstrike-sec-inspector"  "CrowdStrike Security Inspector"  "CrowdStrike"        "security-network-infrastructure"
fetch_spec "paloalto-sec-inspector"     "Palo Alto Security Inspector"    "Palo Alto Networks"  "security-network-infrastructure"
fetch_spec "zscaler-sec-inspector"      "Zscaler Security Inspector"      "Zscaler"            "security-network-infrastructure"
fetch_spec "cloudflare-sec-inspector"   "Cloudflare Security Inspector"   "Cloudflare"         "security-network-infrastructure"

# Vulnerability & Application Security
fetch_spec "qualys-sec-inspector"     "Qualys Security Inspector"     "Qualys"   "vulnerability-application-security"
fetch_spec "tenable-sec-inspector"    "Tenable Security Inspector"    "Tenable"  "vulnerability-application-security"
fetch_spec "veracode-sec-inspector"   "Veracode Security Inspector"   "Veracode" "vulnerability-application-security"
fetch_spec "knowbe4-sec-inspector"    "KnowBe4 Security Inspector"    "KnowBe4"  "vulnerability-application-security"

# Monitoring, Logging & Observability
fetch_spec "splunk-sec-inspector"     "Splunk Security Inspector"     "Splunk"     "monitoring-logging-observability"
fetch_spec "datadog-sec-inspector"    "Datadog Security Inspector"    "Datadog"    "monitoring-logging-observability"
fetch_spec "newrelic-sec-inspector"   "New Relic Security Inspector"  "New Relic"  "monitoring-logging-observability"
fetch_spec "sumologic-sec-inspector"  "Sumo Logic Security Inspector" "Sumo Logic" "monitoring-logging-observability"
fetch_spec "elastic-sec-inspector"    "Elastic Security Inspector"    "Elastic"    "monitoring-logging-observability"

# SaaS & Collaboration
fetch_spec "salesforce-sec-inspector"   "Salesforce Security Inspector"   "Salesforce"   "saas-collaboration"
fetch_spec "servicenow-sec-inspector"   "ServiceNow Security Inspector"   "ServiceNow"   "saas-collaboration"
fetch_spec "slack-sec-inspector"        "Slack Security Inspector"        "Slack"        "saas-collaboration"
fetch_spec "zoom-sec-inspector"         "Zoom Security Inspector"         "Zoom"         "saas-collaboration"
fetch_spec "webex-sec-inspector"        "Webex Security Inspector"        "Cisco"        "saas-collaboration"
fetch_spec "zendesk-sec-inspector"      "Zendesk Security Inspector"      "Zendesk"      "saas-collaboration"
fetch_spec "box-sec-inspector"          "Box Security Inspector"          "Box"          "saas-collaboration"

# DevOps & Developer Platforms
fetch_spec "github-sec-inspector"       "GitHub Security Inspector"       "GitHub"       "devops-developer-platforms"
fetch_spec "pagerduty-sec-inspector"    "PagerDuty Security Inspector"    "PagerDuty"    "devops-developer-platforms"
fetch_spec "launchdarkly-sec-inspector" "LaunchDarkly Security Inspector" "LaunchDarkly" "devops-developer-platforms"
fetch_spec "mulesoft-sec-inspector"     "MuleSoft Security Inspector"     "MuleSoft"     "devops-developer-platforms"

echo ""
echo "Done. ${SUCCESS} succeeded, ${FAIL} failed."
