---
title: KEV / EPSS
description: Search the public CISA Known Exploited Vulnerabilities catalog and FIRST EPSS scores. No tenant credentials.
---

The KEV tools read two public feeds. They do not sign in to a tenant, and they do not change any data.

- The CISA Known Exploited Vulnerabilities catalog, published at `https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json`. grclanker caches that file for four hours.
- FIRST EPSS scores, from `https://api.first.org/data/v1/epss`. A score is the estimated probability that a CVE is exploited in the next 30 days. When the API includes a score date, the tools show it.

Search matches a CVE ID, vendor, product, vulnerability name, or short description. When the query is a CVE ID, that CVE's own entry comes first, ahead of other matches such as entries whose descriptions cite it. Ransomware results are the catalog entries marked as known ransomware campaign use.

## Run it

Start `grclanker` and ask in plain words. The agent calls the matching tools, for example:

```text
Is CVE-2024-3400 in the CISA KEV catalog, and what is its EPSS score?
Which vulnerabilities were added to the CISA KEV catalog in the last 30 days?
Which KEV entries for this vendor are linked to known ransomware campaigns?
```

The same four tools cover the vulnerability step in the [investigate](/docs/workflows/investigate/) workflow.

## Tools

| Tool | What it answers | Defaults |
| --- | --- | --- |
| `kevs_search` | Which catalog entries match a CVE, vendor, product, or keyword, with an EPSS score for each shown entry | `limit` defaults to 10. A value below 1 uses 10. A value above 50 is capped at 50. When the limit leaves entries out, the reply says how many matched |
| `kevs_get_epss` | The EPSS score and percentile for one or more CVE IDs, including CVEs that are not in the KEV catalog | Pass `cve_ids`. There is no result cap |
| `kevs_recent` | Catalog entries added in a recent window, newest first, with EPSS scores | `days` defaults to 30. A negative lookback, including a fraction such as `-0.5`, uses 30. `0` means entries added today. `limit` defaults to 10, and a value below 1 uses 10. When the limit leaves entries out, the reply says how many were added |
| `kevs_check_ransomware` | Catalog entries with known ransomware campaign use, newest first. An optional `vendor` keeps entries whose vendor or product name contains that text | `limit` defaults to 20. A value below 1 uses 20 |

Scores above 10% are usually worth fast triage. That note is part of the `kevs_get_epss` reply.
