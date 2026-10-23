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

## When a feed fails

Each request to either feed gets up to four attempts, and each attempt times out after 30 seconds. A timeout, a network error, or a `429`, `500`, `502`, `503`, or `504` answer is retried after the wait the feed's `Retry-After` header asks for, or after 1, 2, and then 4 seconds when it names none. Any other error, such as `404`, is not retried, and neither is an answer that asks for a wait longer than 30 seconds. The final error names the feed URL without its query string and, when the request was retried, the number of attempts. A failed read is never cached, so the next call tries the feed again.

When the retries run out:

- **KEV catalog.** `kevs_search`, `kevs_recent`, and `kevs_check_ransomware` fail with the error. None of them answers "no matches" from a catalog it could not read.
- **EPSS in `kevs_get_epss`.** CVE IDs are scored in batches of 100. Each CVE ID from a batch that failed shows `Unavailable`, the heading ends in `(incomplete)`, and a note gives the error. `Not scored` still means EPSS answered and had no score for that CVE ID. The result sets `incomplete` and lists the affected IDs under `unavailable`. When no batch succeeds, the tool fails instead of reporting that no scores were found.
- **EPSS in `kevs_search` and `kevs_recent`.** The catalog entries still come back. Each entry whose score could not be read shows `EPSS: Unavailable (the EPSS API request failed)`, and a closing note says how many entries lack a score and why. The result sets `epss_incomplete` and lists those IDs under `epss_unavailable`.
