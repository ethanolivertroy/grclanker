## Purpose

Give security and compliance teams a read-only, repeatable view of Okta authentication, privileged access, application, lifecycle, and monitoring posture without treating unavailable tenant evidence as compliance.

## Design guidance

Use a dedicated least-privilege audit principal. Preserve tenant, edition, and permission limitations as evidence. Keep manual checks when Okta exposes no decisive read surface, and treat every output as sensitive identity-governance evidence. Retry rate limits, server errors, timeouts, and transport failures a bounded number of times, then record the dataset as unreadable rather than keeping the pages read before the failure as a complete inventory.
