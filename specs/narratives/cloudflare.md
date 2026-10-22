## Purpose

Give security and compliance teams a read-only, repeatable view of Cloudflare identity, zone, edge, and Zero Trust controls without treating an unlicensed, denied, or unreadable feature as compliant.

## Design guidance

Prefer a scoped API token over a Global API Key. Select an account explicitly when more than one is visible. Preserve plan limitations, per-zone read failures, pagination state, and configured sampling caps as evidence. Report the access check failed only when every probe sent draws a 401 or a documented invalid-credential error, matched on code and message together, because 9109 also answers an IP-filtered or out-of-scope token and 10000 is a permission denial.
