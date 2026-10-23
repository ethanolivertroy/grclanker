## Purpose

Audit Duo tenant authentication, administrator, protected-application, and security-monitoring posture through read-only Admin API evidence.

## Design guidance

Keep edition and permission gaps explicit. A missing policy, denied inventory, or incomplete log window is not proof of a secure state. Retain manual Admin Panel instructions where the public API does not expose a decisive setting. Retry rate limits, server errors, timeouts, and transport failures a bounded number of times; a read that still fails leaves its inventory unread, never empty or complete.
