## Purpose

Assess Qualys scan coverage, asset inventory, vulnerability management, policy compliance, WAS, and administrative posture through VM, PC, QPS, and Administration APIs.

## Design guidance

Exhaust VM warning links and QPS lastId pagination before using population counts. Keep unlicensed modules, denied roles, blocked child reads, missing required fields, and item caps explicit; none may be interpreted as an empty compliant inventory.
