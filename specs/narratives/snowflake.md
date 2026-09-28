## Purpose

Assess Snowflake network, authentication, access-control, monitoring, retention, stage, sharing, policy, and warehouse posture through read-only SQL.

## Design guidance

Guard every statement as read-only, poll asynchronous statements and fetch every partition, and interpret empty results only in light of the caller role and exact ACCOUNT_USAGE visibility.
