# Database-aware upgrade and recovery

This handoff covers the accepted v0.161.11 application source
`45da038c6209a7a5ad422dbde35d9a14c3bc62a6` to official v0.167.1
`efb619fb4857803ba90425f4fe5e1f8feede00a9`. The hardening base is
`faf35374213e8f3802cfae1ffb505241849322cd`, with official application code and
migrations unchanged. Bind deployment to the final reviewed source and published
image digest, and retain the accepted image digest separately.

The isolated synthetic upgrade from 467 to 584 migrations and the synthetic
backup/restore exercise passed during candidate qualification. Those results
establish the exercised fixture behavior. They do not establish production data
conversion, key availability, migration duration, or recovery of production
state. CI publication does not authorize a production rollout.

## Before scheduling production

1. Have the operator restore a current, protected PostgreSQL backup into a
   **separate isolated datastore**, with compatible Redis state and the same
   encryption-key/KMS/HSM configuration. Preserve the original backups, encryption
   keys, authentication configuration, Redis persistence, and any external
   recording/object storage needed for recovery. Keep credentials and restored
   data outside Git and CI artifacts. Prevent the restored application and its
   workers from contacting production services or sending notifications.
2. Run the exact candidate against that restored copy under operator control.
   Confirm the starting migration inventory, successful completion of all 584
   migrations, conversion summaries, representative data decryptability, and
   application behavior below. Measure elapsed time and storage requirements.
   This production-data rehearsal remains a prerequisite; the synthetic pass
   does not substitute for it.
3. Confirm deployed database versions and capacity against the
   [requirements](../docs/self-hosting/configuration/requirements.mdx): PostgreSQL
   14 or newer is recommended, with Redis 6.x/7.x and at least 6.2 advised. The
   inspected release interval introduces no separate database-version upgrade
   mandate. Concurrent index builds and data conversions still need time, disk
   headroom, and freedom from conflicting writers.
4. Resolve the applicable data and client changes below before selecting the
   maintenance window. Record the final image/configuration, backup recovery point,
   maintenance owner, and rollback destination using existing deployment records.

## Data and cutover checks

| Area | Required restored-copy check |
| --- | --- |
| Removed SSH and Agent Sentinel products | Inventory retained product data before upgrading. [This migration](../backend/src/db/migrations/20260729150000_drop-ssh-and-ai-mcp-tables.ts) drops their tables and has an empty `down()`. Preserve any required records through the backup/export process. |
| PAM | Verify account conversion, credentials and session recordings after the [revamp](../backend/src/db/migrations/20260612142201_pam-revamp.ts). Unsupported account types stop migration; session re-encryption errors can be logged and skipped, leaving recordings unreadable even when migration completes. Preserve `pam_revamp_backup` and the database backup. |
| MFA and encrypted rules | Exercise existing MFA users and recovery behavior after the [recovery-code backfill](../backend/src/db/migrations/20260701120200_add-mfa-recovery-codes.ts). Inspect [validation-rule conversion](../backend/src/db/migrations/20260908120000_secret-validation-rule-named-constraints.ts) warnings: unsupported constraints and duplicates can be discarded. Verify effective rules and decryptability with the retained keys. |
| Approvals and reminders | Inspect both [approval migration summaries](../backend/src/db/migrations/utils/approval-migration.ts), including failed checks, locked policies and errors. These policies remain legacy and do not fail the overall migration. [Reminder conversion](../backend/src/db/migrations/20260929130000_migrate-secret-reminders-to-alerts.ts) filters departed recipients and skips reminders whose listed recipients all departed. Verify resulting policy and alert coverage. |
| Other data cleanup | Check affected records for [orphan CA cleanup](../backend/src/db/migrations/20260909143802_internal-ca-parent-set-null-on-delete.ts), [duplicate PAM policy deletion](../backend/src/db/migrations/20260928120000_approval-policies-unique-pam-folder-scope.ts), and [secret-scanning cleanup](../backend/src/db/migrations/20260929120000_reshape-secret-scanning-v2-tables.ts). These transformations can delete rows or change behavior. |
| Agent Vault | Follow the coordinated pod/CLI/proxy cutover in [v0.166.5](../upgrade-impact/data/releases/v0.166.5.yaml) and [v0.166.6](../upgrade-impact/data/releases/v0.166.6.yaml). Session logs move to S3/Redis; old pods can fail after table/column removal. Verify recording storage and [renamed variable keys](../backend/src/db/migrations/20261012120000_agent-vault-variables-product-scope.ts). |
| Identity clients | Verify the specific credential-management permissions listed in [v0.166.6](../upgrade-impact/data/releases/v0.166.6.yaml), then exercise the existing Universal Auth consumers. Check applicable native-integration and Gateway changes in [v0.162.22](../upgrade-impact/data/releases/v0.162.22.yaml) and [v0.162.23](../upgrade-impact/data/releases/v0.162.23.yaml). |

Migrations normally run at startup. Some run outside a single transaction;
interruption can leave committed partial work. Examine the migration ledger and
logs before recovery or retry. Do not infer complete conversion from the migration
count alone. The [secret-change validation/index migration](../backend/src/db/migrations/20261002193922_secret-change-requests-validate-and-index.ts)
allows hour-long statements but only 30-second lock waits.

## Production acceptance and recovery

During the authorized window, quiesce old application writers and workers, capture
the final recoverable PostgreSQL/Redis state and required key/configuration
material, and apply the rehearsed coordinated cutover. Preserve external storage
and the accepted image. After startup, check migration completion and warnings,
login/MFA, secret decryption, existing Universal Auth consumers, approval behavior,
and enabled PAM/Agent Vault workflows. Readiness alone is insufficient. Resume
traffic and workers only after those checks succeed.

If acceptance fails, stop candidate writers and workers and retain the failed
datastores for diagnosis. Restore the preserved pre-upgrade PostgreSQL backup and
compatible Redis state into **separate recovery datastores**. Start the accepted
image with its matching keys/configuration against those restored datastores,
verify login, decryptability and consumers, then perform the operator-controlled
traffic cutback. Account explicitly for writes after the backup recovery point.

A Helm image rollback alone is insufficient: removed tables, converted data and
new writes may be incompatible with the old application. Individual `down()`
migrations are not a complete data recovery procedure; some are empty or restore
only empty schema. Do not point the accepted image at the upgraded database as a
substitute for the rehearsed restore.
