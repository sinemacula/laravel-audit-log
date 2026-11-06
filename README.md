<h1 align="center">Laravel Audit Log</h1>

<div align="center">

[![Latest Stable Version](https://img.shields.io/packagist/v/sinemacula/laravel-audit-log.svg)](https://packagist.org/packages/sinemacula/laravel-audit-log)
[![PHP Version](https://img.shields.io/packagist/dependency-v/sinemacula/laravel-audit-log/php.svg)](https://packagist.org/packages/sinemacula/laravel-audit-log)
[![Laravel Version](https://img.shields.io/packagist/dependency-v/sinemacula/laravel-audit-log/laravel/framework.svg?label=laravel)](https://packagist.org/packages/sinemacula/laravel-audit-log)
[![Build Status](https://github.com/sinemacula/laravel-audit-log/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/sinemacula/laravel-audit-log/actions/workflows/tests.yml)
[![Quality Gates](https://github.com/sinemacula/laravel-audit-log/actions/workflows/quality-gates.yml/badge.svg?branch=master)](https://github.com/sinemacula/laravel-audit-log/actions/workflows/quality-gates.yml)
[![Maintainability](https://qlty.sh/gh/sinemacula/projects/laravel-audit-log/maintainability.svg)](https://qlty.sh/gh/sinemacula/projects/laravel-audit-log)
[![Code Coverage](https://qlty.sh/gh/sinemacula/projects/laravel-audit-log/coverage.svg)](https://qlty.sh/gh/sinemacula/projects/laravel-audit-log)
[![Total Downloads](https://img.shields.io/packagist/dt/sinemacula/laravel-audit-log.svg)](https://packagist.org/packages/sinemacula/laravel-audit-log)
[![License](https://img.shields.io/github/license/sinemacula/laravel-audit-log.svg)](LICENSE)

</div>

Event-driven audit logging of user activity for Laravel. Records who did what, to what, on whose behalf and from where,
as append-only database rows behind a storage contract, so a custom store can take the place of the database.

Captures Laravel's own authentication events on its own, and gives the application one call to record anything else -
an invoice approved, a user suspended, a setting changed. Stands alone: it names no other package, and exposes a mapping
seam that suite packages and applications register their own events through.

## Core Concept

| Concept       | What it is                                                                                                      |
|---------------|-----------------------------------------------------------------------------------------------------------------|
| **Record**    | One immutable entry: an event code, its outcome, and who, what and where. Scalars only, resolved at capture.    |
| **Event**     | A stable dotted code such as `authentication.signed_in` or `invoice.approved`, never derived from a class name. |
| **Actor**     | Who did it. Taken from the authenticated user, or named explicitly; `null` for a guest or the system.           |
| **Subject**   | What it was done to: any model, or any type and id.                                                             |
| **Principal** | Who the actor was acting as, when that differs - a role, a membership. Optional.                                |
| **Tenant**    | The isolation boundary the action happened within. Optional, for multi-tenant apps.                             |
| **Store**     | Where records go. The database by default; any `AuditStore` implementation otherwise.                           |

## Features

- **[Automatic capture](docs/guides/automatic-capture.md)** of Laravel's authentication events: sign-in, failed
  sign-in, remember-me restore, sign-out, lockout, registration, verification and password reset - one row each, and
  none per request.
- **Gate denials**, once turned on: one row per denied check, with the ability, and its arguments only as model
  references, class names or a marker, never their values.
- **Model changes**: watch a model's creation, update, deletion, restore and force delete, keeping only the fields
  named, written once its transaction commits.
- **Bulk operations**: one entry for an operation on many subjects, with a signed, encrypted manifest of every subject,
  refused rather than truncated when it is too large.
- **Manual capture** through `AuditLog::record()` and a fluent builder, filled in with the actor, guard, IP address,
  user agent, origin and request id.
- **[Mapping seam](docs/guides/extending.md)**: register a mapper for any event class or interface and record it with
  `AuditLog::capture()`.
- **Transaction-safe writes**: a record made inside a transaction is written once it commits, and dropped if it rolls
  back, unless it is written immediately or fail-closed.
- **Never silently lost**: a failed write is reported, dispatched as an event and spilled to a log channel, without
  breaking the request - or thrown, when the record must exist.
- **Redaction** of secret-shaped keys, keyed hashing of sign-in identifiers, IP address minimisation and size caps.
- **[Owners' keys and erasure](docs/guides/privacy.md)**: a field a definition encrypts is sealed under a key of its
  owner's by default, read only by a viewer the access policy grants it, and erased by destroying the owner's keys, so
  every entry, seal and journal row still verifies; restores, holds, preservation and pending deliveries are accounted
  for.
- **Chained membership seals**: entries are sealed in signed batches, each chained to the one before it and optionally
  anchored on a write-once disk, and `audit-log:verify` reports any entry or seal changed, removed or added.
- **Append-only storage** with indexed actor, subject, principal and tenant columns, portable across SQLite, MySQL and
  PostgreSQL, and retention through `audit-log:prune`, scheduled by the package.
- **[Lifecycle](docs/guides/retention.md)**: retention per category, holds that keep entries from it, a signed journal
  every seal commits to, and per-entry pruning that verification accounts for.
- **[Import](docs/guides/import.md)** of another system's records, or another installation's export, in batches with
  duplicates and conflicts found, signed and sealed here as this installation's acceptance of them.
- **[Reading the trail](docs/guides/reading.md)** by actor, subject, principal, tenant, event, category, outcome, time
  or correlation id, newest first with signed cursors, through an access policy the application binds, which denies
  every viewer until it does.
- **Audited reads**: every page, count, export and verification is recorded under the package's own codes before
  anything it found is returned, and is refused when it cannot be recorded.
- **Describing entries**: a translated title for each code, which an application overrides per locale, with concealed
  reasons never shown and encrypted values shown only to a scope the access policy grants them.
- **Verifiable exports**: `audit-log:export` writes NDJSON, OCSF or CEF from one consistent snapshot, journals it with a
  signed manifest, and verifies it later, line by line for NDJSON.
- **Request and job context**: the request id and actor follow a request into the jobs it dispatches, and nothing leaks
  between Octane requests or queued jobs.
- **Testing fake** with assertions for what was, and was not, recorded.

## Installation

```bash
composer require sinemacula/laravel-audit-log
```

## Configuration

Publish the config and the migrations, and migrate:

```bash
php artisan vendor:publish --tag=audit-log-config
php artisan vendor:publish --tag=audit-log-migrations
php artisan migrate
```

| Key                                         | Default                        | Env                                                   | What it does                                                                                                                                                                                                                |
|---------------------------------------------|--------------------------------|-------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `storage.connection`                        | `null`                         | `AUDIT_LOG_STORAGE_CONNECTION`                        | The connection the tables live on; `null` or empty for the default connection.                                                                                                                                              |
| `storage.maintenance_connection`            | `null`                         | `AUDIT_LOG_STORAGE_MAINTENANCE_CONNECTION`            | The connection pruning, holds, the lifecycle journal and imports' journal rows run through, and erasure, reinstatement and rewrap, to the same database with a user of its own; `null` or empty for the storage connection. |
| `entries.table`                             | `audit_log_entries`            | `AUDIT_LOG_ENTRIES_TABLE`                             | The entries table: 1 to 47 lower-case letters, digits and underscores, not starting with a digit.                                                                                                                           |
| `entries.artifacts_table`                   | `audit_log_artifacts`          | `AUDIT_LOG_ENTRIES_ARTIFACTS_TABLE`                   | The table of each entry's artifact (bulk subjects, read disclosures, export manifests), on the storage connection: the entries table's grammar.                                                                             |
| `integrity.keys`                            | `[]`                           | -                                                     | A map of key ids to secrets of at least 32 bytes that sign and verify entries; empty to derive the key from `app.key`.                                                                                                      |
| `integrity.current`                         | `null`                         | `AUDIT_LOG_INTEGRITY_CURRENT`                         | The key in `integrity.keys` that signs new entries.                                                                                                                                                                         |
| `integrity.log_id`                          | `null`                         | `AUDIT_LOG_INTEGRITY_LOG_ID`                          | The log every seal names, 1 to 64 letters, digits, dots, underscores or hyphens; `null` or empty for `source.id`. Set before the first seal.                                                                                |
| `integrity.checkpoints_table`               | `audit_log_checkpoints`        | `AUDIT_LOG_INTEGRITY_CHECKPOINTS_TABLE`               | The seals table, on the storage connection: the same grammar as the entries table.                                                                                                                                          |
| `integrity.members_table`                   | `audit_log_checkpoint_members` | `AUDIT_LOG_INTEGRITY_MEMBERS_TABLE`                   | The table of the entries each seal holds, on the storage connection: the same grammar as the entries table.                                                                                                                 |
| `integrity.state_table`                     | `audit_log_integrity_state`    | `AUDIT_LOG_INTEGRITY_STATE_TABLE`                     | The table of the progress of sealing, anchoring and verification, never evidence: the same grammar as the entries table.                                                                                                    |
| `integrity.seal.schedule`                   | `*/5 * * * *`                  | `AUDIT_LOG_INTEGRITY_SEAL_SCHEDULE`                   | When the package schedules `audit-log:seal`, as a cron expression; `null` or empty to schedule nothing.                                                                                                                     |
| `integrity.seal.sweep_schedule`             | `15 3 * * *`                   | `AUDIT_LOG_INTEGRITY_SEAL_SWEEP_SCHEDULE`             | When the package schedules `audit-log:seal --sweep`, which seals what a run missed; `null` or empty to schedule nothing.                                                                                                    |
| `integrity.seal.batch`                      | `5000`                         | `AUDIT_LOG_INTEGRITY_SEAL_BATCH`                      | The most entries one seal holds, from 100 to 50000.                                                                                                                                                                         |
| `integrity.seal.max_batches`                | `100`                          | `AUDIT_LOG_INTEGRITY_SEAL_MAX_BATCHES`                | The most seals one run writes, from 1 to 100000.                                                                                                                                                                            |
| `integrity.seal.lookback_seconds`           | `3600`                         | `AUDIT_LOG_INTEGRITY_SEAL_LOOKBACK_SECONDS`           | How far before the newest seal's latest entry a run looks for late entries, from 0 to 2592000; above the worst clock skew.                                                                                                  |
| `integrity.seal.settle_seconds`             | `0`                            | `AUDIT_LOG_INTEGRITY_SEAL_SETTLE_SECONDS`             | How long an entry waits after it is recorded before a seal may hold it, from 0 to 3600.                                                                                                                                     |
| `integrity.seal.max_attempts`               | `5`                            | `AUDIT_LOG_INTEGRITY_SEAL_MAX_ATTEMPTS`               | How many attempts a seal gets against a concurrent sealer, from 1 to 100.                                                                                                                                                   |
| `integrity.verify.schedule`                 | `45 3 * * *`                   | `AUDIT_LOG_INTEGRITY_VERIFY_SCHEDULE`                 | When the package schedules `audit-log:verify --strict --sweep-first`, as a cron expression; `null` or empty for none.                                                                                                       |
| `integrity.verify.max_unsealed_age_seconds` | `90000`                        | `AUDIT_LOG_INTEGRITY_VERIFY_MAX_UNSEALED_AGE_SECONDS` | How old an unsealed entry may grow before verification calls the log incomplete, from 600 to 31536000; above a day, for the sweep.                                                                                          |
| `integrity.anchor.driver`                   | `null`                         | `AUDIT_LOG_INTEGRITY_ANCHOR_DRIVER`                   | Where each seal is anchored: `null` for nowhere, or `disk`, which holds only on a write-once (WORM) store.                                                                                                                  |
| `integrity.anchor.disk`                     | `null`                         | `AUDIT_LOG_INTEGRITY_ANCHOR_DISK`                     | The disk a disk anchor writes to, configured in `filesystems.disks`; `null` or empty for `filesystems.default`.                                                                                                             |
| `integrity.anchor.path`                     | `audit-log-anchors`            | `AUDIT_LOG_INTEGRITY_ANCHOR_PATH`                     | The namespace a disk anchor writes under: 1 to 191 characters of path segments that cannot leave it.                                                                                                                        |
| `integrity.anchor.batch`                    | `100`                          | `AUDIT_LOG_INTEGRITY_ANCHOR_BATCH`                    | How many seals one run anchors, from 1 to 10000.                                                                                                                                                                            |
| `lifecycle.journal_table`                   | `audit_log_lifecycle`          | `AUDIT_LOG_LIFECYCLE_JOURNAL_TABLE`                   | The signed, chained journal of every hold, release, prune and import, on the storage connection: the entries table's grammar.                                                                                               |
| `lifecycle.holds_table`                     | `audit_log_holds`              | `AUDIT_LOG_LIFECYCLE_HOLDS_TABLE`                     | The projection of the active holds, for listing and checks, never trusted for a decision: the entries table's grammar.                                                                                                      |
| `lifecycle.lock_table`                      | `audit_log_lifecycle_lock`     | `AUDIT_LOG_LIFECYCLE_LOCK_TABLE`                      | The one-row table every lifecycle transaction locks first: the entries table's grammar.                                                                                                                                     |
| `retention.after_days`                      | `0`                            | `AUDIT_LOG_RETENTION_AFTER_DAYS`                      | Days an entry of a category not listed is kept, from 1 to 36500; `0` keeps it forever.                                                                                                                                      |
| `retention.categories`                      | `[]`                           | -                                                     | A map of categories to the days their entries are kept, from 1 to 36500, `0` forever, over `retention.after_days`.                                                                                                          |
| `retention.preserve`                        | `[]`                           | -                                                     | A map of categories to the days their entries must stay readable, `0` forever; a shorter retention is refused.                                                                                                              |
| `retention.batch`                           | `1000`                         | `AUDIT_LOG_RETENTION_BATCH`                           | The most entries one transaction of a prune deletes, from 100 to 10000.                                                                                                                                                     |
| `retention.max_seconds`                     | `3000`                         | `AUDIT_LOG_RETENTION_MAX_SECONDS`                     | How long a prune runs before it stops between chunks, for the next run to resume, from 60 to 86400.                                                                                                                         |
| `retention.schedule`                        | `30 3 * * *`                   | `AUDIT_LOG_RETENTION_SCHEDULE`                        | When the package schedules `audit-log:prune`, once anything is kept for less than forever or a policy of your own is bound; `null` or empty for none.                                                                       |
| `import.batches_table`                      | `audit_log_import_batches`     | `AUDIT_LOG_IMPORT_BATCHES_TABLE`                      | The table of each import's batch, on the storage connection: the entries table's grammar.                                                                                                                                   |
| `import.chunk`                              | `500`                          | `AUDIT_LOG_IMPORT_CHUNK`                              | How many lines one transaction of an import writes, from 100 to 5000.                                                                                                                                                       |
| `import.max_skew_seconds`                   | `300`                          | `AUDIT_LOG_IMPORT_MAX_SKEW_SECONDS`                   | How far after the clock an imported entry may claim to have happened, from 0 to 86400.                                                                                                                                      |
| `import.max_line_bytes`                     | `1048576`                      | `AUDIT_LOG_IMPORT_MAX_LINE_BYTES`                     | The longest line an import reads, from 1024 to 16777216; a longer one is rejected unread.                                                                                                                                   |
| `actor.guards`                              | `null`                         | -                                                     | The guards the ambient actor is read from, in order; `null` for the default guard.                                                                                                                                          |
| `context.trust_request_id`                  | `false`                        | `AUDIT_LOG_CONTEXT_TRUST_REQUEST_ID`                  | Whether a request id from a trusted proxy is believed.                                                                                                                                                                      |
| `context.request_id_header`                 | `X-Request-Id`                 | `AUDIT_LOG_CONTEXT_REQUEST_ID_HEADER`                 | The header a trusted request id comes in.                                                                                                                                                                                   |
| `context.trust_traceparent`                 | `false`                        | `AUDIT_LOG_CONTEXT_TRUST_TRACEPARENT`                 | Whether a `traceparent` from a trusted proxy is believed.                                                                                                                                                                   |
| `definitions.require_registered`            | `false`                        | `AUDIT_LOG_DEFINITIONS_REQUIRE_REGISTERED`            | Whether a code with no registered definition is refused, rather than taking the permissive definition.                                                                                                                      |
| `capture.laravel.except_guards`             | `[]`                           | -                                                     | The guards whose authentication events are not recorded, matched against the event's guard; `['*']` for every event.                                                                                                        |
| `capture.laravel.identifier_key`            | `email`                        | `AUDIT_LOG_CAPTURE_LARAVEL_IDENTIFIER_KEY`            | The one credential a failed sign-in or a lockout is read for, stored as `redaction.identifiers` says.                                                                                                                       |
| `capture.gate.enabled`                      | `false`                        | `AUDIT_LOG_CAPTURE_GATE_ENABLED`                      | Whether Gate denials are recorded. Only denials are; allowed checks never are.                                                                                                                                              |
| `capture.gate.only_abilities`               | `null`                         | -                                                     | The only abilities whose denials are recorded, compared exactly; `null` for every ability.                                                                                                                                  |
| `capture.gate.except_abilities`             | `[]`                           | -                                                     | The abilities whose denials are never recorded, compared exactly; it wins over `capture.gate.only_abilities`.                                                                                                               |
| `capture.gate.reason_codes`                 | `[]`                           | -                                                     | The machine-readable codes a denial's response may give that are kept as its reason; any other is never kept.                                                                                                               |
| `capture.bulk.max_members`                  | `100000`                       | `AUDIT_LOG_CAPTURE_BULK_MAX_MEMBERS`                  | The most subjects a bulk operation's manifest holds, from 1 to 1000000; a larger one is refused, never truncated.                                                                                                           |
| `capture.bulk.max_bytes`                    | `4194304`                      | `AUDIT_LOG_CAPTURE_BULK_MAX_BYTES`                    | The most a bulk operation's encoded manifest may hold, from 65536 to 8388608; a larger one is refused, never truncated.                                                                                                     |
| `read.max_per_page`                         | `100`                          | `AUDIT_LOG_READ_MAX_PER_PAGE`                         | The most entries a page of the trail may ask for, from 1 to 500.                                                                                                                                                            |
| `export.chunk`                              | `1000`                         | `AUDIT_LOG_EXPORT_CHUNK`                              | How many entries an export reads per statement, from 100 to 10000; memory grows with it, never with the export.                                                                                                             |
| `source.id`                                 | `null`                         | `AUDIT_LOG_SOURCE_ID`                                 | The deployment records come from, 1 to 64 characters; `null` or empty for a slug of `app.name`.                                                                                                                             |
| `source.region`                             | `null`                         | `AUDIT_LOG_SOURCE_REGION`                             | The region records come from, 1 to 32 characters; `null` or empty for none.                                                                                                                                                 |
| `redaction.keys`                            | `[]`                           | -                                                     | More key names to redact, merged with the built-ins, which cannot be removed.                                                                                                                                               |
| `redaction.key`                             | `null`                         | `AUDIT_LOG_REDACTION_KEY`                             | The key identifiers, pseudonyms and IP hashes use, of at least 32 bytes; `null` or empty to derive it from `app.key`.                                                                                                       |
| `redaction.identifiers`                     | `hash`                         | `AUDIT_LOG_REDACTION_IDENTIFIERS`                     | Whether a sign-in identifier is stored as a keyed hash (`hash`) or not at all (`drop`).                                                                                                                                     |
| `redaction.ip`                              | `full`                         | `AUDIT_LOG_REDACTION_IP`                              | How the IP address is stored: `full`, `truncate`, `hash`, `drop` or `encrypt`.                                                                                                                                              |
| `redaction.max_bytes`                       | `16384`                        | `AUDIT_LOG_REDACTION_MAX_BYTES`                       | The most the encoded properties may hold, from 8192 to 16777216; the largest fields are omitted beyond it.                                                                                                                  |
| `redaction.max_context_bytes`               | `4096`                         | `AUDIT_LOG_REDACTION_MAX_CONTEXT_BYTES`               | The most the encoded context may hold, from 1024 to 16777216.                                                                                                                                                               |
| `privacy.keys`                              | `[]`                           | -                                                     | A map of wrapping key ids to secrets of at least 32 bytes that wrap owners' keys; empty to derive the wrapping keys from `app.key`.                                                                                         |
| `privacy.current`                           | `null`                         | `AUDIT_LOG_PRIVACY_CURRENT`                           | The key in `privacy.keys` that wraps new owners' keys; set with `privacy.keys`, or neither.                                                                                                                                 |
| `privacy.subject_keys_table`                | `audit_log_subject_keys`       | `AUDIT_LOG_PRIVACY_SUBJECT_KEYS_TABLE`                | The owners' keys, one row per owner, tenant, category and generation, on the storage connection: the entries table's grammar.                                                                                               |
| `privacy.owner_erasures_table`              | `audit_log_owner_erasures`     | `AUDIT_LOG_PRIVACY_OWNER_ERASURES_TABLE`              | The marker of each erasure and reinstatement of an owner, on the storage connection: the entries table's grammar.                                                                                                           |
| `privacy.key_uses_table`                    | `audit_log_key_uses`           | `AUDIT_LOG_PRIVACY_KEY_USES_TABLE`                    | Which key sealed a field of which entry, written with the entry, on the storage connection: the entries table's grammar.                                                                                                    |
| `privacy.rewrap_batch`                      | `500`                          | `AUDIT_LOG_PRIVACY_REWRAP_BATCH`                      | The most keys one transaction of `audit-log:rewrap` changes, from 100 to 10000.                                                                                                                                             |
| `failure.mode`                              | `report`                       | `AUDIT_LOG_FAILURE_MODE`                              | What a failed write does: `report` it and carry on, or `throw`. A `failClosed()` or `transactional()` record always throws.                                                                                                 |
| `failure.log_channel`                       | `null`                         | `AUDIT_LOG_FAILURE_LOG_CHANNEL`                       | The channel a failed record is spilled to, which holds personal data; `null` or empty for the default channel.                                                                                                              |
| `delivery.mode`                             | `sync`                         | `AUDIT_LOG_DELIVERY_MODE`                             | How a record reaches its store: `sync`, or `outbox` for a drain to deliver it.                                                                                                                                              |
| `delivery.outbox.connection`                | `null`                         | `AUDIT_LOG_DELIVERY_OUTBOX_CONNECTION`                | The connection the outbox table lives on; `null` or empty for the storage connection.                                                                                                                                       |
| `delivery.outbox.table`                     | `audit_log_outbox`             | `AUDIT_LOG_DELIVERY_OUTBOX_TABLE`                     | The outbox table: the same grammar as the entries table.                                                                                                                                                                    |
| `delivery.outbox.lease_seconds`             | `300`                          | `AUDIT_LOG_DELIVERY_OUTBOX_LEASE_SECONDS`             | How long a drain's claim on a row lasts, from 30 to 86400.                                                                                                                                                                  |
| `delivery.outbox.max_attempts`              | `10`                           | `AUDIT_LOG_DELIVERY_OUTBOX_MAX_ATTEMPTS`              | How many attempts a row gets before it is failed and kept, from 1 to 1000.                                                                                                                                                  |
| `delivery.outbox.backoff_seconds`           | `60`                           | `AUDIT_LOG_DELIVERY_OUTBOX_BACKOFF_SECONDS`           | How long the first retry waits, doubling up to an hour, from 1 to 3600.                                                                                                                                                     |
| `delivery.deliveries_table`                 | `audit_log_deliveries`         | `AUDIT_LOG_DELIVERY_DELIVERIES_TABLE`                 | The table of each destination's receipts, on the storage connection: the same grammar as the entries table.                                                                                                                 |
| `monitor.seal_minutes`                      | `30`                           | `AUDIT_LOG_MONITOR_SEAL_MINUTES`                      | How old the last seal run may grow before `audit-log:check --freshness` calls sealing stale, from 5 to 1440 minutes.                                                                                                        |
| `monitor.daily_minutes`                     | `1560`                         | `AUDIT_LOG_MONITOR_DAILY_MINUTES`                     | How old the last sweep, full verification and prune may grow before `--freshness` calls each stale, from 60 to 10080 minutes.                                                                                               |
| `monitor.outbox_minutes`                    | `15`                           | `AUDIT_LOG_MONITOR_OUTBOX_MINUTES`                    | How long the oldest outbox row may wait for a drain before `--freshness` calls the backlog stale, from 1 to 1440 minutes.                                                                                                   |

The package schedules `audit-log:seal` every five minutes, and `audit-log:seal --sweep` and `audit-log:verify --strict
--sweep-first` daily, on Laravel's scheduler, each in the background, kept from overlapping itself and, on a cache store
every server shares, run on one server. Once retention keeps anything for less than forever, or the application binds a
retention policy of its own, it schedules `audit-log:prune` daily too. Set a run's schedule to `null` to schedule
nothing and run that command elsewhere. `audit-log:verify` exits non-zero on a `tampered`, `incomplete` or
`unverifiable` seal, and with `--strict` also on one the anchor does not confirm.

Run `php artisan audit-log:check` in a deploy pipeline: it reports every malformed setting, missing connection, schema
problem and unusable key at once, exits non-zero on any, and writes nothing. It also says whether the spill channel is
the one a replay can read, and fails on one that would fail together with the store. After a database restore it fails
too, on keys an erasure destroyed and on a database behind its anchor, until `audit-log:erase --reapply` has re-applied
the erasures since. In production it also fails on the testing fake bound as the store or a stack's destination, and
notes, without failing, a seal, sweep or verification schedule turned off.

## Usage

Record an action, with the ambient actor, guard, client and request filled in:

```php
use SineMacula\Laravel\AuditLog\Facades\AuditLog;

AuditLog::record('invoice.approved', subject: $invoice, properties: ['amount' => '1200.00']);
```

Or build one up:

```php
use SineMacula\Laravel\AuditLog\Facades\AuditLog;

AuditLog::event('user.suspended')
    ->on($user)
    ->by($admin)
    ->forTenant($organisation)
    ->withProperties(['until' => $until])
    ->record();
```

A record made before the `auth` middleware has run has no actor, because the package only reads a user the guard already
holds and never loads one; name it with `->by()`. A request id or `traceparent` sent by the edge is believed only with
its flag on and from a proxy `TrustProxies` trusts, and that proxy must overwrite or validate those headers, because
only the immediate peer is checked.

Record a completed disclosure, with its purpose and channel as machine-readable codes:

```php
AuditLog::accessed('document.downloaded', subject: $document, purpose: 'legal_hold', channel: 'portal')->record();
```

Choose when a record is written. Inside a transaction a record waits for the commit, and is dropped on a rollback:

```php
AuditLog::event('invoice.approved')->on($invoice)->afterCommit()->record();          // the default
AuditLog::event('invoice.approved')->on($invoice)->afterCommit('billing')->record(); // that connection's transaction
AuditLog::event('invoice.approved')->on($invoice)->immediately()->record();          // now, whatever is open
AuditLog::event('invoice.approved')->on($invoice)->transactional()->record();        // atomic with an open transaction
AuditLog::event('invoice.approved')->on($invoice)->failClosed()->record();           // now, and a failure must throw
```

A `failClosed()` record needs a durable store and a `transactional()` record a store that joins the transaction, unless
the outbox acknowledges for it.

A failed write does not break the request by default: the record is spilled to `failure.log_channel` as one line, the
failure is reported without any value of the record, `AuditWriteFailed` is dispatched, and the code carries on. With
`failure.mode` set to `throw`, or for a `failClosed()` record, the record is spilled and the failure is thrown. A
`transactional()` record always throws and is never spilled, because it describes work that has not committed. Either
way the failure thrown holds the record's id and code, and none of its values. Replay the spilled lines once the store
is back:

```bash
php artisan audit-log:replay --spill=storage/logs/audit-spill.log
```

To write a record in the application's own transaction and deliver it separately, migrate the outbox and set
`delivery.mode` to `outbox`, then schedule the drain, which the package does not schedule:

```php
Schedule::command('audit-log:drain --until-empty')->everyMinute();
```

A row on the connection the application's transactions run on commits exactly when they do. Delivery is at least once,
in no guaranteed order, and a row that keeps failing is kept rather than deleted, for `audit-log:replay --outbox` to
requeue. See [delivery](docs/design/delivery.md) for what each mode guarantees and how to configure a spill channel a
replay can read.

Watch the scheduled runs from cron or an uptime monitor with `php artisan audit-log:check --freshness`, which exits
non-zero once sealing, the sweep, verification, retention, anchoring or the outbox is stale or failed; see
[monitoring](docs/guides/operations.md#monitor).

Register event definitions and your own context contributors from a service provider's `boot()`; registration is refused
once the application has booted:

```php
AuditLog::define(InvoiceActivity::class);
AuditLog::contribute(OrganisationContributor::class);
```

A contributor implements `ContextContributor` and fills only what is still a gap.

In a test, swap the store for a fake that holds what would have been stored:

```php
$fake = AuditLog::fake();

$this->post('/invoices/42/approve');

self::assertTrue($fake->hasRecorded('invoice.approved'));
```

Secret-shaped keys are redacted everywhere, at capture. This is a heuristic: it cannot find a secret in free text or
under an innocuous key, and an event definition, which allowlists a code's fields, is the remedy. See
[redaction](docs/design/redaction.md) and the [threat model](docs/design/threat-model.md). A sign-in identifier is never
a property: it is stored as a keyed hash, so failed attempts correlate without keeping the address:

```php
AuditLog::event('app.sign_in_failed')->withIdentifier($email)->failed('invalid_credentials')->record();
```

### Automatic capture

Laravel's authentication events are recorded with no code at all, and Gate denials once `capture.gate.enabled` is on.
Map an event of your own, or an interface its events share, from a service provider's `boot()`, and it is recorded
whenever it is dispatched:

```php
AuditLog::map(OrderShipped::class, OrderShippedMapper::class);
```

A mapper implements `EventMapper`: it sets the code and the fields on the builder it is given and returns it, or returns
`null` to skip the event. An event that is never dispatched is captured through its mapper directly. A captured record
is written at once, and a failure is reported rather than thrown, unless it ended a transaction the application had
open:

```php
AuditLog::capture($event);
```

Watch a model's changes from `boot()` too, keeping only the fields named:

```php
AuditLog::watch(Invoice::class, as: 'invoice', fields: ['status', 'amount']);
```

Record one bulk operation with the manifest of every subject it affected, sealed beside its entry and written after
commit like any record. The bound store must keep attachments, as the database store does:

```php
AuditLog::bulk('invoice.voided', $invoices)->record();
```

What is captured, and the gaps where nothing can be, is in
[the automatic-capture guide](docs/guides/automatic-capture.md); mapping another package's events, with one row per
sign-in, is in [the extending guide](docs/guides/extending.md).

### Reading the trail

Nothing is read until the application binds an access policy: the package's default denies every viewer. A policy
answers with the scope of entries a viewer may see for a purpose, and is asked again on every read. Bind it in a service
provider's `register()`:

```php
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;

$this->app->singleton(AuditAccessPolicy::class, OrganisationAuditPolicy::class);
```

```php
use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\AuditLog\Records\Reference;

final class OrganisationAuditPolicy implements AuditAccessPolicy
{
    public function scope(Authenticatable|Reference $viewer, ReadPurpose $purpose): AccessScope
    {
        return $viewer instanceof User && $viewer->isAuditor()
            ? AccessScope::tenants(Reference::to($viewer->organisation))
            : AccessScope::none();
    }
}
```

Read a page for the user the application has authenticated, newest first, and the next page from its cursor:

```php
$page = AuditLog::trail()->visibleTo($user)->forSubject($invoice)->cursorPaginate();

$next = AuditLog::trail()->visibleTo($user)->forSubject($invoice)->cursorPaginate(50, $page->nextCursor);
```

A viewer the policy denies sees an empty page. Every page, count, export and verification is recorded before anything
it found is returned: one that cannot be recorded, or that runs inside a transaction which could still roll its record
back, throws `AuditReadRefusedException` and returns nothing. Describe an entry for a person, its title from the
package's translations, which `php artisan vendor:publish --tag=audit-log-lang` copies for an application to override
and extend:

```php
use SineMacula\Laravel\AuditLog\Querying\Describer;

$title = app(Describer::class)->describe($page->entries[0])->title; // "Signed in"
```

Export the entries a viewer may see to a file, journalled, with its bundle beside it, and verify the export later. The
viewer is named by type and id, which asserts who the export is for and proves nothing of who runs the command:

```bash
php artisan audit-log:export storage/app/audit.ndjson --viewer-type='App\Models\User' --viewer-id=42
php artisan audit-log:export storage/app/audit.ndjson --verify --viewer-type='App\Models\User' --viewer-id=42
```

Filters, cursors, scopes, exports and their verification are in [the reading guide](docs/guides/reading.md).

### Retention, holds and import

Retention keeps everything forever until `retention.after_days` or `retention.categories` says otherwise; the package
then schedules `audit-log:prune`, which deletes, entry by entry, only sealed entries past retention, never one a hold
keeps, one still waiting for delivery or an `audit_log.trail_exported` record, and journals every deletion so
`audit-log:verify` accounts for it. Place a hold for a legal claim, an investigation or a regulator, and release it
when it ends:

```php
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Records\Reference;

$result = AuditLog::lifecycle()->hold(
    HoldScope::tenants(Reference::to($organisation))->categories('security'),
    new Authority(Reference::to($user), 'legal.claim', 'app:case-118'),
    HoldBasis::LEGAL_CLAIM,
);

AuditLog::lifecycle()->release($result->hold->id, new Authority(Reference::to($user), 'case.closed'));
```

The same operations run from the console, each trusting the shell: `--by-type` and `--by-id` assert the operator and
prove nothing of who ran the command.

```bash
php artisan audit-log:hold --tenant=organisation:org_01 --category=security --basis=legal_claim \
    --by-type=App\\Models\\User --by-id=7 --reason=legal.claim --reference=app:case-118
php artisan audit-log:holds
php artisan audit-log:release <hold-id> --by-type=App\\Models\\User --by-id=7 --reason=case.closed
php artisan audit-log:prune --dry-run
php artisan audit-log:import storage/app/crm-audit.ndjson --source=crm-eu \
    --by-type=App\\Models\\User --by-id=7 --reason=migration.crm
php artisan audit-log:reconcile
```

Holds, prunes and the journal make the destruction of entries accountable, never impossible: whoever holds the
maintenance credentials can still delete rows, and the seals and the journal make that detectable. An imported row is
this installation's acceptance of what its source asserted, signed and sealed here, and never delivered to a
destination. Policies, holds and prune runs are in [the retention guide](docs/guides/retention.md), and the import
format, batches and conflicts in [the import guide](docs/guides/import.md).

### Encrypted fields and erasure

A field a definition encrypts is sealed under a key of its owner's, one key per owner, tenant and category, with nothing
else to bind. The owner is the actor, the subject, or a reference held in another property:

```php
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;

AuditLog::define(EventDefinition::for('billing.card_charged')->category('billing')->retain('amount')->encrypt('card', KeyOwner::ACTOR));
```

A page shows every sealed field as `[ENCRYPTED]` unless the access policy grants the viewer's scope
`revealingEncryptedFields()`; under the grant each shows its value, `[ERASED]` once its owner's keys are destroyed, or
`[UNREADABLE]`, and the read's record counts each, never a value. The grant reveals every sealed field of the entries
the scope sees, whoever owns it. `holdingDataOf()` finds the entries holding an owner's fragments:

```php
return AccessScope::tenants(Reference::to($viewer->organisation))->revealingEncryptedFields();
```

```php
$page = AuditLog::trail()->visibleTo($investigator)->holdingDataOf($customer)->cursorPaginate();
```

Erase an owner by destroying its keys. It is all or nothing by default: an active hold or a category's preservation over
an entry the owner's key sealed refuses the whole erasure, as do records still waiting in the outbox, until `--partial`
or `--pending` accepts them. Every entry still verifies, and the erasure is journalled and recorded as
`audit_log.subject_erased`, which names the owner only by a keyed fingerprint:

```php
$result = AuditLog::lifecycle()->erase($customer, new Authority(Reference::to($user), 'gdpr.article_17', 'dpo:case-118'));
```

```bash
php artisan audit-log:erase 'App\Models\Customer' 42 --by-type=App\\Models\\User --by-id=7 --reason=gdpr.article_17
php artisan audit-log:reinstate 'App\Models\Customer' 42 --by-type=App\\Models\\User --by-id=7 --reason=consent.renewed
php artisan audit-log:rewrap --by-type=App\\Models\\User --by-id=7 --reason=keys.rotated --rotate
php artisan audit-log:keys --rebuild-uses --dry-run
```

An erasure revokes the owner's fields in the live store when it commits; it is complete only once the procedure across
backups, replicas, exports, logs, destinations and pending deliveries has run. Database credentials can still destroy
or restore keys, and `audit-log:verify` and `audit-log:check` make that detectable: after a restore, re-apply the
erasures since with `audit-log:erase --reapply=<file>`. References, hashes and the members of manifests are not erased.
Keys, erasure, restores and what each store holds are in [the privacy guide](docs/guides/privacy.md).

### Guides

| Guide                                                 | Covers                                                                                                             |
|-------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------|
| [Installation](#installation)                         | Requiring the package                                                                                              |
| [Configuration](#configuration)                       | Publishing the config and migrations, every setting, what the package schedules and `audit-log:check`              |
| [Recording](#usage)                                   | Recording, timing, failures, the outbox, definitions, contributors, identifiers and the fake                       |
| [Automatic capture](docs/guides/automatic-capture.md) | Laravel's authentication events, excluded guards, Gate denials, model changes, bulk operations, gaps and failures  |
| [Extending](docs/guides/extending.md)                 | Extension points, mapping another package's events, one row per sign-in, correlation ids and contributors          |
| [Reading](docs/guides/reading.md)                     | Access policies, filters, cursors, audited reads, describing entries, exports and their verification               |
| [Events](docs/guides/events.md)                       | The events the package dispatches, and alerting on a failed write, a failed capture or an integrity failure        |
| [Storage](docs/design/storage.md)                     | The tables, their columns and indexes, the storage and maintenance connections, and grants and triggers as SQL     |
| [Retention](docs/guides/retention.md)                 | Retention by category, a policy of your own, preservation, holds, prune runs and verification after a prune        |
| [Import](docs/guides/import.md)                       | The import format, importing an export, duplicates and conflicts, batches, holds and dry runs                      |
| [Operations](docs/guides/operations.md)               | Scheduling sealing, verification and pruning, monitoring, anchoring, keys, grants and what sealing costs           |
| [Privacy](docs/guides/privacy.md)                     | Encryption by default, owners' keys and wrapping, erasure and its two outcomes, restores and what each store holds |
| [Testing](docs/design/testing-helpers.md)             | The fake store, its assertions, what runs with it and how Laravel's test helpers change a record                   |

The contracts behind them, for maintainers and reviewers, are in [docs/design](docs/design/README.md).

## Requirements

- PHP ^8.3
- Laravel ^12.40 || ^13.3

## Testing

```bash
composer test               # all suites in parallel (Paratest)
composer test:coverage      # all suites with clover coverage
composer test:unit          # unit suite only
composer test:feature       # feature suite only
composer test:integration   # integration suite only
composer test:performance   # performance budget suite (serial)
composer test:mutation      # scoped mutation gate
composer test:mutation:full # full mutation suite (no thresholds)
composer check              # static analysis + style
composer format             # format the codebase
composer smells             # advisory code smells (duplication, complexity)
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of notable changes.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on branching, commits, code
quality, and pull requests.

## Security

If you discover a security vulnerability, please report it responsibly. See [SECURITY.md](SECURITY.md) for the
disclosure policy and contact details.

## License

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).
