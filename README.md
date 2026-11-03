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

> **Status:** in development. The API and schema below describe the planned 1.0 and may change before it is tagged.

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

- **Automatic capture** of Laravel's authentication events: sign-in, failed sign-in, remember-me restore, sign-out,
  lockout, registration, verification and password reset - one row each, and none per request.
- **Manual capture** through `AuditLog::record()` and a fluent builder, filled in with the actor, guard, IP address,
  user agent, origin and request id.
- **Mapping seam**: register a mapper for any event class or interface and record it with `AuditLog::capture()`.
- **Transaction-safe writes**: a record made inside a transaction is written once it commits, and dropped if it rolls
  back, unless it is written immediately or fail-closed.
- **Never silently lost**: a failed write is reported, dispatched as an event and spilled to a log channel, without
  breaking the request - or thrown, when the record must exist.
- **Redaction** of secret-shaped keys, keyed hashing of sign-in identifiers, IP address minimisation and size caps.
- **Chained membership seals**: entries are sealed in signed batches, each chained to the one before it and optionally
  anchored on a write-once disk, and `audit-log:verify` reports any entry or seal changed, removed or added.
- **Append-only storage** with indexed actor, subject, principal and tenant columns, portable across SQLite, MySQL and
  PostgreSQL, and retention through Laravel's `model:prune`.
- **Reading the trail** by actor, subject, principal or tenant, with cursor pagination and translatable descriptions.
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

| Key                                         | Default                        | Env                                                   | What it does                                                                                                                                    |
|---------------------------------------------|--------------------------------|-------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| `storage.connection`                        | `null`                         | `AUDIT_LOG_STORAGE_CONNECTION`                        | The connection the tables live on; `null` or empty for the default connection.                                                                  |
| `storage.maintenance_connection`            | `null`                         | `AUDIT_LOG_STORAGE_MAINTENANCE_CONNECTION`            | The connection pruning, holds and erasure run through, to the same database with a user of its own; `null` or empty for the storage connection. |
| `entries.table`                             | `audit_log_entries`            | `AUDIT_LOG_ENTRIES_TABLE`                             | The entries table: 1 to 47 lower-case letters, digits and underscores, not starting with a digit.                                               |
| `integrity.keys`                            | `[]`                           | -                                                     | A map of key ids to secrets of at least 32 bytes that sign and verify entries; empty to derive the key from `app.key`.                          |
| `integrity.current`                         | `null`                         | `AUDIT_LOG_INTEGRITY_CURRENT`                         | The key in `integrity.keys` that signs new entries.                                                                                             |
| `integrity.log_id`                          | `null`                         | `AUDIT_LOG_INTEGRITY_LOG_ID`                          | The log every seal names, 1 to 64 letters, digits, dots, underscores or hyphens; `null` or empty for `source.id`. Set before the first seal.    |
| `integrity.checkpoints_table`               | `audit_log_checkpoints`        | `AUDIT_LOG_INTEGRITY_CHECKPOINTS_TABLE`               | The seals table, on the storage connection: the same grammar as the entries table.                                                              |
| `integrity.members_table`                   | `audit_log_checkpoint_members` | `AUDIT_LOG_INTEGRITY_MEMBERS_TABLE`                   | The table of the entries each seal holds, on the storage connection: the same grammar as the entries table.                                     |
| `integrity.state_table`                     | `audit_log_integrity_state`    | `AUDIT_LOG_INTEGRITY_STATE_TABLE`                     | The table of the progress of sealing, anchoring and verification, never evidence: the same grammar as the entries table.                        |
| `integrity.seal.schedule`                   | `*/5 * * * *`                  | `AUDIT_LOG_INTEGRITY_SEAL_SCHEDULE`                   | When the package schedules `audit-log:seal`, as a cron expression; `null` or empty to schedule nothing.                                         |
| `integrity.seal.sweep_schedule`             | `15 3 * * *`                   | `AUDIT_LOG_INTEGRITY_SEAL_SWEEP_SCHEDULE`             | When the package schedules `audit-log:seal --sweep`, which seals what a run missed; `null` or empty to schedule nothing.                        |
| `integrity.seal.batch`                      | `5000`                         | `AUDIT_LOG_INTEGRITY_SEAL_BATCH`                      | The most entries one seal holds, from 100 to 50000.                                                                                             |
| `integrity.seal.max_batches`                | `100`                          | `AUDIT_LOG_INTEGRITY_SEAL_MAX_BATCHES`                | The most seals one run writes, from 1 to 100000.                                                                                                |
| `integrity.seal.lookback_seconds`           | `3600`                         | `AUDIT_LOG_INTEGRITY_SEAL_LOOKBACK_SECONDS`           | How far before the newest seal's latest entry a run looks for late entries, from 0 to 2592000; above the worst clock skew.                      |
| `integrity.seal.settle_seconds`             | `0`                            | `AUDIT_LOG_INTEGRITY_SEAL_SETTLE_SECONDS`             | How long an entry waits after it is recorded before a seal may hold it, from 0 to 3600.                                                         |
| `integrity.seal.max_attempts`               | `5`                            | `AUDIT_LOG_INTEGRITY_SEAL_MAX_ATTEMPTS`               | How many attempts a seal gets against a concurrent sealer, from 1 to 100.                                                                       |
| `integrity.verify.schedule`                 | `45 3 * * *`                   | `AUDIT_LOG_INTEGRITY_VERIFY_SCHEDULE`                 | When the package schedules `audit-log:verify --strict --sweep-first`, as a cron expression; `null` or empty for none.                           |
| `integrity.verify.max_unsealed_age_seconds` | `90000`                        | `AUDIT_LOG_INTEGRITY_VERIFY_MAX_UNSEALED_AGE_SECONDS` | How old an unsealed entry may grow before verification calls the log incomplete, from 600 to 31536000; above a day, for the sweep.              |
| `integrity.anchor.driver`                   | `null`                         | `AUDIT_LOG_INTEGRITY_ANCHOR_DRIVER`                   | Where each seal is anchored: `null` for nowhere, or `disk`, which holds only on a write-once (WORM) store.                                      |
| `integrity.anchor.disk`                     | `null`                         | `AUDIT_LOG_INTEGRITY_ANCHOR_DISK`                     | The disk a disk anchor writes to, configured in `filesystems.disks`; `null` or empty for `filesystems.default`.                                 |
| `integrity.anchor.path`                     | `audit-log-anchors`            | `AUDIT_LOG_INTEGRITY_ANCHOR_PATH`                     | The namespace a disk anchor writes under: 1 to 191 characters of path segments that cannot leave it.                                            |
| `integrity.anchor.batch`                    | `100`                          | `AUDIT_LOG_INTEGRITY_ANCHOR_BATCH`                    | How many seals one run anchors, from 1 to 10000.                                                                                                |
| `actor.guards`                              | `null`                         | -                                                     | The guards the ambient actor is read from, in order; `null` for the default guard.                                                              |
| `context.trust_request_id`                  | `false`                        | `AUDIT_LOG_CONTEXT_TRUST_REQUEST_ID`                  | Whether a request id from a trusted proxy is believed.                                                                                          |
| `context.request_id_header`                 | `X-Request-Id`                 | `AUDIT_LOG_CONTEXT_REQUEST_ID_HEADER`                 | The header a trusted request id comes in.                                                                                                       |
| `context.trust_traceparent`                 | `false`                        | `AUDIT_LOG_CONTEXT_TRUST_TRACEPARENT`                 | Whether a `traceparent` from a trusted proxy is believed.                                                                                       |
| `definitions.require_registered`            | `false`                        | `AUDIT_LOG_DEFINITIONS_REQUIRE_REGISTERED`            | Whether a code with no registered definition is refused, rather than taking the permissive definition.                                          |
| `source.id`                                 | `null`                         | `AUDIT_LOG_SOURCE_ID`                                 | The deployment records come from, 1 to 64 characters; `null` or empty for a slug of `app.name`.                                                 |
| `source.region`                             | `null`                         | `AUDIT_LOG_SOURCE_REGION`                             | The region records come from, 1 to 32 characters; `null` or empty for none.                                                                     |
| `redaction.keys`                            | `[]`                           | -                                                     | More key names to redact, merged with the built-ins, which cannot be removed.                                                                   |
| `redaction.key`                             | `null`                         | `AUDIT_LOG_REDACTION_KEY`                             | The key identifiers, pseudonyms and IP hashes use, of at least 32 bytes; `null` or empty to derive it from `app.key`.                           |
| `redaction.identifiers`                     | `hash`                         | `AUDIT_LOG_REDACTION_IDENTIFIERS`                     | Whether a sign-in identifier is stored as a keyed hash (`hash`) or not at all (`drop`).                                                         |
| `redaction.ip`                              | `full`                         | `AUDIT_LOG_REDACTION_IP`                              | How the IP address is stored: `full`, `truncate`, `hash`, `drop` or `encrypt`.                                                                  |
| `redaction.max_bytes`                       | `16384`                        | `AUDIT_LOG_REDACTION_MAX_BYTES`                       | The most the encoded properties may hold, from 8192 to 16777216; the largest fields are omitted beyond it.                                      |
| `redaction.max_context_bytes`               | `4096`                         | `AUDIT_LOG_REDACTION_MAX_CONTEXT_BYTES`               | The most the encoded context may hold, from 1024 to 16777216.                                                                                   |
| `failure.mode`                              | `report`                       | `AUDIT_LOG_FAILURE_MODE`                              | What a failed write does: `report` it and carry on, or `throw`. A `failClosed()` or `transactional()` record always throws.                     |
| `failure.log_channel`                       | `null`                         | `AUDIT_LOG_FAILURE_LOG_CHANNEL`                       | The channel a failed record is spilled to, which holds personal data; `null` or empty for the default channel.                                  |
| `delivery.mode`                             | `sync`                         | `AUDIT_LOG_DELIVERY_MODE`                             | How a record reaches its store: `sync`, or `outbox` for a drain to deliver it.                                                                  |
| `delivery.outbox.connection`                | `null`                         | `AUDIT_LOG_DELIVERY_OUTBOX_CONNECTION`                | The connection the outbox table lives on; `null` or empty for the storage connection.                                                           |
| `delivery.outbox.table`                     | `audit_log_outbox`             | `AUDIT_LOG_DELIVERY_OUTBOX_TABLE`                     | The outbox table: the same grammar as the entries table.                                                                                        |
| `delivery.outbox.lease_seconds`             | `300`                          | `AUDIT_LOG_DELIVERY_OUTBOX_LEASE_SECONDS`             | How long a drain's claim on a row lasts, from 30 to 86400.                                                                                      |
| `delivery.outbox.max_attempts`              | `10`                           | `AUDIT_LOG_DELIVERY_OUTBOX_MAX_ATTEMPTS`              | How many attempts a row gets before it is failed and kept, from 1 to 1000.                                                                      |
| `delivery.outbox.backoff_seconds`           | `60`                           | `AUDIT_LOG_DELIVERY_OUTBOX_BACKOFF_SECONDS`           | How long the first retry waits, doubling up to an hour, from 1 to 3600.                                                                         |
| `delivery.deliveries_table`                 | `audit_log_deliveries`         | `AUDIT_LOG_DELIVERY_DELIVERIES_TABLE`                 | The table of each destination's receipts, on the storage connection: the same grammar as the entries table.                                     |

The package schedules `audit-log:seal` every five minutes, and `audit-log:seal --sweep` and `audit-log:verify --strict
--sweep-first` daily, on Laravel's scheduler, each in the background, kept from overlapping itself and, on a cache store
every server shares, run on one server. Set a run's schedule to `null` to schedule nothing and run that command
elsewhere. `audit-log:verify` exits non-zero on a `tampered`, `incomplete` or `unverifiable` seal, and with `--strict`
also on one the anchor does not confirm.

Run `php artisan audit-log:check` in a deploy pipeline: it reports every malformed setting, missing connection, schema
problem and unusable key at once, exits non-zero on any, and writes nothing. It also says whether the spill channel is
the one a replay can read, and fails on one that would fail together with the store.

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
