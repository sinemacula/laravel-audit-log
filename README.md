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

| Key                              | Default             | Env                                        | What it does                                                                                                                                    |
|----------------------------------|---------------------|--------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| `storage.connection`             | `null`              | `AUDIT_LOG_STORAGE_CONNECTION`             | The connection the tables live on; `null` or empty for the default connection.                                                                  |
| `storage.maintenance_connection` | `null`              | `AUDIT_LOG_STORAGE_MAINTENANCE_CONNECTION` | The connection pruning, holds and erasure run through, to the same database with a user of its own; `null` or empty for the storage connection. |
| `entries.table`                  | `audit_log_entries` | `AUDIT_LOG_ENTRIES_TABLE`                  | The entries table: 1 to 47 lower-case letters, digits and underscores, not starting with a digit.                                               |
| `integrity.keys`                 | `[]`                | -                                          | A map of key ids to secrets of at least 32 bytes that sign and verify entries; empty to derive the key from `app.key`.                          |
| `integrity.current`              | `null`              | `AUDIT_LOG_INTEGRITY_CURRENT`              | The key in `integrity.keys` that signs new entries.                                                                                             |
| `actor.guards`                   | `null`              | -                                          | The guards the ambient actor is read from, in order; `null` for the default guard.                                                              |
| `context.trust_request_id`       | `false`             | `AUDIT_LOG_CONTEXT_TRUST_REQUEST_ID`       | Whether a request id from a trusted proxy is believed.                                                                                          |
| `context.request_id_header`      | `X-Request-Id`      | `AUDIT_LOG_CONTEXT_REQUEST_ID_HEADER`      | The header a trusted request id comes in.                                                                                                       |
| `context.trust_traceparent`      | `false`             | `AUDIT_LOG_CONTEXT_TRUST_TRACEPARENT`      | Whether a `traceparent` from a trusted proxy is believed.                                                                                       |
| `definitions.require_registered` | `false`             | `AUDIT_LOG_DEFINITIONS_REQUIRE_REGISTERED` | Whether a code with no registered definition is refused, rather than taking the permissive definition.                                          |
| `source.id`                      | `null`              | `AUDIT_LOG_SOURCE_ID`                      | The deployment records come from, 1 to 64 characters; `null` or empty for a slug of `app.name`.                                                 |
| `source.region`                  | `null`              | `AUDIT_LOG_SOURCE_REGION`                  | The region records come from, 1 to 32 characters; `null` or empty for none.                                                                     |

Run `php artisan audit-log:check` in a deploy pipeline: it reports every malformed setting, missing connection, schema
problem and unusable key at once, exits non-zero on any, and writes nothing.

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
