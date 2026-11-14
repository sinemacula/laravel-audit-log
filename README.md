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
an invoice approved, a user suspended, a setting changed. Entries are sealed in signed, chained batches that
`audit-log:verify` checks; retention, holds, import and the erasure of an owner's encrypted fields are journalled; and
the trail is read only through an access policy the application binds, with every read recorded. Stands alone: it
names no other package, and exposes a mapping seam that suite packages and applications register their own events
through.

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

The package schedules sealing, a daily sweep and verification on Laravel's scheduler, and pruning once retention keeps
anything for less than forever. Run `php artisan audit-log:check` in a deploy pipeline: it reports every malformed
setting, missing connection, schema problem and unusable key, exits non-zero on any, and writes nothing.

Every setting, its default and its env var are in [the configuration guide](docs/guides/configuration.md).

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

Inside a transaction a record waits for the commit and is dropped on a rollback, and a failed write is reported without
breaking the request; [the recording guide](docs/guides/recording.md) covers both, and how to change them.

### Guides

| Guide                                                 | Covers                                                                                                             |
|-------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------|
| [Configuration](docs/guides/configuration.md)         | Publishing, every setting, what the package schedules and `audit-log:check`                                        |
| [Recording](docs/guides/recording.md)                 | Recording, timing, failures, the outbox, definitions, contributors, identifiers and the fake                       |
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
