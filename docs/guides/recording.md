# Recording

This guide covers recording an action, choosing when a record is written, what a failed write does, the outbox,
definitions and contributors, sign-in identifiers and the testing fake.

## Recording an action

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

## Disclosures

Record a completed disclosure, with its purpose and channel as machine-readable codes:

```php
AuditLog::accessed('document.downloaded', subject: $document, purpose: 'legal_hold', channel: 'portal')->record();
```

## When a record is written

Choose when a record is written. Inside a transaction a record waits for the commit, and is dropped on a rollback:

```php
AuditLog::event('invoice.approved')->on($invoice)->afterCommit()->record();          // the default
AuditLog::event('invoice.approved')->on($invoice)->afterCommit('billing')->record(); // that connection's transaction
AuditLog::event('invoice.approved')->on($invoice)->immediately()->record();          // now, whatever is open
AuditLog::event('invoice.approved')->on($invoice)->transactional()->record();        // atomic with an open transaction
AuditLog::event('invoice.approved')->on($invoice)->afterTransaction()->record();     // when it ends, kept on a rollback
AuditLog::event('invoice.approved')->on($invoice)->failClosed()->record();           // now, and a failure must throw
```

A `failClosed()` record needs a durable store and a `transactional()` record a store that joins the transaction, unless
the outbox acknowledges for it.

## Failed writes

A failed write does not break the request by default: the record is spilled to `failure.log_channel` as one line, the
failure is reported without any value of the record, `AuditWriteFailed` is dispatched, and the code carries on. With
`failure.mode` set to `throw`, or for a `failClosed()` record, the record is spilled and the failure is thrown. A
`transactional()` record always throws and is never spilled, because it describes work that has not committed. Either
way the failure thrown holds the record's id and code, and none of its values. Replay the spilled lines once the store
is back:

```bash
php artisan audit-log:replay --spill=storage/logs/audit-spill.log
```

## The outbox

To write a record in the application's own transaction and deliver it separately, migrate the outbox and set
`delivery.mode` to `outbox`, then schedule the drain, which the package does not schedule:

```php
Schedule::command('audit-log:drain --until-empty')->everyMinute();
```

A row on the connection the application's transactions run on commits exactly when they do. Delivery is at least once,
in no guaranteed order, and a row that keeps failing is kept rather than deleted, for `audit-log:replay --outbox` to
requeue. See [delivery](../design/delivery.md) for what each mode guarantees and how to configure a spill channel a
replay can read.

## Definitions and contributors

Register event definitions and your own context contributors from a service provider's `boot()`; registration is refused
once the application has booted:

```php
AuditLog::define(InvoiceActivity::class);
AuditLog::contribute(OrganisationContributor::class);
```

A contributor implements `ContextContributor` and fills only what is still a gap. Definitions, contributors and mapping
another package's events are in [the extending guide](extending.md).

## Redaction and identifiers

Secret-shaped keys are redacted everywhere, at capture. This is a heuristic: it cannot find a secret in free text or
under an innocuous key, and an event definition, which allowlists a code's fields, is the remedy. See
[redaction](../design/redaction.md) and the [threat model](../design/threat-model.md). A sign-in identifier is never
a property: it is stored as a keyed hash, so failed attempts correlate without keeping the address:

```php
AuditLog::event('app.sign_in_failed')->withIdentifier($email)->failed('invalid_credentials')->record();
```

## Testing

In a test, swap the store for a fake that holds what would have been stored:

```php
$fake = AuditLog::fake();

$this->post('/invoices/42/approve');

self::assertTrue($fake->hasRecorded('invoice.approved'));
```

The fake's assertions, and how Laravel's test helpers change a record, are in
[the testing notes](../design/testing-helpers.md).
