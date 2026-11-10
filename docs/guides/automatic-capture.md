# Automatic capture

The package records some activity with no call of the application's own: Laravel's authentication events always,
Gate denials once they are turned on, and the changes of each model the application watches. A bulk operation, which
fires no model event, is recorded as one entry with the manifest of every subject it touched. Every captured record
goes through the same pipeline as one the application records itself, its contributors, its definition, minimising and
signing included. Recording the events of another package is in [the extending guide](extending.md).

## Laravel's authentication events

Each of these events is recorded as one row, under a code of the package's own:

| Laravel event                      | Code                                      | Outcome   | Actor             | Subject                        | Kept                                       |
|------------------------------------|-------------------------------------------|-----------|-------------------|--------------------------------|--------------------------------------------|
| `Login`                            | `authentication.signed_in`                | `success` | the user          | the user                       | `remember`                                 |
| `Login`, from a remember-me cookie | `authentication.session_restored`         | `success` | the user          | the user                       | `remember`                                 |
| `Failed`                           | `authentication.sign_in_failed`           | `failure` | none, explicitly  | the user when found, else none | the identifier, hashed                     |
| `Logout`, `CurrentDeviceLogout`    | `authentication.signed_out`               | `success` | the user, or none | the user, or none              | nothing                                    |
| `OtherDeviceLogout`                | `authentication.signed_out_other_devices` | `success` | the user, or none | the user, or none              | nothing                                    |
| `Lockout`                          | `authentication.locked_out`               | `denied`  | none, explicitly  | none                           | the IP address, and the identifier, hashed |
| `Registered`                       | `account.registered`                      | `success` | the user          | the user                       | nothing                                    |
| `Verified`                         | `account.email_verified`                  | `success` | the user          | the user                       | nothing                                    |
| `PasswordReset`                    | `account.password_reset`                  | `success` | the user          | the user                       | nothing                                    |
| `PasswordResetLinkSent`            | `account.password_reset_requested`        | `success` | none, explicitly  | the user                       | nothing                                    |

- Every value is read from the event, never from what a guard holds now. The actor and the subject are the event's
  user. A failed sign-in, a lockout and a reset link name no one as the actor explicitly, because anyone can cause
  them, so no contributor fills in whoever happens to be signed in.
- The guard is the one the event names. `Lockout`, `Registered`, `Verified`, `PasswordReset` and
  `PasswordResetLinkSent` name none, so their records have no guard.
- A failed sign-in and a lockout read one credential, the one `capture.laravel.identifier_key` names, and only when it
  is a string. Both read the key as one name, a dot included, never as a path into nested input, so they hash the same
  identifier alike. It is stored as `redaction.identifiers` says, a keyed hash by default and never a property, so a
  password, a one-time code or any other field the application passed is never read. A failed sign-in of an unknown
  user has the same code and the same hash, and no subject, so attempts against one identifier correlate whether or not
  it exists. A missing or malformed identifier still records the failure.
- Each code is defined by the package at boot, at version 1, in the `security` category, with every field it does not
  list dropped. An application or an integration that defines one of them differently is refused at boot; record your
  own activity under codes of your own.
- One event object is recorded once, even when a mapping of the application sees it too.
- A captured record is written at once, and a failure is reported rather than thrown, as the last section says.

## Excluding guards

Leave a guard's events out with `capture.laravel.except_guards`, a list of guard names matched exactly against the
guard each event names:

```php
'capture' => [
    'laravel' => [
        'except_guards' => ['partner'],
    ],
],
```

- `['*']` turns core capture off: no authentication event is recorded at all.
- An event that names no guard, a lockout or an account event, is skipped only under `['*']`, since no list of names
  can match it.
- `audit-log:check` names an excluded guard `auth.guards` does not configure as a problem, so a typo cannot quietly
  leave a guard recorded, and a malformed list fails closed when it is read.
- An integration that records its own sign-ins has its guards excluded here, by configuration and never by detection;
  [the extending guide](extending.md) has the recipe.
- `capture.laravel.identifier_key` (`AUDIT_LOG_CAPTURE_LARAVEL_IDENTIFIER_KEY`, `email` by default) is the credential
  a failed sign-in and a lockout are read for: 1 to 64 letters, digits, underscores, dots or hyphens. Set it to the key
  the application's sign-in form uses, such as `username`.

## Remember-me restores

A `Login` is recorded as `authentication.session_restored`, not as a sign-in, when the guard the event names is an
`Illuminate\Auth\SessionGuard` and its `viaRemember()` says the user came from the remember-me cookie.

- The guard is resolved by the name the event carries, and only when `auth.guards` configures it. Any other guard, or
  one the auth manager cannot build, such as one of a driver never registered or with no user provider, records
  `authentication.signed_in`.
- `viaRemember()` is guard state, not part of the event: once a recaller has restored a user, it stays true on that
  guard for the rest of the request. So an explicit `login()` on the same guard after a restore can be recorded as a
  restore too.
- A custom flow that is ambiguous in that way needs a mapper of its own: dispatch an event that says what happened,
  map it, and exclude the guard.

## Gaps in core capture

Some ways of authenticating fire no event the package records, so they record nothing:

- `Auth::once()` and `Auth::onceUsingId()` authenticate for one request and fire no `Login`.
- Token guards that fire neither `Login` nor `Failed`, such as a guard made with `Auth::viaRequest()` or Laravel's
  token guard, record nothing: authenticating each request with a token is not a sign-in. Record token issuance
  explicitly, where the application issues the token:

  ```php
  AuditLog::event('api_token.issued')->on($user)->withProperties(['name' => $tokenName])->record();
  ```

- `Attempting`, `Validated` and `Authenticated` are never recorded: they fire for every attempt or every request, and
  the outcome of an attempt is already `Login` or `Failed`.

## Gate denials

Gate denials are recorded only when `capture.gate.enabled` (`AUDIT_LOG_CAPTURE_GATE_ENABLED`) is `true`, a real
boolean. Each denial is `authorization.gate_denied`, outcome `denied`.

- A denial is what the Gate itself treats as one: `false`, `null` (no policy answered) or a denied `Response`, from
  `Gate::allows()`, `authorize()`, `@can` or any other check that evaluates an ability. A check that allows records
  nothing. A `Response` is asked whether it denies only once capture is on and its ability is selected, so with capture
  off it is never asked, and one that throws when asked is a contained failure.
- Every evaluation is recorded, the same denial twice included, so a `@can` inside a loop records each time it is
  denied. Volume is controlled by the opt-in and two lists of ability names, compared literally, with no pattern or
  wildcard: `capture.gate.only_abilities`, the only abilities recorded, `null` for every one, and
  `capture.gate.except_abilities`, the abilities never recorded, which wins.
- The actor is the user the Gate checked, `Gate::forUser()` included, or explicitly no one for a guest. The Gate names
  no guard, so the record has none.
- The properties are `ability`, cleaned and cut to 191 bytes, `arguments` and `argument_count`. At most 8 arguments are
  kept, in order: a model as its type and id, a class name of an existing class (such as the class an ability to
  create is checked against) without a leading backslash, and anything else as the marker `[ARGUMENT]`. Nothing is
  serialised, cast to a string or traversed, so no attribute and no value reaches the record. `argument_count` is the
  full count.
- A denied `Response`'s `code()` is the record's reason only when `capture.gate.reason_codes` lists it, as a machine
  code. Treat that list as application-controlled data: list the codes the application's own policies return, never a
  value that came from a request, because a token can look like a code. The response's message is free text and is
  never read.
- A denial is written at once, so inside a transaction open on the storage connection, or in outbox mode on the
  outbox's, each one costs a savepoint, which on PostgreSQL is a subtransaction held until that transaction ends. Past
  64 in one transaction PostgreSQL's snapshots overflow and every session of the cluster slows. An application on
  PostgreSQL that wraps a request in a transaction and may meet many denials in it, such as a `@can` inside a loop,
  puts the storage, or the outbox, on a connection of its own.
- `Gate::allowIf()`, `Gate::denyIf()` and callbacks that throw fire no `GateEvaluated`, so they record nothing. A
  policy that throws its own `AuthorizationException` ends the check before the Gate can say what it decided. Record
  these explicitly:

  ```php
  AuditLog::event('report.export_denied')->on($report)->denied('not_owner')->record();
  ```

## Model changes

Watch a model from a service provider's `boot()`, naming the code segment its changes are stored under and the fields
kept:

```php
use SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;

AuditLog::watch(Invoice::class, as: 'invoice', fields: ['status', 'amount', 'approved_by' => FieldHandling::PSEUDONYMISE]);
```

- `AuditLog::watch()` is refused once the application has booted, as every registration is. Watching a class again
  as it is watched changes nothing; any other second watch of it is refused.
- The codes are `{as}.created`, `{as}.updated`, `{as}.deleted`, `{as}.restored` and `{as}.force_deleted`, each defined
  at version 1 in the `change` category. `as` is one code segment, a lower-case letter then up to 176 lower-case
  letters, digits or underscores, and none of the segments the package's own codes are stored under:
  `authentication`, `session`, `account`, `authorization`, `mfa`, `sso` and `audit_log`.
- Only the fields named are kept, 1 to 64 columns: a name alone is retained, and a name given as a key takes the
  handling given, as an event definition's field rules do. Every other attribute is dropped. A field is never
  `changes`, and never starts with `_audit`. An encrypted field is encrypted under the key of the model, the record's
  subject.
- The class is watched exactly. Eloquent names each event after the model's own class, so a subclass is not watched
  through its parent: watch it too. The package's own models are never watched.
- A field the instance hides, through `$hidden` or a `$visible` list that leaves it out, or casts encrypted
  (`encrypted`, `encrypted:*` or an `AsEncrypted*` class) refuses the capture unless the watch gives it an explicit
  handling; `RETAIN` is not explicit. It is checked on the instance itself, before any value is read: the capture fails
  as the last section says, no row is written, and the change goes on.
- Values are read raw, from the attributes, `getChanges()` and `getPrevious()`, never through `toArray()`, an accessor,
  an appended attribute or a cast.
- A creation keeps the fields as they were set. An update keeps `changes`, each changed field's value `before` and
  `after`, and records nothing when no watched field changed. A deletion, soft or not, keeps the fields as they are
  stored, never values set and not saved, and names the model by the key it is stored under, which Eloquent deletes
  by, so an encrypted field is sealed for the row that was removed.
- A restore and a force delete are one row each. A force delete is one `{as}.force_deleted`, without the deletion it
  runs through, and a field the instance hides fails it once. A restore is one `{as}.restored`, decided when an update
  turns a soft-deleted model's deleted-at column from a time to `null`, keeping the fields and any watched changes
  alongside it; the deleted-at column is among them only when it is watched. A restore that changes nothing records
  nothing.
- Deleting a hard-deleted instance again fires nothing and records nothing. Soft-deleting a trashed instance again
  writes its deleted-at again, and records a second `{as}.deleted`.
- The record is built and minimised when the event fires, with the actor of that moment, and written after commit:
  once the transaction open on the model's own connection commits, and never when it rolls back. It is the one captured
  source that waits for commit. Two saves before a commit give two rows, each with its own snapshot. In outbox mode,
  with the outbox on the model's connection, the row is inserted inside that transaction, in a savepoint of its own:
  on PostgreSQL each is a subtransaction held until the transaction ends, and past 64 in one transaction PostgreSQL's
  snapshots overflow and every session of the cluster slows. A model saved many times in one transaction on
  PostgreSQL, in an import loop or an observer cascade, wants the outbox on a connection of its own.

## Gaps in model capture

Each of these changes rows without a model event, so none of them records anything:

- query-builder `update`, `delete`, `insert`, `upsert` and `increment` (and `decrement`), such as
  `Invoice::query()->where('status', 'draft')->update([...])`
- `saveQuietly` and the other quiet methods
- anything done inside `withoutEvents`
- raw `DB::` statements
- pivots without a `using()` model: attaching, detaching or syncing a `belongsToMany()` relation that has no pivot model
- custom `$dispatchesEvents` listeners that stop the fallback: a listener of a model's own event that returns a value
  stops Eloquent dispatching the `eloquent.*` event the watch listens for

`covering()` is the answer: record the operation itself, with the manifest of what it touched, in the same transaction:

```php
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;

DB::transaction(function () use ($invoices): void {
    Invoice::query()->whereKey($invoices->modelKeys())->update(['status' => 'void']);

    AuditLog::event('invoice.voided')->covering($invoices)->record();
});
```

## Bulk operations

`covering($subjects)` makes any builder one entry of a bulk operation, with a manifest of its subjects:
`AuditLog::event($code)->covering($subjects)` from the application, or the builder a mapper is handed (see
[Mapping another package's events](extending.md#mapping-another-packages-events)). It writes nothing until
`record()`, and its timing is chosen as for any record: after commit by default. A builder takes one manifest.

- The subjects are models or references. The manifest holds each `[type, id]` once, sorted. The entry signs its
  descriptor, `properties._audit.manifest`, holding the manifest's artifact id, the SHA-256 digest of its canonical
  form and its count, and the members are kept in `entries.artifacts_table`, one row per operation, beside the entry.
- A manifest is bounded by `capture.bulk.max_members` (`AUDIT_LOG_CAPTURE_BULK_MAX_MEMBERS`, 100,000 by default, from 1
  to 1,000,000) and `capture.bulk.max_bytes` (`AUDIT_LOG_CAPTURE_BULK_MAX_BYTES`, 4,194,304 by default, from 65,536 to
  8,388,608), the size of its canonical form. A larger one is refused, never truncated, with an
  `\InvalidArgumentException` from `covering()`, and nothing is written; record a larger operation as
  several. At most four times `max_members` subjects are read, duplicates included, so an input that never ends is
  refused too.
- Only a store that keeps attachments can take one. `DatabaseAuditStore`, the fake and `NullAuditStore` do;
  `LogAuditStore` does not, since its line would lose the members; a stack does only when every destination does; and a
  store that does not implement `Contracts\AcceptsAttachments` does not. With any other store bound, `covering()` is a
  `\LogicException` before anything is built, so a manifest is never silently discarded.
- The database store writes the artifact and the entry in one transaction, in a savepoint when one is open, so both are
  kept or neither is. Storing the same bundle again is a no-op, and a different one under the same id is a conflict.
- The outbox and the spill keep the whole bundle: the record, its artifact and its sealed members, under an explicit
  bundle version. A drain and a replay store both, and a destination that keeps no attachments is that destination's
  failure, so the row is retried and kept, never deleted.
- The members are encrypted under `app.key`, through `encryptString()`, once, when the operation is recorded, and never
  again. A rotated key must stay in `app.previous_keys` for as long as artifacts sealed under it are kept, or they are
  unverifiable, though their entries still verify.
- `audit-log:verify` checks each bulk entry's artifact: that it is stored under the signed id, names the entry, is a
  bulk artifact, and that its members decrypt to the signed count, each once and in canonical order, with the signed
  digest. Each difference is its own finding: a missing artifact is `manifest_missing`, one stored under another id or
  naming another entry `manifest_swapped`, one stored as another kind `manifest_wrong_kind`, one storing another count
  or digest `manifest_mismatch`, members that are no canonical list `manifest_malformed`, another canonical list than
  the one signed `manifest_tampered`, and members that cannot be read `manifest_unreadable`. An entry's manifest is
  checked with its seal: until an entry is sealed, its artifact is checked by nothing.
- An artifact follows its entry's retention: it is never updated, and is deleted only with its entry, by the
  maintenance user, so a hold on the entry holds it too.

## When capture fails

A capture never throws into the code that dispatched the event, but for one failure. A mapper that throws, a malformed
setting, a watched field the instance hides and a failed write are each contained:

- The failure is reported once, without any value of the event or the record, `AuditCaptureFailed` is dispatched once,
  and the capture returns `null`. The sign-in, the Gate's check or the save goes on, and the listeners after the
  capture still run.
- A failed write is handled as any failed write first: the record is spilled, the sanitised
  `Stores\AuditWriteFailedException` is reported and `AuditWriteFailed` is dispatched, then `AuditCaptureFailed`. A
  capture always follows the `report` rule and never reads `failure.mode`, so `throw` never reaches the dispatching
  flow, and a captured record is never `failClosed()` or `transactional()`.
- Any other failure is reported as a `Capture\CaptureFailedException`, which names the classes of the event, of what
  translated it and of the exception, and holds no previous exception.
- The host-fatal exception: a deadlock or a lost connection that ended a transaction open on its connection, during a
  capture that writes at once, propagates sanitised, as a `DeadlockException`, a `Stores\AuditWriteFailedException`
  when the write itself lost its connection, or a `Capture\CaptureFailedException` when the connection was lost before
  the write, as it does from any record, because the application's transaction is already gone. It is neither spilled
  nor reported, and `AuditCaptureFailed` is still dispatched once.
- A watched model's change written at its commit lets nothing out: the change has committed, so the same failure
  there is spilled and reported. A failure while the record is built at the event, or an outbox insert made inside the
  model's own transaction, propagates sanitised as for any capture that writes at once.
- Nothing is captured while an entry is being written: an event dispatched by a store, a reporter or a listener of a
  failed write records nothing and reports nothing.

[The events guide](events.md) shows how to alert on `AuditCaptureFailed`, and [the outcomes
note](../design/outcomes.md) lists each captured row of the guarantees.
