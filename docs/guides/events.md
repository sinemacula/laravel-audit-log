# Events

The package tells the application what became of each record, and of the log as a whole, through three events. None
holds a value of a record, so a listener can pass one to an alerting tool or a queue without copying personal data.

| Event                                                     | Dispatched when                                                                             | Carries                                                                                                         |
|-----------------------------------------------------------|---------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|
| `SineMacula\Laravel\AuditLog\Events\AuditRecorded`        | The store has accepted a record                                                             | `id`, `code` and `category`                                                                                     |
| `SineMacula\Laravel\AuditLog\Events\AuditWriteFailed`     | A record could not be written                                                               | `id`, `code`, the `store` and `exception` classes                                                               |
| `SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed` | Sealing or verifying found the log altered, incomplete or unverifiable, or a verify stopped | `command`, the `integrity` and `anchoring` counts, `finding`, `firstBadId`, `head`, `remoteHead` and `complete` |

All three implement `SineMacula\Laravel\AuditLog\Contracts\AuditLogEvent`, and none is sent anywhere unless a listener
is registered. [The event model](../design/event-model.md) has the exact timing of each, and
[outcomes](../design/outcomes.md) has what each timing, mode and failure guarantees.

## Alert on a failed write

Listen for `AuditWriteFailed`. It fires whatever `failure.mode` says, so it is the one place to catch a failed write
whether or not the code that recorded it was told:

```php
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use SineMacula\Laravel\AuditLog\Events\AuditWriteFailed;

Event::listen(static function (AuditWriteFailed $event): void {
    Log::channel('ops')->error('An audit record could not be written.', [
        'id'        => $event->id,
        'code'      => $event->code,
        'store'     => $event->store,
        'exception' => $event->exception,
    ]);
});
```

- In `sync` mode it fires as the write fails. In `outbox` mode it fires when an insert fails, and from `audit-log:drain`
  when a row has used its last attempt. A retry dispatches nothing, so a brief outage of a destination raises no alert.
- A row the drain cannot read at all, because its key was removed or its envelope does not verify, has no code to name.
  It is reported by its id and dispatches no event, so route the package's reports to the same place: they are
  `SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException`.
- The record itself is in the spill unless it was transactional. `audit-log:replay` brings it back once the store is
  healthy; see [delivery](../design/delivery.md).
- Do not record from this listener. The write it reports just failed, so a record made here is refused, as the last
  section says.

## Alert on an integrity failure

Listen for `IntegrityCheckFailed`. It fires from the scheduled runs of `audit-log:seal` and `audit-log:verify`, and from
one started by hand, when a run finds the log altered, incomplete or unverifiable, when a `--strict` verification finds
a seal the anchor does not confirm, and when a verification stops before it can say:

```php
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed;

Event::listen(static function (IntegrityCheckFailed $event): void {
    Log::channel('ops')->critical('The audit log failed an integrity check.', [
        'command'      => $event->command,
        'integrity'    => $event->integrity,
        'anchoring'    => $event->anchoring,
        'finding'      => $event->finding,
        'first_bad_id' => $event->firstBadId,
        'head'         => $event->head,
        'remote_head'  => $event->remoteHead,
        'complete'     => $event->complete,
    ]);
});
```

- It carries no value of a record: only the command, counts, the code of the first finding, the id of the first seal
  or entry it was found at, and sequence numbers. It is safe to forward as it is.
- `integrity` counts segments by `valid`, `pruned`, `incomplete`, `unverifiable` and `tampered`, and `anchoring` by
  `anchored`, `unanchored`, `unavailable` and `contradicted`. Both always list every status, zero-filled, whichever
  command fired, so a listener reads one shape. An alarm from `audit-log:seal` counts its one failing condition once:
  entries it skipped as malformed count 1 under `unverifiable`, whatever their number, which its output prints.
- `firstBadId` is a lower-case UUID or `null`. An id read from an altered table that is no UUID, which could put a line
  break or a control character in a log, is never passed on.
- A verification that stopped, because something it reads failed under it or an anchor setting is malformed, has no
  `finding`, and `complete` is `false`: the log's integrity was not established either way. An event from
  `audit-log:seal` is never `complete` either, because sealing does not check the whole log. A seal run stopped by
  anything but a refused head dispatches no event: it is reported as a
  `SineMacula\Laravel\AuditLog\Integrity\SealFailedException` alone.
- A listener that throws is reported as it threw, as any listener of the package's events is, and the package's own
  report of the failure still follows it.
- The package also reports a `SineMacula\Laravel\AuditLog\Integrity\IntegrityCheckFailedException` for the same run, so
  route the package's reports to the same place.
- A scheduled run that never happens raises nothing: a stopped scheduler or a worker that is down dispatches no event.
  Monitor the progress the package records for the last seal, the last anchoring and the last full verification, as
  the operations guide describes, and alert when it goes stale.

## Alert on a stored record

Listen for `AuditRecorded` and match on the code:

```php
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\AuditLog\Events\AuditRecorded;

Event::listen(static function (AuditRecorded $event): void {
    if ($event->code === 'invoice.voided') {
        app(FinanceAlerts::class)->voided($event->id);
    }
});
```

- The event says the store accepted the record, and accepted is not always durable. For a `transactional()` or
  `immediately()` write inside a transaction, it fires before that commit, and a rollback afterwards takes the row away.
  Use a queued listener after the commit, below, when that matters.
- In `outbox` mode it fires from `audit-log:drain`, after the row is delivered. It does not fire for the request that
  recorded, and the listener has no authenticated user or request to read.
- A process that dies just before the dispatch loses the event and keeps the record, and a spill line replayed twice is
  dispatched twice. Treat the event as a signal, and key anything that counts on `$event->id`.
- To read more than the event carries, look the entry up by its id in a process allowed to read it.

## Use a queued listener

An event holds only ids, codes, counts and class names, so a queue payload or a `failed_jobs` row of a listener holds
nothing else of the record. Use `ShouldQueueAfterCommit` so a listener does not run for a record that then rolls back:

```php
use Illuminate\Contracts\Queue\ShouldQueueAfterCommit;
use SineMacula\Laravel\AuditLog\Events\AuditRecorded;

final class ForwardToMonitoring implements ShouldQueueAfterCommit
{
    public function handle(AuditRecorded $event): void
    {
        // The worker sees the id, the code and the category.
    }
}
```

What becomes of a queued listener then follows Laravel's own retry and failure handling. The package neither retries
it nor sees it fail.

## What a listener may do

- **Fail.** A synchronous listener's exception is reported and goes no further, so it never fails the write or reaches
  the code that recorded. Laravel stops a dispatch at the first listener that throws, though, so the ones behind it do
  not run for that record. A queued listener avoids that.
- **Use the database, with care.** A deadlock or a lost connection in a listener, on a connection with a transaction
  open, has ended that transaction, so it propagates, sanitised, to the host. That holds for any connection the
  application uses, not only the audit log's own. On a connection with none open it is reported like any other failure.
- **Record another code from `AuditRecorded`.** That is a normal pattern, and the record goes through the whole
  pipeline. A listener that records unconditionally, its own code included, recurses until the process stops, and the
  package does not catch that:

  ```php
  Event::listen(static function (AuditRecorded $event): void {
      if ($event->code === 'invoice.voided') {
          AuditLog::record('invoice.void_noticed');
      }
  });
  ```

- **Not record from `AuditWriteFailed`.** The same goes for a store, a reporter or a spill channel. An ordinary record
  made there comes back unwritten and one report of a `\LogicException` says so, and a `failClosed()` or
  `transactional()` record throws it.
- **Not assume a request.** A drain and a replay run on the command line, so read nothing from the request or the
  authenticated user in a listener that has to work in `outbox` mode.

In a test, fake only the event you mean to assert on, as `Event::fake([AuditRecorded::class])`, because a fake with no
list also replaces the dispatcher the package's frame listeners are on.
