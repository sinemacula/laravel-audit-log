# Outcomes

## Purpose

This note records what storing a finalised record answers, from the store's side: when `AuditStore::store()` returns,
which exception it raises for each way a write can fail, and what the caller's transaction is left as. A store either
keeps the record exactly once or says why it did not, so every result is listed here and none is silent; the failure
policy that decides what the application does with each of them is not part of the store. It also records, from the
caller's side, what each timing, delivery mode and failure promises: when `record()` has a record written, what its
return means, what a failed write does to the transaction it waited for, and what `AuditRecorded` says; and what a
read of the trail returns, and when, since its own record is written before anything it found is.

## Invariants

- `AuditStore::store()` takes a finalised record, never a model, and returns nothing: returning means a row with the
  record's id is stored and holds its captured content.
- A store keeps no state between calls and stores a record at most once. The same id with the same captured content
  is a success; different content is a `Stores\RecordConflictException`; every other failure propagates unchanged.
- `DatabaseAuditStore` answers as the table below says, on every supported engine:

  | What happens                                                                     | What the caller sees                                                                          |
  |----------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------|
  | The record is stored                                                             | `store()` returns                                                                             |
  | A row under the id verifies and holds the same captured content                  | `store()` returns; the first row is kept, its `recorded_at` and key included                  |
  | A row under the id verifies but holds different captured content                 | `RecordConflictException::differentContent()`                                                 |
  | A row under the id fails verification                                            | `RecordConflictException::unverified()`                                                       |
  | A row under the id is signed under a key the ring does not hold                  | `UnknownKeyException`                                                                         |
  | A row under the id has an unsupported version or is malformed                    | `\UnexpectedValueException`                                                                   |
  | Another unique index is violated, the source identity included                   | the original `UniqueConstraintViolationException`, never a success                            |
  | The row under the id is beyond a PostgreSQL REPEATABLE READ or SERIALIZABLE host | the original `UniqueConstraintViolationException`, never a success                            |
  | Any other statement failure                                                      | its `QueryException`; inside a host transaction the savepoint is rolled back and it is usable |
  | A deadlock or another concurrency error inside a host transaction                | Laravel's `DeadlockException` propagates; the write path passes on a sanitised one            |
  | A lost connection, or a PostgreSQL host transaction that is already aborted      | the exception propagates; the write path decides what follows, as the guarantees say          |
  | The storage connection is not a Laravel database connection                      | `\LogicException`                                                                             |

- A success is returned only after a row with the id was read on the writer, verified and found equal in captured
  content; every other path throws.
- The store decides nothing else: it never retries, never spills and never reports a failure itself.
- A failure the store or the outbox raises goes to `Delivery\FailureHandler` and no further.
  `Delivery\Enums\FailureRule` fixes once what each record does, from its timing, whether it fails closed and
  `failure.mode`: `transactional()` is `THROW`, then `failClosed()` or `failure.mode = throw` is `SPILL_AND_THROW`, and
  anything else is `REPORT`.
- Nothing thrown or reported is the original failure, whose message and bindings hold the row.
  `Stores\AuditWriteFailedException` holds the record's id and code, the operation, the store's class, the failure's
  class, its SQLSTATE and numeric driver code, the connection's alias and the destination, and has no previous
  exception.

## Success Path

- A new record returns after one insert; inside a host transaction, after one insert in a savepoint, and the host
  commits or rolls the entry back with its own work.
- A record stored again, by a retry or a replay of the same finalised record or by a second finalisation of the same
  captured record, returns without writing.

## Failure / Edge Cases

- A conflict leaves the first row as it was and, inside a host transaction, leaves the transaction usable.
- Two processes racing to store one record each wait on the other's row, then one stores it and the other resolves the
  duplicate as above; with different content, one of them is a conflict.
- The failure policy (spill, report, throw), the spill channel and the `AuditWriteFailed` event belong to the write
  path. What a failure of the store becomes for the caller of `record()` is in the guarantees below.

## Guarantees

Each row is one timing, delivery mode and failure, and `tests/Feature/Delivery/OutcomesTableTest.php` has one test for
each, named after its id.

- Mode is `delivery.mode` and Policy is `failure.mode`; `any` means the row holds whatever it is set to.
- A spill is one `critical` line on `failure.log_channel` holding the finalised record. A report is the sanitised
  `Stores\AuditWriteFailedException`, given to Laravel's reporter. An event is `AuditWriteFailed`.
- In outbox mode a row is an outbox row, which a drain delivers to the store later. `-` means the column does not apply.
- Rolled back when shared means on a connection the host's transaction is open on. A dedicated connection is outside it,
  and the write is kept whatever the host does.

| Row id                           | Timing                              | Mode                               | Policy  | Written                | On a failed write                                                                                                               | On the host's rollback                 | `record()` returning means                                                |
|----------------------------------|-------------------------------------|------------------------------------|---------|------------------------|---------------------------------------------------------------------------------------------------------------------------------|----------------------------------------|---------------------------------------------------------------------------|
| `after-commit-sync-report`       | after commit                        | sync                               | report  | at the commit          | spill, report, event; the commit stands                                                                                         | dropped                                | captured, in memory                                                       |
| `after-commit-sync-throw`        | after commit                        | sync                               | throw   | at the commit          | spill, event; throws from the commit                                                                                            | dropped                                | captured, in memory                                                       |
| `after-commit-none-open`         | after commit                        | sync                               | report  | now                    | spill, report, event                                                                                                            | none open                              | stored, or in the spill                                                   |
| `after-commit-outbox-same`       | after commit                        | outbox, selected on its connection | report  | now, inside it         | report, event at once; spill bound to the commit                                                                                | row and spill gone                     | a row that commits with the host                                          |
| `after-commit-outbox-same-throw` | after commit                        | same                               | throw   | now, inside it         | event; spill bound; throws now                                                                                                  | row and spill gone                     | a row that commits with the host                                          |
| `after-commit-outbox-other`      | after commit                        | outbox, selected elsewhere         | report  | at that commit         | spill, report, event                                                                                                            | dropped                                | captured, in memory                                                       |
| `immediately-sync-report`        | immediately                         | sync                               | report  | now                    | spill, report, event                                                                                                            | rolled back when shared                | stored, or in the spill                                                   |
| `immediately-sync-throw`         | immediately                         | sync                               | throw   | now                    | spill, event; throws                                                                                                            | rolled back when shared                | stored                                                                    |
| `immediately-outbox`             | immediately                         | outbox                             | report  | now                    | spill, report, event                                                                                                            | rolled back when shared                | a row, or in the spill                                                    |
| `transactional-sync`             | transactional                       | sync                               | any     | now, inside it         | event; throws; no spill                                                                                                         | rolled back                            | stored inside it                                                          |
| `transactional-outbox`           | transactional                       | outbox                             | any     | now, inside it         | event; throws; no spill                                                                                                         | rolled back                            | a row inside it                                                           |
| `fail-closed-sync`               | immediately                         | sync                               | any     | now                    | spill, event; throws                                                                                                            | rolled back when shared                | stored                                                                    |
| `fail-closed-outbox`             | immediately                         | outbox                             | any     | now                    | spill, event; throws                                                                                                            | rolled back when shared                | a row                                                                     |
| `fail-closed-transactional`      | transactional                       | either                             | any     | now, inside it         | event; throws; no spill                                                                                                         | rolled back                            | inside it                                                                 |
| `host-deadlock`                  | any, host open                      | any                                | any     | -                      | event; `DeadlockException`; no spill                                                                                            | the host's                             | -                                                                         |
| `host-connection-lost`           | any, host open                      | any                                | any     | -                      | event; `AuditWriteFailedException`; no spill                                                                                    | the host's                             | -                                                                         |
| `aborted-postgres-host`          | immediately                         | sync                               | report  | never                  | spill, report, event; no fatal error                                                                                            | rolled back                            | in the spill                                                              |
| `failed-finalise`                | immediately                         | sync                               | report  | never                  | unsigned spill, report, event                                                                                                   | -                                      | in the spill, unreplayable                                                |
| `inside-a-store`                 | any                                 | any                                | report  | never                  | one report of a `\LogicException`                                                                                               | -                                      | captured, unwritten                                                       |
| `inside-a-store-strict`          | `failClosed()` or `transactional()` | any                                | any     | never                  | `\LogicException`                                                                                                               | -                                      | does not return                                                           |
| `drain-transient`                | outbox drain                        | outbox                             | -       | on a later attempt     | receipt and row's error class, backoff                                                                                          | -                                      | -                                                                         |
| `drain-final`                    | outbox drain                        | outbox                             | -       | never, kept            | `failed_at`, report, event; never deleted                                                                                       | -                                      | -                                                                         |
| `drain-undecryptable`            | outbox drain                        | outbox                             | -       | never, kept            | `failed_at`, report by id; never deleted                                                                                        | -                                      | -                                                                         |
| `captured-report`                | immediately, captured               | any                                | ignored | now                    | spill, report, event, `AuditCaptureFailed`; nothing thrown                                                                      | rolled back when shared                | `capture()`: stored, or `null` and in the spill                           |
| `captured-host-fatal`            | immediately, captured, host open    | any                                | ignored | -                      | event, `AuditCaptureFailed`; a sanitised `DeadlockException`, `AuditWriteFailedException` or `CaptureFailedException`; no spill | the host's                             | -                                                                         |
| `captured-model-after-commit`    | after the model's commit            | any                                | ignored | at the commit          | spill, report, event, `AuditCaptureFailed`; the commit stands                                                                   | dropped                                | the save returns; captured, in memory                                     |
| `read-sync`                      | a read of the trail                 | sync                               | ignored | now, before the result | see `read-failed-write`                                                                                                         | none open: see `read-open-transaction` | the result, once its record is stored                                     |
| `read-outbox`                    | a read of the trail                 | outbox                             | ignored | now, a committed row   | see `read-failed-write`                                                                                                         | none open: see `read-open-transaction` | the result, once its record is accepted; delivered when drained           |
| `read-open-transaction`          | a read, a transaction open          | any                                | ignored | never                  | -                                                                                                                               | refused before any query               | does not return: `AuditReadRefusedException`, nothing queried or recorded |
| `read-failed-write`              | a read of the trail                 | any                                | ignored | never                  | spill, event, one report; `AuditReadRefusedException`                                                                           | -                                      | does not return: nothing it found is disclosed                            |

What the table cannot say in a cell:

- **A record for an uncommitted operation must not later become committed evidence.** So a transactional record's failed
  write leaves no replayable spill: the event and the thrown exception are its diagnostics. A failure or a denial can be
  true even when the business change rolls back, and it can be kept by writing it `immediately()` on a dedicated
  connection.
- The steps run in the order spill, report, event, each on its own, because the spill is the only lasting trace and a
  reporter may block or end the process. One that fails stops no other: its failure is reported, sanitised, and goes no
  further. With no transaction open, nothing it raises reaches the code that recorded.
- A record that throws is not also reported by the package, since Laravel's handler reports what reaches it and would
  report it twice.
- **The outbox moves failures ahead of the commit.** With `after-commit-outbox-same`, finalising and inserting happen
  inside the selected transaction, so a bad key ring or a failed insert shows before the commit rather than after it,
  and under `throw` the code that recorded can see it.
- **A bound spill waits in memory.** Between the failed insert and the commit that writes it, the spill exists only in
  the process, so a process that dies in that window leaves the report and the event, and no line.
- **An after-commit record's spill waits for any transaction still open on the connection it was written to**, not only
  for the one selected. A sync write in another connection's commit, an outbox insert after another connection's commit
  and a pinned record written now all join a transaction open there, so the spill goes with that transaction's commit
  and is discarded by its rollback.
- **An immediate or fail-closed record's spill is written at once**, because its host may already have failed. After an
  enclosing rollback the line is evidence of an attempt, not of a committed change, and replaying it is the operator's
  choice.
- A concurrency error or a lost connection while a transaction is open has ended that transaction, whatever the rule
  says, so `host-deadlock` and `host-connection-lost` are thrown to the host. They are never spilled, because a retried
  `transaction()` closure captures its record again under a new id and a spill would be a second record of one activity.
  With no transaction open the same failure ended nothing, and it follows the policy. A deadlock or a lost connection
  raised by a spill channel, a reporter or a listener on any connection with a transaction open propagates sanitised
  too, once the remaining steps have run: the write's own connection decides only what the write's own failure ended. -
  **What counts as fatal is read from the driver, not from the record.** A failed statement's message holds its
  bindings, so a record's value could read as a deadlock. The classifier reads the driver's own exception, and a data or
  constraint failure, whose driver message can quote a value, is never fatal. A lost connection is only ever a database
  failure, so a store's cURL error or a channel's missing file saying the same words is an ordinary failure, and a
  failure on a connection with no transaction open ended nothing. A `DeadlockException` is always fatal, because Laravel
  throws it having left the savepoint without a rollback; a serialisation failure reaches the host that way, and is
  retried.
- `aborted-postgres-host` is the one failure inside a host that follows the rule without a savepoint to protect it.
  PostgreSQL ends an aborted transaction with a rollback while reporting a success, so a spill bound to its commit would
  run for work that was undone: an after-commit record's spill is discarded there, a stack's destination included, and
  the report and the event still go out.
- **A commit that is really a rollback writes nothing.** The same holds when the application swallows a failed statement
  and then commits. So just before an outermost commit on PostgreSQL with audit work waiting on it, one `select 1` asks
  whether the transaction is still alive. When it answers `25P02`, a deferred write or outbox insert writes nothing and
  dispatches nothing, as for any rollback, and is reported with that SQLSTATE, because the application saw its commit
  succeed. A bound spill is dropped. A record inserted inside that transaction goes with it, and needs no question.
- `failed-finalise` leaves a line marked `unsigned`, with no integrity fields. Replay counts it and leaves it, because
  signing bytes anyone can edit would establish nothing about where they came from.
- `inside-a-store` and `inside-a-store-strict` hold for every record made while a store runs or a failure is handled.
  An ordinary record comes back unwritten, since it would fail or be refused the same way, and repeats inside one window
  are not reported again. A strict one is refused, because returning would break its guarantee, and left uncaught inside
  the store it is a failure of the write around it.
- The `captured-` rows hold for every record captured from an event: a mapped event, Laravel's authentication events, a
  Gate denial and a watched model's change. A capture follows the `report` rule and never reads `failure.mode`, so
  `throw` never reaches the code that dispatched the event, and a capture is never `failClosed()` or `transactional()`.
  A failed write is spilled, reported and said once, as `AuditWriteFailed`, then `AuditCaptureFailed` is dispatched
  once and the capture returns `null`.
- `captured-host-fatal` is the one failure a capture lets out. A deadlock or a lost connection that ended a transaction
  open on its connection, during a capture written now, propagates sanitised: a deadlock as a `DeadlockException`, as
  `host-deadlock` does; a connection the write itself lost as a `Stores\AuditWriteFailedException`, as
  `host-connection-lost` does; and a connection lost before the write, in a contributor or the minimiser, as a
  `Capture\CaptureFailedException`. `AuditCaptureFailed` is still dispatched once. The transactions open are read
  before the capture runs, because Laravel forgets one whose connection is lost. A watched model's change built at its
  event, and its outbox insert made inside the model's own transaction, are written now in this sense.
- `captured-model-after-commit` never throws from the commit. Whatever its write lets out, a host-fatal failure
  included, is reported and said, because the business data has already committed and the save that changed it
  returned long ago. Its record is spilled too, even when its failure ended a transaction still open on the storage
  connection, since the change it records has committed and the spill is the only trace left of it.
- **A read discloses nothing before its record is acknowledged.** The `read-` rows hold for every page, count, export
  and verification of the trail, and `record()` is the terminal call there: its record is fail-closed and immediate
  whatever `failure.mode` says, and what the read found is returned only once the store has the record, in sync mode,
  or a committed outbox row holds it, in outbox mode. Accepted is not delivered: the store holds an accepted record,
  and `AuditRecorded` is said, only when a drain has run.
- `read-open-transaction` holds for a transaction the framework would not yet call committed on the storage connection,
  and in outbox mode on the outbox connection as well, because a record inside it, or a row it would show, could still
  be rolled back. It is refused again just before the record is written, since the access policy may have opened one.
  The base transaction Laravel's testing helpers wrap a test in counts as committed, and a transaction on any other
  connection refuses nothing.
- `read-failed-write` is spilled once, the record with its disclosure, said as `AuditWriteFailed` and reported once by
  the read, and the read throws `Querying\AuditReadRefusedException`, which names nothing the read found.
- `drain-transient` is not reported, because a retry is expected to succeed; only `drain-final` is. An outage of the
  deliveries table is such a failure, so it backs off like any other. Only a row that kills its worker too often is
  failed as `abandoned` and reported, so it cannot loop forever. A failed row is delivered only by `audit-log:replay`.

## Timing

A record has exactly one timing, and `record()` returns the captured record (`AuditRecord`) whichever it is. The timing
decides when that record is stored, and so what its return promises:

| Timing            | Default for                                                        | When it is written                                                                                                               | On the host's rollback                                                            | What `record()` returning means                                                                       |
|-------------------|--------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------|
| `afterCommit()`   | explicit records: `record()`, `event()`, `accessed()` and `bulk()` | at the selected transaction's outermost commit; now when none is selected, or in outbox mode when it is on the outbox connection | dropped unwritten, by the selected transaction or one around it on its connection | captured and held in memory; already written only when none was selected, or in a row inside the host |
| `immediately()`   | captured records (`capture()`) and `failClosed()`                  | now, in a savepoint when the connection has an open transaction                                                                  | rolled back on a shared connection; kept on a dedicated one                       | written, or under `report` in the spill; durable once any transaction open on the connection commits  |
| `transactional()` | nothing: it is always asked for                                    | now, inside the open transaction on the connection, in a savepoint                                                               | rolled back with it, always                                                       | written inside that transaction; durable only when it commits                                         |

- The connection is the storage connection in sync mode and the outbox connection in outbox mode.
- A return is a written record only when a failed write would have thrown: with `failClosed()`, `transactional()` or
  `failure.mode = throw`. Under `report` a failed write returns too, and the record then exists only in the spill.
- A write costs one insert, and a savepoint as well when a transaction is open on the storage connection. A deferred
  record costs nothing until the commit, and a dropped one nothing at all. On PostgreSQL a commit with audit work
  waiting costs one `select 1` as well, however many records wait on it. These budgets cover the default contributors
  and a fresh insert.

### After Commit

- Without a name, the innermost pending transaction on any connection is selected. `afterCommit('billing')` pins that
  connection's innermost: a transaction on another connection neither delays nor cancels the record, and with only
  another connection's transaction open it is written now.
- A name no connection is configured under is an `\InvalidArgumentException` from `record()`, which opens no connection
  and writes nothing.
- Selecting the innermost promises nothing about a transaction around it on another connection. The write happens on
  the innermost's commit, so while a transaction is still open on the storage connection the write is inside it, and
  that transaction's rollback takes it away.
- A dedicated storage connection does not change what is selected: a default record waits for the host's transaction
  and is dropped by its rollback, though nothing would have rolled the row back. To keep a record whatever the host
  does, write it `immediately()` or pin the dedicated connection.
- A connection named with a read or write selector, such as `afterCommit('reporting::write')`, is the connection it
  selects, so the record waits for that connection's transaction and goes with its rollback.
- A transaction the testing manager wraps a test in is never selected, so a record inside only that wrapper is written
  at once. The current manager is read on every record, so one swapped in later is the one consulted.
- `occurred_at` is when the record was captured and `recorded_at` when it was written.
- A record waiting for its commit exists only in memory, so a process that dies between a sync commit and its write
  loses it. `transactional()` closes that gap, and so does the outbox when the selected transaction is on its
  connection.
- **The gap stays for `after-commit-outbox-other`.** With the selected transaction on another connection, the outbox row
  is inserted after that commit, and two connections share no commit, so a process that dies between the two loses the
  record. Pin the outbox connection, or use `transactional()` on it, to close it.

### Captured Records

- A captured record is written immediately under `report`, whatever `failure.mode` says, so a capture inside a
  transaction is written in a savepoint and rolled back with the host on a shared connection.
- Model changes are the exception, the one captured source that waits for commit. A watched model's record is built and
  minimised when its event fires, then written after the commit of the transaction open on the model's own connection,
  `$model->getConnection()->getName()`, and dropped by its rollback. In outbox mode, with the outbox on that connection,
  its row is inserted inside the transaction, as `after-commit-outbox-same` is.
- A mapper never chooses a timing, `failClosed()` or `transactional()`: a mapped record that sets any of them is a
  contained capture failure, and writes nothing.

### Immediately and the Savepoint

- The savepoint adds isolation, not durability. It stops a failed audit insert poisoning a healthy host transaction,
  and it keeps nothing past that transaction's rollback.
- For a record to survive a host rollback, `storage.connection` names a dedicated connection and the record is written
  immediately. The host's transaction is not open on that connection, so no savepoint is used.

### Transactional

- `transactional()` needs a transaction already open on the connection it writes to: the storage connection in sync mode
  and the outbox connection in outbox mode. Its preconditions are checked when `record()` runs, before any contributor.
  Each refusal is a `\LogicException`, writes nothing and leaves the builder usable, so the same builder can be recorded
  once a transaction is open. It is refused when:
  - it names a connection other than that one, even one with a transaction open; in sync mode that needs the outbox
  - no transaction is open on it, even when one is open on the host's and it is dedicated
  - it is not a Laravel database connection
  - in sync mode, the store does not say it joins that transaction through
    `Contracts\DurableAuditStore::participatesIn()`
- A test's wrapping transaction counts as open, so inside only that wrapper a `transactional()` record is accepted.
- A failed write is `AuditWriteFailed` and a thrown `Stores\AuditWriteFailedException`, under either `failure.mode`, and
  no spill, and its savepoint leaves the host's transaction usable. The caller must not catch the exception and commit,
  since the business change would then commit without its record; left uncaught, it rolls the business change back.
- `participatesIn()` is what the check asks, so the atomicity is the store's to claim. `DatabaseAuditStore` joins its
  storage connection, and a stack only when every destination does. A store without the contract counts as joining
  nothing. In outbox mode the row is what joins the transaction, so the store is not asked.

### Fail Closed

- A `failClosed()` record is written immediately unless it is transactional, when it stays transactional and needs the
  transaction. `failClosed()` never combines with `afterCommit()`, whichever is called first (see `record-model.md`).
- It needs a store that says a return is durable through `Contracts\DurableAuditStore::isDurable()`, or it is refused
  with a `\LogicException`. In outbox mode the row is the acknowledgement, so the store is not asked.
- A return means the insert succeeded, of the entry or of the outbox row, and it is durable once any transaction open on
  that connection commits.
- A failed write is spilled at once, followed by `AuditWriteFailed`, and thrown as `Stores\AuditWriteFailedException` to
  the call, under either `failure.mode`; a transactional one dispatches the event and is thrown, and is not spilled.

### A Failed Write

- A failed write follows the record's rule, as the guarantees say, and whatever is thrown is sanitised.
- An immediate or transactional write, or an after-commit write with no transaction selected, fails inside `record()`.
- **Under `report`, an after-commit write failure leaves the commit alone.** The business data is committed, the
  after-commit callbacks registered behind the record still run, and the failure is in the spill, the report and the
  event.
- **Under `throw`, an after-commit write failure surfaces after the business data has committed.** The exception comes
  out of the code that committed, `commit()` or `DB::transaction()`, long after `record()` returned. The business data
  stays committed, the connection is out of its transaction and no row exists, so the exception does not mean a
  rollback, and retrying the work repeats what already committed. - **One record's failure costs no other.** Every
  deferred write and bound spill of an outermost transaction, and of those nested in it, runs in one commit callback,
  placed at the first audit use in that transaction. All of them run, the first failure is thrown once they have, and
  any later one is reported, since only one exception can leave a commit.
- That thrown failure stops the application's after-commit callbacks registered behind the first audit use, because
  Laravel runs them in order and nothing catches the exception. The callbacks before it have already run.
- **An application callback can still cost the audit log its records.** One that throws and was registered before the
  first audit use in the transaction, or on a transaction nested in it, stops the commit's remaining callbacks, the
  audit log's among them, because nothing can run ahead of it. Those records are lost without a trace. Use
  `transactional()` or the outbox on the same connection for a record that must not depend on the application's
  callbacks.

### AuditRecorded

- `AuditRecorded` means the store accepted the record. It carries the record's id, code and category and nothing else,
  so no value of the record reaches a listener.
- In sync mode it follows the write. In outbox mode an insert in the outbox dispatches nothing: it is dispatched by the
  drain, after the store call and the row's delete, so a stale worker dispatches nothing and a process that dies between
  the delete and the dispatch loses the event, never the record.
- Accepted is not always durable. For a `transactional()` write, or an immediate write inside a transaction, the record
  is durable only when that transaction commits: the event is dispatched before the commit, and a rollback afterwards
  takes the row away. The same goes for an after-commit write made inside a transaction still open on the storage
  connection.
- A record dropped by a rollback and a failed write dispatch nothing.
- It is dispatched outside the write. A synchronous listener's exception is reported and goes no further: not to the
  caller, not into another write and not to a later after-commit callback, unless it is a deadlock or a lost connection
  on any connection with a transaction open, which has ended that transaction and propagates sanitised. A reporter that
  fails too is ignored, on the same condition. Laravel stops a dispatch at the first listener that throws, so the
  listeners behind it do not run for that record.
- A queued listener is queued as any other, and what becomes of it follows Laravel's normal handling.
- A listener or a contributor that records unconditionally recurses, and it is the application's to stop: the write
  guard covers a store and the failure path, and not those two.

## Implementation Anchors

- `src/Contracts/AuditStore.php`: `store()`.
- `src/Contracts/DurableAuditStore.php`: `isDurable()`, `participatesIn()`.
- `src/Stores/DatabaseAuditStore.php`: `store()`.
- `src/Stores/RecordConflictException.php`: `differentContent()`, `unverified()`.
- `src/Stores/AuditWriteFailedException.php`, `src/Stores/WriteDiagnostics.php`, `src/Stores/FailureSettings.php`.
- `src/Stores/FailureSpill.php`: `spillFinalised()`, `spillUnsigned()`.
- `src/Integrity/UnknownKeyException.php`, `src/Integrity/RecordSigner.php`: `verifies()`, `capturedDigest()`.
- `src/Records/Concerns/ChoosesDelivery.php`: `afterCommit()`, `immediately()`, `transactional()`, `failClosed()`.
- `src/Delivery/RecordDelivery.php`: `check()`, `deliver()`.
- `src/Delivery/OutboxWriter.php`: `write()`.
- `src/Delivery/OutboxDrainer.php`: `drain()`.
- `src/Delivery/FailureHandler.php`: `handle()`, `abandon()`.
- `src/Delivery/CommitQueue.php`: `defer()`, `reserve()`, `probe()`; `src/Delivery/CommitFlush.php`: `run()`, `doom()`.
- `src/Delivery/Enums/FailureRule.php`: `for()`.
- `src/Delivery/RecordedNotifier.php`: `notify()`.
- `src/Database/AfterCommit.php`: `selected()`; `src/Database/OpenTransactions.php`: `names()`.
- `src/Database/FailureClassifier.php`: `sanitisedDeadlock()`, `masked()`, `isConcurrencyError()`, `isLostConnection()`,
  `connectionOf()`.
- `src/Runtime/WriteGuard.php`: `during()`.
- `src/Events/AuditRecorded.php`, `src/Events/AuditWriteFailed.php`, `src/Events/AuditCaptureFailed.php`.
- `src/Querying/ReadGate.php`: `enter()`, `confirmDurable()`; `src/Querying/AccessRecorder.php`: `record()`.
- `src/Capture/CaptureCoordinator.php`: `mapped()`, `captured()`; `src/Delivery/CaptureSignal.php`: `defer()`, `fail()`;
  `src/Capture/ModelChangeDescriber.php`.

## Authoritative Tests

- `tests/Feature/Delivery/OutcomesTableTest.php` `testRowAfterCommitSyncReport`, `testRowAfterCommitSyncThrow`,
  `testRowAfterCommitNoneOpen`, `testRowAfterCommitOutboxSame`, `testRowAfterCommitOutboxSameThrow`,
  `testRowAfterCommitOutboxOther`, `testRowImmediatelySyncReport`, `testRowImmediatelySyncThrow`,
  `testRowImmediatelyOutbox`, `testRowTransactionalSync`, `testRowTransactionalOutbox`, `testRowFailClosedSync`,
  `testRowFailClosedOutbox`, `testRowFailClosedTransactional`, `testRowHostDeadlock`, `testRowHostConnectionLost`,
  `testRowAbortedPostgresHost`, `testRowFailedFinalise`, `testRowInsideAStore`, `testRowInsideAStoreStrict`,
  `testRowDrainTransient`, `testRowDrainFinal`, `testRowDrainUndecryptable`, `testRowCapturedReport`,
  `testRowCapturedHostFatal`, `testRowCapturedModelAfterCommit`, `testEveryRowOfTheTableHasATest`,
  `testEveryRowOfTheTableHasEachColumn`, `testADeadlockAtACommitWithNothingOpenFollowsThePolicy`,
  `testADeadlockAtAnotherCommitInsideAHostIsTheHosts`,
  `testAnAfterCommitSpillWaitsForATransactionStillOpenOnItsConnection`,
  `testASpillWrittenAtOnceOutlivesAnEnclosingRollback`, `testAStrictRecordLeftUncaughtInsideAStoreFailsTheOuterWrite`,
  `testTheOutboxAcknowledgesForAStoreThatIsNotDurable`, `testRowReadSync`, `testRowReadOutbox`,
  `testRowReadOpenTransaction`, `testRowReadFailedWrite`
- `tests/Feature/Delivery/FailureHandlerTest.php` `testReportDoesEachStepAndContinues`, `testTheSpillGoesFirst`,
  `testAThrownFailureIsNotAlsoReportedByThePackage`, `testThrowEmitsTheEventAndNeverASpill`,
  `testTheThrownExceptionHasNoPrevious`, `testAFailedSpillStopsNothingElse`, `testABrokenReporterStopsNothingElse`,
  `testAThrowingListenerStopsNothingElse`, `testAHostFatalSecondaryFailurePropagatesSanitised`,
  `testAnUnfinalisedRecordIsSpilledUnsigned`
- `tests/Feature/Delivery/OutboxWriterTest.php` `testAfterCommitOnTheOutboxConnectionInsertsInsideIt`,
  `testAfterCommitOnAnotherConnectionWaitsForItsCommit`,
  `testAFailedInsertInTheSelectedTransactionBindsItsSpillToTheCommit`, `testARolledBackHostDiscardsTheSpill`,
  `testACommittedHostSpillsOnce`, `testDiagnosticsGoOutAtOnce`, `testAFailedFinaliseOnThisPathFailsBeforeTheCommit`,
  `testAFailedTransactionalInsertNeverSpills`, `testAFailedImmediateInsertSpillsAtOnce`,
  `testAnInsertAfterAnotherCommitInsideAnOpenOutboxTransactionBindsItsSpill`
- `tests/Feature/Delivery/OutboxDrainerTest.php` `testAFailureRetriesWithBackoff`, `testATransientFailureIsNotReported`,
  `testTheFinalAttemptFailsTheRowAndKeepsIt`, `testTheFinalFailureIsReported`, `testAFailedRowIsNotClaimedAgain`,
  `testARowThatCrashedPastItsAttemptsIsAbandoned`, `testAnUndecryptablePayloadIsFailedAndKept`,
  `testAnUndecryptableRowIsReportedById`, `testAuditRecordedFollowsTheDelete`
- `tests/Feature/Delivery/RecordedNotifierTest.php` `testAHostFatalListenerFailureInsideAHostPropagatesSanitised`,
  `testAListenerFailingOnAnOpenConnectionPropagates`, `testAListenerFailingOnAnIdleConnectionIsContained`,
  `testAPhraseOutsideTheDatabaseIsContained`, `testAReporterEndingAnOpenTransactionPropagates`
- `tests/Feature/Delivery/CommitQueueTest.php` `testTwoRecordsUnderThrowAreBothAttempted`,
  `testAThrowingCallbackBetweenTwoRecordsStopsNeither`, `testAThrowingCallbackStopsNoBoundSpill`,
  `testANestedRollbackDropsOnlyItsOwnWork`, `testAnAbortedAnswerDoomsTheWork`
- `tests/Integration/Delivery/AbortedCommitTest.php` `testASyncRecordOfAnAbortedTransactionIsNotWritten`,
  `testAnOutboxRowOfAnAbortedTransactionIsNotInserted`, `testASpillBoundBeforeTheHostAbortedIsNotWritten`,
  `testAStackOverAnAbortedHostLeavesNoSpill`, `testAHealthyCommitWritesTheRecord`
- `tests/Integration/Delivery/HostileValuesTest.php` `testAValueInAFailedStatementsBindingsIsNotFatal`,
  `testAValueTheDriverQuotesLeavesTheHostUsable`
- `tests/Integration/Delivery/OutboxTransactionsTest.php` `testAnAbortedPostgresHostDiscardsTheBoundSpill`
- `tests/Integration/Stores/DatabaseAuditStoreTest.php` `testStoresTheFinalisedRecordAsOneRow`,
  `testTheSameRecordStoredTwiceIsOneRow`, `testTheSameContentWithADifferentRecordedAtKeepsTheFirstRow`,
  `testTheSameContentSignedWithAnotherKeyKeepsTheFirstRow`, `testDifferentContentUnderTheSameIdIsAConflict`,
  `testATamperedRowWithItsOldHmacIsAConflict`, `testAnExistingRowUnderAnUnknownKeyPropagates`,
  `testAMalformedExistingRowPropagates`, `testASourceIdentityViolationPropagatesTheOriginalException`,
  `testAViolationOfAnotherUniqueIndexPropagates`, `testAFailedAuditInsertLeavesAHealthyHostTransactionUsable`,
  `testADuplicateResolvedInsideAHostTransactionLeavesItUsable`, `testAnAlreadyAbortedPostgresHostTransactionPropagates`,
  `testTheStoreCatchesNothingButADuplicate`, `testAConnectionWithoutTransactionsIsRefused`
- `tests/Integration/Stores/ConcurrentDuplicatesTest.php` `testAConcurrentDuplicateWithTheSameContentStoresOneRow`,
  `testAConcurrentDuplicateWithDifferentContentIsAConflict`,
  `testOnMySqlALockWaitTimeoutInsideAHostTransactionPropagates`
- `tests/Integration/Stores/HostTransactionCallbacksTest.php` `testAHostCallbackSurvivesAFailedAuditInsert`,
  `testARolledBackHostDropsItsCallbackAndTheEntry`
- `tests/Unit/Stores/RecordConflictExceptionTest.php` `testDifferentContentNamesTheIdAndKeepsIt`,
  `testAnUnverifiedRowNamesTheIdAndKeepsIt`
- `tests/Integration/Delivery/AfterCommitTimingTest.php` `testWrittenOnCommit`, `testDroppedOnRollback`,
  `testDroppedOnAnInnerRollbackOfTheSelectedTransaction`, `testAnInnerRollbackKeepsARecordOfTheOuterTransaction`,
  `testAnInnerCommitWaitsForTheOuterCommit`, `testDroppedOnAnOuterRollbackAfterAnInnerCommit`,
  `testWrittenNowWithNoTransaction`, `testTheCapturedRecordIsReturnedBeforeItIsWritten`,
  `testOccurredAtIsCaptureTimeAndRecordedAtIsWriteTime`, `testTheDefaultSelectsTheInnermostOnAnyConnection`,
  `testNestedTransactionsOnTwoConnectionsWriteOnTheInnermostsCommit`,
  `testAWriteInsideAnOpenStorageTransactionRollsBackWithIt`, `testPinningWaitsForThatConnectionWhileAnotherIsInnermost`,
  `testPinningWritesNowWhenOnlyAnotherConnectionIsOpen`, `testAPinnedRecordIsDroppedByItsOwnConnectionsRollback`,
  `testPinningAReadOrWriteSelectorStillDefers`, `testARecordPinnedWithASelectorIsDroppedOnRollback`,
  `testAPinnedRecordIgnoresTheOtherConnectionsRollback`, `testPinningAnUnknownConnectionIsRefusedAndWritesNothing`,
  `testAFailedWriteSurfacesAfterTheBusinessDataHasCommitted`, `testAFailedWriteStopsLaterAfterCommitCallbacks`,
  `testTheDedicatedDefaultIsDroppedByAHostRollback`, `testPinningTheDedicatedConnectionIgnoresTheHostsRollback`
- `tests/Integration/Delivery/TestingManagerTimingTest.php` `testTheWrapperIsNotSelected`,
  `testARecordInsideOnlyTheWrapperIsWrittenAtOnce`, `testANestedTransactionDefersToItsCommit`,
  `testANestedRollbackDropsTheRecord`, `testAManagerSwappedAfterTheRecorderIsResolvedIsConsulted`,
  `testTheSameBehaviourUnderLaravelsOwnManager`, `testATransactionalRecordIsAcceptedInsideOnlyTheWrapper`
- `tests/Integration/Delivery/TransactionalTimingTest.php` `testAtomicWithTheHostOnCommit`, `testRolledBackWithTheHost`,
  `testRefusedWithNoOpenTransaction`, `testRefusedWhenTheTransactionIsOnAnotherConnection`,
  `testRefusedNamingAnotherConnection`, `testAcceptedNamingTheStorageConnection`, `testARefusalLeavesTheBuilderUsable`,
  `testAFailedWritePropagatesAndTheHostStaysUsable`, `testAFailedWriteLeftUncaughtRollsBackTheBusinessChange`,
  `testFailClosedTransactionalStaysTransactional`, `testRefusedOnADedicatedConnectionWithOnlyTheHostsTransactionOpen`
- `tests/Integration/Delivery/ImmediateTimingTest.php` `testWrittenNowInsideATransaction`,
  `testRolledBackWithTheHostOnASharedConnection`, `testSurvivesAHostRollbackOnADedicatedConnection`,
  `testAFailedWritePropagatesAndTheHostStaysUsable`, `testFailClosedIsWrittenNow`,
  `testAFailClosedRecordsFailedWriteReachesTheCallerAtTheCall`, `testFailClosedSurvivesOnADedicatedConnection`,
  `testAuditRecordedIsDispatchedBeforeTheHostCommits`
- `tests/Performance/RecorderQueryBudgetTest.php` `testOneExplicitRecordIsOneInsert`,
  `testAnExplicitRecordInATransactionCostsNothingUntilCommit`, `testADroppedRecordCostsNothing`,
  `testATransactionalRecordIsOneInsertAndASavepoint`, `testAnImmediateRecordOutsideATransactionIsOneInsert`,
  `testAnImmediateRecordInsideATransactionAddsOnlyASavepoint`, `testTheBudgetExcludesAQueryingContributor`
- `tests/Feature/Recording/AuditRecordedDispatchTest.php` `testDispatchedAfterAWrite`,
  `testCarriesOnlyTheIdCodeAndCategory`, `testAThrowingListenerIsReportedAndTheRowExists`,
  `testAThrowingListenerNeverReachesTheCaller`, `testDispatchedForAWriteLaterRolledBack`,
  `testNotDispatchedForADroppedRecord`, `testNotDispatchedForAFailedWrite`, `testAQueuedListenerFollowsLaravelsHandling`
- `tests/Feature/Delivery/RecordDeliveryTest.php` `testAThrowingReporterIsContained`,
  `testANotificationFailureNeverCausesAnotherWrite`, `testAThrowingListenerDoesNotStopALaterAfterCommitCallback`,
  `testTransactionalOnAForeignConnectionIsRefused`, `testADeferredWritesFailureReachesTheCommit`,
  `testAReportModeFailureReturnsAndNotifiesNothing`, `testADeferredReportModeFailureLeavesTheCommitAlone`,
  `testADeferredReportModeFailureLeavesLaterCallbacksRunning`, `testAHostFatalWriteFailurePropagatesInReportMode`,
  `testADeadlockWithNothingOpenFollowsTheRule`, `testAFailedFinaliseFollowsThePolicy`,
  `testAnAfterCommitFailureInsideAnOpenStorageTransactionBindsItsSpill`,
  `testARecordInsideAStoreIsRefusedReportedAndReturned`, `testACaptureFollowsTheReportRuleUnderTheThrowMode`,
  `testACaptureIgnoresAMalformedFailureMode`, `testADeferredCapturesFailureIsSignalledAtCommit`,
  `testADeferredCaptureNeverThrowsFromTheCommit`
- `tests/Feature/Capture/CaptureCoordinatorTest.php` `testAWriteFailureIsHandledOnce`,
  `testTheThrowFailureModeIsIgnored`, `testAMapperChoosingTheTimingIsContained`
- `tests/Integration/Capture/ModelChangeTimingTest.php` `testAChangeIsWrittenOnlyWhenItsTransactionCommits`,
  `testARolledBackChangeIsNeverRecorded`, `testADeferredWriteFailureIsSignalledAfterCommit`

## Change Triggers

Update this note when any of the following change:

- what the store returns, or an exception it raises or lets propagate
- how a duplicate is told from a conflict
- what a failed audit statement leaves the host transaction as
- the failure policy, what a row of the guarantee table says, or a row added or removed
- when a timing writes a record, what a rollback does to it, or what `record()` returning means
- what `transactional()` or `failClosed()` needs or refuses
- what a failed after-commit write does to the commit or to later callbacks, or what a commit asks before it runs
- what makes a failure fatal to an open transaction
- where a spill goes, when it is written, or what discards it
- what the outbox writes inside a transaction, or what the drain does with a failure
- what `AuditRecorded` carries or means, or how a listener's failure is handled
- when a captured record is written, which rule it follows, or what its failure lets out
- what a read returns before or after its record is acknowledged, or what refuses it
