# Delivery

## Purpose

This note records how a finalised record reaches its store and what is left when it does not: the pipeline, the outbox
and its drain, the receipts each destination keeps, the spill channel and the replay that reads it, the stores the
package ships and what each can promise, the path a record captured from an event takes and the bundle a bulk
operation travels as, and the formatters that project a record as one line. A delivery mechanism that loses, repeats or
invents a record changes what the log is evidence of, so each of those limits is stated here.
`outcomes.md` holds the table of what each timing, mode and failure guarantees; this note holds the machinery behind it.

## Invariants

- `delivery.mode` (`Delivery\Enums\DeliveryMode`) is `sync` by default, which stores a record as it is written, or
  `outbox`, which inserts it in the outbox for a drain to deliver.
- `failure.mode` (`Stores\Enums\FailureMode`) is `report` by default, or `throw`. It decides what a failed write does to
  the code that recorded it, and `outcomes.md` says what follows from each.
- A record is finalised once, by `Records\RecordFinaliser`, before any store, outbox row or spill line sees it. A retry
  and a replay reuse the finalised record, so every destination receives the same bytes.
- `Records\EnvelopeCodec` is the one decoder of a record kept outside the entries table, for the outbox and the spill
  alike. It holds an envelope to its version's schema and verifies its signature before it builds anything, and it keeps
  the id, the times, the provenance and the JSON types as they were signed. It never minimises or finalises again.
- The `Contracts\AuditStore` binding is the only seam: there is no manager and no driver registry, and the store is
  resolved for each write, so one bound later is the one used.
- Nothing thrown, reported or stored about a failure holds its message. `Stores\WriteDiagnostics` reads a failure's
  class, SQLSTATE and numeric driver code, the connection's alias and the destination, and the operation that failed
  (`Stores\Enums\FailedOperation`): `finalise`, `store`, `outbox`, `spill`, `notify` or `drain`. A `QueryException`'s
  message holds the row, so it is never chained, never reported and never read, and inside a savepoint Laravel is handed
  it masked, so a record's value cannot read as a deadlock and cost the savepoint its rollback. The destination names
  every destination that failed in a sync stack, its ids separated by commas, and the one that failed in a drain.
- The outbox row holds the envelope's canonical JSON encrypted with `Illuminate\Contracts\Encryption\StringEncrypter`,
  through `encryptString()` and `decryptString()`, never PHP serialisation. The row's id is the record's id, and a row
  whose envelope holds another is refused as `id_mismatch`.
- The spill and the outbox hold personal data, and `threat-model.md` says what follows from that.
- A record captured from an event is delivered with its capture's signal, `Delivery\CaptureSignal`, and follows the
  `REPORT` rule whatever `failure.mode` says. A record with an attachment, a bulk operation's or a read's, is
  delivered as one bundle, and only to a store that keeps attachments.
- A record of the package's own read path, a read, a count, an export, the verification of an export or an export's
  failed publication, is a package write, `Delivery\PackageWrite`: fail-closed and immediate whatever `failure.mode`
  says. `RecordPipeline::write()` refuses a code under the reserved `audit_log.` prefix without one, and a package write
  of any other code. Its `accept` check runs once the record is built and before anything is delivered, refusing a
  record that would not keep its evidence exactly, and its `acknowledged` hand-over receives the finalised record once
  the store has stored it or the outbox row is inserted, so the read discloses nothing before then, as `reading.md` sets
  out.
- Accepted is not delivered. In sync mode the store's return is both. In outbox mode a committed outbox row is the
  record's acceptance: it is durable, and a read's result or an export's publication may follow it, but the store holds
  the record, and `AuditRecorded` is said, only once a drain has delivered it. `Querying\Enums\Acknowledgement` names
  which an export's journal had, `stored` or `accepted`.
- No payload reaches `failed_jobs`, because no job exists. The drain is a command, and an empty job would not have been
  enough on its own: Laravel stores exception text in `failed_jobs` separately from the payload.

## Success Path

1. `record()` reads both modes, refuses what it cannot honour and captures the record, all before anything is deferred,
   so a malformed setting is a refusal at the call and never an exception out of a commit callback.
2. The timing decides when the write runs, and the mode decides where it goes.
3. In `sync` mode the write finalises the record, calls `AuditStore::store()` inside the write guard and dispatches
   `AuditRecorded`.
4. In `outbox` mode `Delivery\OutboxWriter` finalises the record, encrypts its envelope and inserts one row:
   - after commit, with the selected transaction on the outbox connection: now, inside that transaction, so the row
     exists exactly when the transaction commits and an inner rollback removes it
   - after commit, with the selected transaction on another connection: in that transaction's commit callback
   - `immediately()`, `transactional()` or no selected transaction: now, in a savepoint when a transaction is open on
     the outbox connection
5. The application runs `audit-log:drain`, from its scheduler or a worker of its own. The package does not schedule it:

   ```php
   Schedule::command('audit-log:drain --until-empty')->everyMinute();
   ```

6. Each run takes the rows due when it starts, at most `--limit` (100 by default, from 1 to 10000) or, with
   `--until-empty`, batch after batch of that many. It claims each row, decrypts and verifies it, delivers it to each
   destination, deletes the row once every destination has it and then dispatches `AuditRecorded`. It prints how many
   rows were delivered, retried, failed, taken over and missed, and exits non-zero when any row failed.

## Failure / Edge Cases

- **The in-transaction path moves finalisation and insert failures before the commit.** A bad key ring or a failed
  insert shows up inside the host's transaction, where a `throw` can stop it, instead of after the business data has
  committed.
- A failed insert uses a savepoint, so it does not poison a healthy host, and it follows the record's rule. The
  diagnostics go out at once, while a spill waits for the transaction it depends on, as `outcomes.md` says.
- `transactional($connection)` in outbox mode must name the outbox connection, and any other is a `\LogicException`.
- `immediately()` in outbox mode rolls back with an enclosing transaction on the outbox connection. Only a dedicated
  outbox connection keeps the row whatever the host does.
- A drain inside a transaction would hold its receipts and entries for that commit while a delete on a separate outbox
  connection commits at once, so a rollback would lose the record. So the drain refuses to run inside a transaction on
  either connection, with a `\LogicException`, before it claims anything.
- A failed delivery is retried without a report, after a wait that doubles from `delivery.outbox.backoff_seconds` with
  each attempt up to an hour, with no jitter. Only the class of its failure is kept, on the row and the receipt. At
  `delivery.outbox.max_attempts` the row gets `failed_at` and stays in the table, the failure is reported and
  `AuditWriteFailed` is dispatched. A failed row is never deleted and never claimed again until a replay requeues it.
- Reading or writing a receipt is part of delivering, so an outage of the deliveries table is a failed delivery: it
  backs off, keeps the failure's class and is reported at the last attempt.
- A row whose work stops for any other reason is reported and retried after the same wait, and stays on its lease only
  when that retry cannot be written either, so the outbox itself is out of reach. A claim that fails is reported,
  counted missed, and stops no other row. A run stopped by something else, such as a missing table, prints the class and
  the tally so far, and reports it as a `Stores\AuditWriteFailedException` with no record id, because a scheduled run's
  output is discarded by default.
- `attempts` counts at the claim, so an attempt that kills its worker still counts. A row claimed past
  `delivery.outbox.max_attempts`, which only repeated crashes reach, is failed as `abandoned` and reported, so a record
  that kills its worker cannot loop forever.
- A decrypt failure means a removed key or corruption, and the row is kept: it is failed as `undecryptable` and reported
  by its id. Old keys must stay in `app.previous_keys` while rows need them, and restoring a key there makes such a row
  readable to a replay.
- An envelope in the outbox that does not verify is failed and kept under its failure's stored value, and is never
  repaired or signed again.
- `payload` is `longText`, and an envelope is at most `Records\EnvelopeCodec::MAX_BYTES`, two budgets of 16 MiB and 64
  KiB of columns. Encrypted, the largest is about 60 MiB, which fits MySQL's default `max_allowed_packet` of 64 MiB; a
  server set lower refuses the insert. An envelope over the bound is refused as `oversize` and follows the failure
  policy.
- A deadlock or a lost connection has ended the transaction it happened in, whoever raised it. So a host-fatal failure
  of a spill channel, a reporter or a listener on any connection with a transaction open propagates sanitised, once the
  remaining steps have run, as the write's own failure does. Which connections had one open is read before the write,
  because Laravel forgets it when a connection is lost. A failure on a connection with none open is contained and
  reported.
- Deferred writes and bound spills wait in one commit callback per outermost transaction, so one record's failure stops
  no other, and `outcomes.md` says what that leaves. On PostgreSQL that commit first asks whether the transaction is
  already aborted, and writes nothing if so.
- The write guard refuses a record made while a store runs or a failure is handled, the drain's included. An ordinary
  record comes back unwritten and is reported once in that window, and a `failClosed()` or `transactional()` record
  throws a `\LogicException`. It covers a store, a reporter, a spill channel and an `AuditWriteFailed` listener, and not
  a contributor or an `AuditRecorded` listener; see `event-model.md`.
- `audit-log:check` reports what it can before a deploy. Under `[delivery]`, each a problem that exits non-zero: a spill
  channel `logging.channels` does not configure, one using the `database` driver on the storage connection or, in outbox
  mode, on the outbox connection, however deep in a `stack`, `failure.mode` set to `throw` in sync mode with no durable
  store, and in outbox mode a table that does not have the shipped shape. `[spill]` is a note and changes no exit code,
  because every default install has a channel that is not the documented one.

## Spill Channel

A spill line goes to `failure.log_channel`, or to the default channel when that is empty. This channel is the documented
one, a dedicated file:

```php
'audit-spill' => [
    'driver'         => 'single',
    'path'           => storage_path('logs/audit-spill.log'),
    'level'          => 'critical',
    'permission'     => 0600,
    'formatter'      => Monolog\Formatter\LineFormatter::class,
    'formatter_with' => ['format' => "%message%\n", 'allowInlineLineBreaks' => false],
],
```

- Replay is guaranteed only for that format, and a `daily` driver with the same formatter counts as it.
  `audit-log:check` prints `[spill] OK` for it, and for any other channel a `[spill]` warning that replaying what it
  holds is unverified and that whole records in plaintext go to it and to everything it feeds. The same format with a
  `permission` missing or open to group or others, or a file already written with such a mode, is noted too, since
  Monolog applies a permission only when it is given and only as it creates the file. - A line is written at `critical`
  past Laravel's log wrapper, so it has no shared context and no `MessageLogged` listener sees it, while the channel's
  handlers and formatter still run. Laravel's `Context` reaches a logger as `extra`, which only a format printing
  `%extra%` shows. The line is the marker `audit-log-spill:v1` and a space, then the record's canonical JSON. A carriage
  return and a line feed are escaped by that encoding, and every `%` is written as `\u0025`, because a `LineFormatter`
  rewrites a `%token%` in its output even after the message is substituted. The escape decodes to the same value, so the
  line still verifies. A line is never truncated by the package.
- Other channels can damage a line. A syslog or cloud log handler may cut it at a size limit or rewrite it, and a cut
  line is skipped and counted as `truncated`, never repaired.
- **Access.** The file holds whole records, so `permission` is `0600` and it belongs to the application's user alone. A
  stack that sends `critical` to an alerting channel sends the record there too, which is why the channel is dedicated.
- **Rotation.** A `single` file grows until something rotates it, and a `daily` channel's `days` deletes old files
  whether or not they were replayed. Replay reads one file per run, so a rotated file is replayed by its own name.
- **Retention.** Replay reads a file and never edits or deletes it. Delete a file once a replay of it exits zero and it
  has passed the retention the application sets for personal data. A file holding skipped lines is a quarantine, kept
  for as long as someone may restore their key.

## Claims And Receipts

- A drain reads the ids of the rows due, then claims each with one conditional `UPDATE`, whose predicates are that
  `failed_at` is null, `available_at` is due and the lease is unset or expired. Of two drains racing for a row exactly
  one wins, on every engine and without `SKIP LOCKED`.
- Each claim writes its own token to `claimed_by`, and every later change to the row, a renewal, a retry, a failure or
  the delete, requires that token. A worker whose lease expired and whose row has a new owner changes nothing, and it
  writes nothing further, not even the receipt of a call that succeeded. The new owner repeats the call.
- The lease is renewed before each destination call and each receipt, and not during a call, so a destination call must
  finish within `delivery.outbox.lease_seconds`: set a destination's timeout below it. Leases are judged by each
  worker's clock, so worker clocks must agree to well within the lease.
- Delivery is at-least-once, and the fence narrows that without removing it. The database store's idempotency makes a
  repeated call a no-op, comparing captured content, and a log destination writes its line again.
- Delivery order is not guaranteed: rows retry on their own schedules, and two drains may run at once.
- One receipt per entry and destination is kept in `delivery.deliveries_table`, on the storage connection. A single
  store is the destination `store`, and a stack's destinations go under their ids, which match
  `StackAuditStore::DESTINATION_PATTERN` and must stay stable: a renamed destination is a new one and is called again.
- The order is fixed for a crash at any point: the attempt is counted before the call, each successful receipt persists
  before the row is deleted, and the row goes only once every destination has the record. A destination that joins a
  transaction on the storage connection shares one with its receipt, so its entry and its receipt commit or roll back
  together. A retry skips a destination whose receipt says it has the record.
- A destination removed from the stack stops blocking its rows, and a receipt it left undelivered is reported once as
  the row completes.
- A receipt says what the package called: a successful call to a remote destination is not proof that it ingested the
  record. It holds the attempts, the times and the last error's class, and nothing of the record.
- Receipts are kept. The drain never deletes one, and a later replay relies on them, so they outlive their rows. They
  are pruned with their entries once terminal: `audit-log:prune` keeps an entry while it has an outbox row or a receipt
  not yet delivered, read after the prune's lock, and deletes an entry's receipts with it once every one is delivered.
- Every row a drain claims is checked against the tombstones (`Lifecycle\PruneTombstones`) once its record is read: an
  id a seal holds as a member whose entry is no longer stored, and whose position a valid prune record of the seal sets,
  was pruned by retention; an absent member no valid record covers was removed some other way, and its row is delivered,
  so the store keeps the authentic row again. A pruned row is deleted and counted `pruned`, no destination is called and
  no `AuditRecorded` is dispatched, so a pruned record is never stored again. The check is one indexed statement per
  row, since a row requeued by `audit-log:replay --outbox` starts its attempts again and may hold a record stored,
  sealed and pruned since. A row whose tombstones cannot be read is retried as any failure is.

## Replay

`audit-log:replay` takes `--spill=<path>`, `--outbox` or both, the spill first, and `--dry-run`, which changes nothing
and dispatches nothing. Output is counts by outcome, then line numbers, ids and classes, and never a value. It exits
non-zero when anything was skipped or failed.

- A spill line is replayed only when it verifies, so anyone able to edit the log cannot inject a record. The id, the
  envelope and the provenance are kept and a record is never re-signed, so replaying twice adds nothing.
- A line without the marker is ignored and not counted, since a shared channel holds other lines. The reader is bounded
  and extracts one JSON value after the first marker, whatever prefix or suffix a channel's format adds.
- Each envelope it cannot use is counted under one of these stored values (`Records\Enums\EnvelopeFailure`), and a
  spill line stays in its file:

  | Value                 | What it means                                 | What can be done                  |
  |-----------------------|-----------------------------------------------|-----------------------------------|
  | `signature_mismatch`  | The content is not what was signed            | Nothing: it stays quarantined     |
  | `unknown_key`         | Its signing key is not in the ring            | Restore the key, or leave it      |
  | `unsupported_version` | This release does not read its version        | Replay it on a release that does  |
  | `malformed`           | It is not a well-formed record of its version | Nothing: it stays quarantined     |
  | `truncated`           | It ends before its JSON value does            | Nothing: it is never repaired     |
  | `unsigned`            | It failed before it was finalised             | Nothing here: see below           |
  | `id_mismatch`         | An outbox row holds another record's envelope | Only an outbox row can raise this |
  | `oversize`            | It is larger than any record can be           | Nothing: it is never parsed       |

- A removed signing key means the record is unverifiable: restore the key or leave the record quarantined. It is never
  re-signed, because a new signature would vouch for bytes nobody can now check.
- An unsigned line is counted and left, and there is no option to replay one, because signing editable bytes cannot
  establish where they came from. The importer, `audit-log:import`, takes third-party evidence, marked as asserted by
  its source: it refuses this installation's own source, so its own records come back through a replay, never as an
  import. An imported row is signed and sealed here as this installation's acceptance of what the source asserted; it
  is never dispatched as `AuditRecorded` and never delivered to a destination.
- A spill replay checks every line's id against the tombstones before the store, and a dry run does too: a record
  retention pruned is counted `pruned` and never stored again. Outside a dry run the check and the store run in one
  lifecycle transaction, behind the lock every prune takes first, so a prune never deletes the record between its check
  and its insert, and the replay needs the maintenance connection a prune needs. An outbox replay's rows are checked by
  the drain, whose outbox row keeps its entry from any prune until it is drained.
- The store's conflict path checks the id it could not insert: a unique violation under the id of a pruned record is
  `RecordConflictException::alreadyPruned()`, never the raw exception. A fresh insert of a pruned id violates no index,
  so a record an application stores again by hand through `AuditStore::store()` is not refused: the drain and the spill
  replay are the paths that hand the store an id it did not mint now, and they check it. Verification reports such a
  record `resurrected`, so it is detected, not prevented.
- `--outbox` resets the receipts of the destinations without the record, then requeues the failed rows, then drains. A
  crash between the two leaves the rows failed and a rerun is safe, and a crash after the requeue leaves them due, for
  any drain. Delivered receipts are kept, so a replay reaches only what failed, and the drain also takes any other row
  that is due.
- A spill replay goes straight to the store, so a failure is counted by id and class and raises no `AuditWriteFailed`. A
  stored record dispatches `AuditRecorded`, again for a line replayed twice.

## Stores And Capabilities

`Contracts\DurableAuditStore` extends `AuditStore` with two separate questions, since a durable remote store cannot be
atomic with local data, and a store that joins a transaction is durable only once it commits.
`Contracts\AcceptsAttachments` asks a third, whether the store keeps a record's attachment with its entry:

| Store                | `isDurable()` | `participatesIn()`               | `acceptsAttachments()`           |
|----------------------|---------------|----------------------------------|----------------------------------|
| `DatabaseAuditStore` | yes           | its storage connection           | yes                              |
| `StackAuditStore`    | as its first  | only when every destination does | only when every destination does |
| `LogAuditStore`      | no            | no                               | no                               |
| `NullAuditStore`     | no            | no                               | yes                              |
| `FakeAuditStore`     | yes           | any connection                   | yes                              |
| Without the contract | no            | no                               | no                               |

```php
$this->app->singleton(AuditStore::class, static fn ($app): AuditStore => new StackAuditStore([
    'database' => $app->make(DatabaseAuditStore::class),
    'siem'     => new LogAuditStore($app->make(LogManager::class), new CefFormatter, 'siem'),
]));
```

- `failClosed()` needs durability and `transactional()` needs participation, or it is a `\LogicException`. In outbox
  mode the row acknowledges for them, so the store is not asked.
- A read of the trail needs, in sync mode, a store that says it is durable and keeps attachments, since every read's
  record carries one, so the read gate refuses any other before anything is queried. In outbox mode the committed row
  is the acknowledgement, and the store is asked whether it keeps attachments only when a drain delivers the row.
- A stack is durable when its first destination is, and joins a transaction only when every destination does. A stack of
  the database and a log would write its line for a business change that may then roll back, so such a stack is refused
  for `transactional()` in sync mode, and the outbox is the remedy.
- A stack tries every destination in order. One that fails stops none of the others and undoes nothing. In sync mode a
  single `StackDeliveryException` names each one that failed, once all are tried, and it follows the failure policy.
- In outbox mode a failing destination is tracked on its receipt and reported at its final attempt, and a retry reaches
  only the destinations without the record.
- In sync mode there are no receipts, so a replay can repeat a log destination's line.
- `LogAuditStore` writes one line per record at `info`: the marker `audit-log:v1` and a space, then its formatter's
  output with any carriage return, line feed or Unicode line or paragraph separator escaped. The marker is there because
  Monolog's `LineFormatter` turns escaped line breaks back into real ones in a message starting with `{` or `[`.
- A `LineFormatter` substitutes `%context%`, `%extra%`, `%channel%` and its other tokens inside a message after placing
  it, with no escaping for CEF or JSON, so a value holding one could import the log context, a field or a whole physical
  line. So the store writes past Laravel's log wrapper, where no shared context joins the line and no `MessageLogged`
  listener receives it, and writes the `%` that opens each such token as `%25`. A `%` that opens nothing is left alone.
  The log store's line is a projection, not the integrity artefact. The stored row, with its HMAC, is the evidence.
- `NullAuditStore` writes nothing, so a return from it means nothing was kept, and it accepts attachments because it
  keeps nothing of any record, so no part of one is lost selectively. `LogAuditStore` accepts none, because its line
  would lose the members.
- A store of the application's own should implement `DurableAuditStore`, answer from its configuration and never from
  the record, and keep no state between calls.

## Captures And Bundles

A record captured from an event, by a mapper, by Laravel's authentication events, by a Gate denial or by a watched
model, is written through the same delivery as any other, with one difference: its failures go back to the capture.

- The capture hands the delivery a `Delivery\CaptureSignal`. The record is written now, or after commit for a watched
  model's change, never fail-closed or transactional: a capture asking for either is a `\LogicException` before
  anything is consumed. A capture never reads `failure.mode`, so a malformed mode never stops one, and its rule is
  always `REPORT`.
- A failed write is handled once by `Delivery\FailureHandler`, spilled, reported and said as `AuditWriteFailed`, then
  the signal is told once, and the capture dispatches `AuditCaptureFailed`. A later failure of the same write changes
  nothing.
- The signal is marked deferred before a write is queued for a commit, so the failure path knows the capture has
  returned. A deferred capture's failure, a host-fatal one included, is reported and signalled when the commit runs the
  write, and its record is spilled even when the failure ended a transaction still open on the storage connection,
  since the work it records has committed. Whatever the write lets out, nothing leaves its commit callback: beyond the
  failure path it is reported as a `Stores\AuditWriteFailedException` by its class alone, inside the write guard, and
  signalled.
- A synchronous capture's deadlock or lost connection inside a transaction open on its connection is thrown sanitised,
  as any record's is, and the signal is told it was fatal.
- In outbox mode the signal travels with the insert. A watched model's change whose transaction is on the outbox
  connection is inserted inside it, and one whose transaction is on another connection waits for that commit, marked
  deferred.

A record with an artifact carries a `Records\Attachment`, the artifact descriptor and the members sealed once with
`encryptString()`, and travels as one bundle. The artifact is a bulk operation's members, kind `bulk`, a read's
`disclosure` or an export's `export` manifest (`Records\Enums\ArtifactKind`):

- The envelope of a record with an attachment is a bundle of three keys, through the canonical encoding:
  `bundle_version` (`EnvelopeCodec::BUNDLE_VERSION`, 1), `record`, the record's 36 columns, and `attachment`, its `id`,
  `entry_id`, `kind`, `member_count`, `digest` and sealed `members`. A record without one keeps its plain envelope.
- `EnvelopeCodec::MAX_BYTES` applies to the whole bundle, so a bundle over it is `oversize` like any record. A bundle
  version this release does not read is `unsupported_version`, and one with another key, or an attachment the signed
  descriptor does not describe or that names another entry, is `malformed`.
- The attachment is not signed itself. The record signs `properties._audit.manifest`, its `artifact_id`, `kind`,
  `digest` and `count`, and the descriptor binds the attachment, so a plain envelope whose properties hold a descriptor
  never becomes a record that lost its members.
- The outbox row and the spill line hold the whole bundle. A drain asks each destination whether it keeps attachments
  before calling it: one that keeps none is refused, as that destination's failure, its attempt counted, so the others
  are still tried and the row is retried, then failed and kept, never deleted. A destination's receipt is marked
  delivered only once it stored both.
- A replay asks the bound store first, and a bundle it would lose is counted failed and stays in the file. A bundle
  stored already is a no-op.
- In sync mode a store that keeps no attachments refuses the bundle inside the attempt, with a `\LogicException` that
  follows the record's rule, so the spill keeps the whole bundle. `bulk()` refuses up front, so that is reached only
  when the binding changed in between.
- `DatabaseAuditStore` writes the artifact and the entry in one transaction, a savepoint inside a host's, and compares
  a duplicate by the artifact's `id`, `entry_id`, `kind`, `member_count` and `digest`, never its ciphertext; the
  members are sealed once, so a retry, a drain and a replay carry the same bytes.

## Formatters

A `Contracts\AuditFormatter` turns a finalised record into one deterministic line. `LogAuditStore` uses one, and nothing
else does yet. A projection is never the integrity artefact.

- `Export\NdjsonFormatter` is the canonical JSON envelope, with its HMAC.
- `Export\OcsfFormatter` writes one event of OCSF `1.9.0` (`OcsfFormatter::VERSION`), in canonical JSON. A code is
  classified only by the class-string of `Contracts\OcsfMapper` that its definition names with
  `EventDefinition::ocsf()`.
- Every OCSF event has the fixed base attributes:
  - `time`, when the activity occurred, in epoch milliseconds
  - `severity_id` and `severity`: 1 Informational for a success, 3 Medium for a failure, 4 High for a denial
  - `status_id` and `status`, with the outcome and reason in `status_detail` and the reason in `status_code`
  - `message`, the code, and `type_uid`, which is `class_uid * 100 + activity_id`
  - `metadata`, with the record's id in `uid`, the code in `event_code`, `version`, `product`, `original_time`,
    `logged_time`, and `correlation_uid` and `tenant_uid` when the record has them
- A mapping applies only to records of its definition's version, because a mapper was written against that payload.
- Any other record falls back to a Base Event: `class_uid` 0, `category_uid` 0 and `activity_id` 0, with `type_name`
  `Base Event: Unknown`, and an `unmapped` attribute holding every column with a value that is carried nowhere else. A
  classification is never invented.
- A mapper returns the integers `class_uid`, `category_uid` and `activity_id`, with the class in that category, and the
  class's own attributes. One that returns any of `metadata`, `time`, `severity_id`, `type_uid` or `type_name`, which
  the formatter sets, is refused with an `\UnexpectedValueException` naming its class and the attribute.
- `hmac`, `key_id` and `integrity_version` are left out of an OCSF event.
- `Export\CefFormatter` writes CEF version 0, with the severity 3 for a success, 6 for a failure and 7 for a denial:

  ```text
  CEF:0|Sine Macula|laravel-audit-log|<record_version>|<event>|<event>|<severity>|<extension>
  ```

- The CEF extension holds, in order and each only when the record has it, `externalId` (the id), `rt` (epoch
  milliseconds), `act` (the code), `outcome`, `src` (only when the column holds an address and not a hash), and
  `requestClientApplication`, then the actor, the subject and the tenant as `<type>:<id>` in `cs1`, `cs2` and `cs3`,
  each labelled by its `cs1Label`, `cs2Label` or `cs3Label`.
- CEF escapes `\` and `|` in the header, where a line break or a Unicode line or paragraph separator becomes one space,
  and `\`, `=`, carriage return and line feed in the extension, where either separator is written as `\n`, then cleans
  every other control character, so no value can end the line or forge a field, for a reader that honours Unicode line
  ends too.

## Implementation Anchors

- `src/Delivery/RecordDelivery.php`: `check()`, `deliver()`; `src/Delivery/OutboxWriter.php`: `write()`.
- `src/Delivery/Outbox.php`: `candidates()`, `claim()`, `renew()`, `retry()`, `fail()`, `delete()`, `requeueFailed()`;
  `src/Delivery/OutboxClaim.php`.
- `src/Delivery/Receipts.php`: `attempting()`, `delivered()`, `failed()`, `resetFailed()`; `src/Delivery/Receipt.php`.
- `src/Delivery/OutboxDrainer.php`: `drain()`, `MAX_BACKOFF_SECONDS`; `src/Delivery/DeliveryCoordinator.php`:
  `deliver()`, `STORE_DESTINATION`; `src/Delivery/DeliveryResult.php`: `failure()`; `src/Console/DrainCommand.php`.
- `src/Delivery/CommitQueue.php`: `defer()`, `reserve()`, `probe()`; `src/Delivery/CommitFlush.php`: `run()`.
- `src/Delivery/Replayer.php`: `spill()`, `outbox()`; `src/Delivery/SpillReader.php`: `lines()`, `extract()`;
  `src/Delivery/SpillLine.php`, `src/Delivery/ReplayResult.php`: `pruned()`, `src/Console/ReplayCommand.php`.
- `src/Lifecycle/PruneTombstones.php`; `src/Delivery/DrainResult.php`: `pruned()`;
  `src/Stores/RecordConflictException.php`: `alreadyPruned()`; `src/Lifecycle/PendingDeliveries.php`;
  `src/Lifecycle/AuditImporter.php`.
- `src/Records/EnvelopeCodec.php`: `encode()`, `decode()`, `MAX_BYTES`, `MAX_ENCODED_BYTES`;
  `src/Records/EnvelopeRejectedException.php`, `src/Records/Enums/EnvelopeFailure.php`.
- `src/Stores/FailureSpill.php`: `MARKER`, `line()`; `src/Stores/FailureSettings.php`,
  `src/Delivery/DeliverySettings.php`.
- `src/Stores/Enums/FailureMode.php`, `src/Delivery/Enums/DeliveryMode.php`, `src/Stores/Enums/FailedOperation.php`.
- `src/Contracts/DurableAuditStore.php`: `isDurable()`, `participatesIn()`; `src/Delivery/StoreCapabilities.php`.
- `src/Contracts/AcceptsAttachments.php`: `acceptsAttachments()`; `src/Records/Attachment.php`;
  `src/Records/EnvelopeCodec.php`: `BUNDLE_VERSION`, `SUPPORTED_BUNDLE_VERSIONS`.
- `src/Delivery/CaptureSignal.php`: `defer()`, `fail()`, `isFatal()`; `src/Capture/CaptureCoordinator.php`.
- `src/Delivery/PackageWrite.php`; `src/RecordPipeline.php`: `write()`; `src/Querying/Enums/Acknowledgement.php`;
  `src/Records/Enums/ArtifactKind.php`.
- `src/Stores/LogAuditStore.php`: `MARKER`; `src/Stores/DirectLog.php`: `channel()`; `src/Stores/NullAuditStore.php`;
  `src/Stores/StackAuditStore.php`: `DESTINATION_PATTERN`; `src/Stores/StackDeliveryException.php`.
- `src/Contracts/AuditFormatter.php`: `format()`; `src/Contracts/OcsfMapper.php`: `map()`;
  `src/Definitions/EventDefinition.php`: `ocsf()`.
- `src/Export/NdjsonFormatter.php`; `src/Export/OcsfFormatter.php`: `VERSION`, `RESERVED`, `CLASSIFICATION`;
  `src/Export/CefFormatter.php`: `SEVERITIES`.
- `src/Console/DeliveryChecks.php`: `problems()`, `spillNote()`; `config/audit-log.php`: `failure`, `delivery`.

## Authoritative Tests

- `tests/Feature/RecordPipelineTest.php` `testAReservedCodeWithoutAPackageWriteIsRefused`,
  `testAPackageWriteOfAnotherCodeIsRefused`, `testARefusingAcceptDeliversNothing`,
  `testAPackageWriteMustBeFailClosedAndImmediate`
- `tests/Feature/Delivery/RecordDeliveryTest.php` `testAPackageWriteIsGivenItsFinalisedRecord`,
  `testAPackageWriteIsAcknowledgedBeforeItsNotification`
- `tests/Feature/Delivery/OutboxWriterTest.php` `testAPackageWriteIsGivenItsFinalisedRecordOnceInserted`
- `tests/Feature/Querying/ExporterTest.php` `testInOutboxModeTheJournalIsAccepted`
- `tests/Feature/Delivery/ReplayerTest.php` `testSpillThenReplayGivesOneRowEqualToTheSpilledBytes`,
  `testReplayingTwiceAddsNothing`, `testAChannelPrefixedLineParses`, `testKeepsIdEnvelopeAndProvenance`,
  `testATamperedLineIsSkippedAndCounted`, `testAnUnsignedLineIsSkippedAndCounted`,
  `testAMalformedLineIsSkippedAndCounted`, `testAnUnknownKeyIsSkippedAndCounted`,
  `testAnUnsupportedVersionIsSkippedAndCounted`, `testATruncatedLineIsSkippedAndCounted`,
  `testEachOutcomeIsCountedApart`, `testAStoreFailureIsCountedByIdAndClass`, `testNeverResigns`,
  `testNeverFinalisesAgain`, `testAuditRecordedFollowsAReplay`, `testRequeuesAndDrainsFailedRows`,
  `testClearsFailedAtAndAttempts`, `testKeepsSuccessfulReceipts`, `testResetsOnlyFailedReceipts`,
  `testAReplayReachesOnlyTheFailedDestination`, `testAnUndecryptableRowFailsAgainAndIsKept`,
  `testADryRunChangesNothing`, `testADryRunCountsWhatItWouldDo`
- `tests/Feature/Delivery/SpillReaderTest.php` `testIgnoresUnmarkedLines`, `testExtractsFromAChannelPrefixedLine`,
  `testExtractsFromALineWithAChannelSuffix`, `testExtractsExactlyOneValue`, `testATruncatedLineIsTruncated`,
  `testAnOverlongLineIsTruncatedWithoutBeingHeld`, `testAShortLineCostsMemoryForItsOwnLengthOnly`
- `tests/Feature/Console/ReplayCommandTest.php` `testNeitherOptionIsInvalid`, `testAllowUnsignedIsNoOption`,
  `testPrintsCountsAndIds`, `testPrintsNoPayload`, `testAHostileIdIsNotPrinted`, `testASkippedLineExitsNonZero`,
  `testAFailedStoreExitsNonZero`, `testACleanRunExitsZero`, `testBothOptionsRun`, `testAMissingFileExitsNonZero`
- `tests/Feature/Delivery/OutboxWriterTest.php` `testNoTransactionInsertsNow`, `testImmediatelyInsertsNow`,
  `testTransactionalInsertsNow`, `testAfterCommitOnTheOutboxConnectionInsertsInsideIt`,
  `testAfterCommitOnAnotherConnectionWaitsForItsCommit`, `testASelectorMatchesItsConnection`,
  `testThePayloadIsEncryptedAsAString`, `testTheOutboxIdEqualsTheEnvelopeId`, `testFinalisesOnce`,
  `testDispatchesNoAuditRecorded`, `testCallsNoStore`, `testAFailedInsertFollowsTheReportRule`,
  `testAFailedInsertInTheSelectedTransactionBindsItsSpillToTheCommit`, `testARolledBackHostDiscardsTheSpill`,
  `testDiagnosticsGoOutAtOnce`, `testAFailedFinaliseOnThisPathFailsBeforeTheCommit`,
  `testAFailedTransactionalInsertNeverSpills`
- `tests/Integration/Delivery/OutboxTransactionsTest.php` `testAnOutboxRowCommitsWithTheHost`,
  `testAnOuterRollbackRemovesTheRow`, `testAnInnerRollbackRemovesTheRow`,
  `testAFailedInsertLeavesAHealthyHostCommitting`, `testAFailedInsertKeepsTheHostsCallbacks`,
  `testAnImmediateRowRollsBackWithAnEnclosingTransaction`, `testADedicatedOutboxConnectionIgnoresTheHostsRollback`,
  `testInterleavedTransactionsOnTwoConnections`, `testInsideOnlyTheWrapperIsInsertedNow`,
  `testABoundSpillRunsAtTheNestedCommit`
- `tests/Integration/Delivery/DrainCrashBoundariesTest.php` `testACrashAtEveryBoundaryRecovers`,
  `testAttemptsCountTheCrashedAttempt`, `testASuccessfulReceiptPrecedesTheDelete`,
  `testADeliveredReceiptIsNeverDeletedWithTheRow`, `testNoCrashLosesARecord`,
  `testARecordKillingItsWorkerIsAbandonedAtItsAttempts`
- `tests/Integration/Delivery/DrainConcurrencyTest.php` `testOneOwnerBeforeExpiry`,
  `testAConditionalUpdateHasOneWinner`, `testAnExpiredLeaseIsReclaimed`, `testAFirstWorkerAliveOnItsLeaseKeepsTheRow`,
  `testAFirstWorkerAlivePastItsLeaseIsRejected`, `testIdempotentRecoveryAfterExpiry`, `testConcurrentRetriesStoreOnce`,
  `testADestinationSlowerThanTheLeaseIsRenewedBetweenDestinations`
- `tests/Feature/Delivery/OutboxDrainerTest.php` `testAStorageOutageBacksOffAndIsReportedOnceAtTheLastAttempt`,
  `testARowThatCannotBeWorkedIsReportedAndRetriedAndStopsNoOther`, `testAFailedClaimIsReportedAndStopsNoOther`,
  `testAFailureRetriesWithBackoff`, `testTheBackoffDoublesAndIsCapped`,
  `testATransientFailureIsNotReported`, `testTheFinalAttemptFailsTheRowAndKeepsIt`, `testAFailedRowIsNotClaimedAgain`,
  `testARowThatCrashedPastItsAttemptsIsAbandoned`, `testAnUndecryptablePayloadIsFailedAndKept`,
  `testARetiredKeyStillInPreviousKeysDecrypts`, `testATamperedEnvelopeIsFailedAndKept`,
  `testAnIdMismatchIsFailedAndKept`, `testUntilEmptyEndsWhileRowsArrive`, `testRefusesToRunInsideATransaction`
- `tests/Feature/Delivery/DeliveryCoordinatorTest.php` `testAttemptsAreRecordedBeforeInvocation`,
  `testARetryReachesOnlyTheFailedDestination`, `testADatabaseDestinationSharesATransactionWithItsReceipt`,
  `testADestinationThatDisappearedStopsBlocking`, `testADestinationThatDisappearedIsReportedOnce`,
  `testARenewalPrecedesEachDestination`, `testALostClaimAfterADestinationWritesNoReceipt`
- `tests/Feature/Console/DrainCommandTest.php` `testWhatStopsTheRunIsReported`,
  `testTheTallyOfRowsAlreadyWorkedIsPrintedWhenTheRunStops`, `testNothingIsScheduled`, `testDispatchesNoJob`,
  `testAFailedRowExitsNonZero`, `testTheDefaultLimitIsOneHundred`
- `tests/Integration/Delivery/FailedJobsTest.php` `testAPermanentlyFailingDestinationLeavesAReceipt`,
  `testNoPayloadIsInFailedJobs`, `testADrainDispatchesNoJob`, `testAThrownFailureInsideAJobLeavesNoSecretInFailedJobs`
- `tests/Integration/Delivery/SpillReplayEnginesTest.php` `testASpilledRecordReplaysToOneRow`,
  `testReplayingTwiceAddsNothing`, `testTheRowEqualsTheSpilledValues`, `testAReplayedRowVerifies`,
  `testAHostileRecordRoundTrips`, `testATamperedLineIsSkipped`, `testADocumentedChannelFileReplays`,
  `testAFullSizeLineRoundTripsThroughTheDocumentedChannel`
- `tests/Integration/Delivery/EnvelopeSizeBoundTest.php` `testTheConfiguredMaximumSurvivesEncryptionAndTheEngine`,
  `testTheEncryptedMaximumFitsTheColumn`, `testTheMaximumFitsMySqlsPacket`,
  `testAnEnvelopeOverTheBoundFollowsThePolicy`, `testTheBoundCoversEveryColumnAtItsLongest`
- `tests/Integration/Delivery/ReplayOutboxEnginesTest.php` `testAFailedRowReplaysToOneEntry`,
  `testAReplayKeepsDeliveredReceipts`, `testARestoredPreviousKeyDecrypts`
- `tests/Integration/Delivery/FailurePolicyEnginesTest.php` `testATransactionalFailureRollsBackTheBusinessChange`,
  `testATransactionalFailureSpillsNothing`, `testATransactionalFailureEmitsSafeDiagnostics`,
  `testRollbackAfterAFailedInsertLeavesNoReplayableSpill`, `testCommitAfterAFailedInsertLeavesOneReplayableSpill`,
  `testFailClosedSurvivesItsDedicatedConnection`, `testRollingBackAnEnclosingTransactionRemovesAFailClosedRow`,
  `testAnAbortedPostgresHostIsReportedAndSpilled`, `testASpillOnTheAbortedDatabaseIsWhatCheckFlags`,
  `testTheInsertReachesTheWriter`
- `tests/Integration/Delivery/HostFatalFailuresTest.php` `testADeadlockInsideAHostPropagatesInReportMode`,
  `testTheHostsTransactionRetryStillWorks`, `testTheSanitisedExceptionHoldsNoBinding`,
  `testALostConnectionInsideAHostPropagatesInReportMode`, `testAStackOfADeadlockingDatabasePropagates`,
  `testAnOutboxInsertDeadlockPropagates`, `testOnMySqlARealDeadlockRetries`,
  `testOnPostgresARealDeadlockPropagatesSanitised`
- `tests/Integration/Delivery/ProcessDeathTest.php` `testAProcessKilledAfterCommitThenADrainGivesOneRow`,
  `testARolledBackTransactionGivesNoRow`, `testAProcessKilledBeforeCommitGivesNoRow`,
  `testATransactionalRowSurvivesAKillAfterCommit`, `testTheRowDrainsToTheSameBytes`,
  `testAKilledDrainLeavesTheRowForALaterOne`, `testASyncRecordIsLostWhenTheProcessDiesBetweenCommitAndWrite`
- `tests/Feature/Stores/FailureSpillTest.php` `testNoListenerAndNoSharedContextReachTheLine`,
  `testTheLineIsTheMarkerAndTheCanonicalEnvelope`, `testEscapesCrAndLf`,
  `testNeverTruncates`, `testAPercentTokenSurvivesTheDocumentedChannel`, `testADocumentedChannelWritesOnePhysicalLine`
- `tests/Feature/Console/DeliveryChecksTest.php` `testADatabaseChannelOnTheOutboxConnectionIsAProblem`,
  `testADocumentedChannelWithNoPermissionIsNoted`, `testAPermissionThatLetsOthersInIsNoted`,
  `testAnExistingFileWithALooserPermissionIsNoted`, `testADatabaseChannelOnTheStorageConnectionIsAProblem`,
  `testADatabaseMemberOfAStackIsAProblem`, `testThrowModeWithNoDurableStoreIsAProblem`,
  `testTheDocumentedChannelHasNoNote`, `testADailyChannelCanBeDocumented`, `testEachOtherChannelIsNoted`
- `tests/Unit/Stores/StackAuditStoreTest.php` `testAFailingSecondDestinationKeepsTheFirst`,
  `testThrowsOneExceptionAfterAttemptingAll`, `testRefusesABadDestinationId`,
  `testAsksItsFirstDestinationIfItIsDurable`, `testParticipatesOnlyWhenEveryDestinationDoes`
- `tests/Integration/Delivery/ReplayCrashBoundariesTest.php` `testAKillLeavesWhatItsBoundarySays`,
  `testASecondReplayRecovers`, `testADrainRecoversAKillAfterTheRequeue`
- `tests/Feature/Stores/LogAuditStoreTest.php` `testNeitherAHostileValueNorTheSharedContextForgesALine`,
  `testATokenCannotBreakAnNdjsonLine`, `testEveryTokenIsDefused`, `testNoListenerAndNoSharedContextReachTheLine`,
  `testPrefixesTheMarker`, `testAMarkedLineIsNotReexpandedByMonolog`,
  `testARetriedRecordIsWrittenAgain`, `testIsNotDurable`, `testParticipatesInNothing`
- `tests/Unit/Stores/NullAuditStoreTest.php` `testStoresNothingAndSucceeds`, `testIsNotDurable`
- `tests/Feature/Delivery/StoreCapabilitiesTest.php` `testAStoreWithoutTheInterfaceIsNeither`,
  `testTheDefaultStoreIsDurableOnTheStorageConnection`
- `tests/Unit/Export/NdjsonFormatterTest.php` `testIsTheCanonicalEnvelope`, `testRepeatsByteForByte`
- `tests/Feature/Export/OcsfFormatterTest.php` `testAnUnmappedCodeIsNeverClassified`,
  `testABaseEventValidatesAgainstThePinnedSchema`, `testAMappedEventValidatesAgainstThePinnedSchema`,
  `testAMappingAppliesOnlyToItsVersion`, `testTheMetadataIsPinned`, `testTheIntegrityFieldsAreLeftOut`,
  `testRefusesAMapperReturningAReservedKey`
- `tests/Unit/Export/CefFormatterTest.php` `testTheHeaderIsPinned`, `testTheExtensionIsPinnedInOrder`,
  `testTheSeverityFollowsTheOutcome`, `testEscapesEachHeaderSeparator`, `testEscapesEachExtensionSeparator`,
  `testAValueCannotForgeAnExtension`
- `tests/Feature/Delivery/RecordDeliveryTest.php` `testACaptureIsRefusedFailClosed`,
  `testACaptureIsRefusedTransactional`, `testACaptureFollowsTheReportRuleUnderTheThrowMode`,
  `testACaptureIgnoresAMalformedFailureMode`, `testACapturesWriteFailureIsSignalledOnce`,
  `testADeferredCaptureIsMarkedBeforeItIsQueued`, `testADeferredCapturesFailureIsSignalledAtCommit`,
  `testADeferredCaptureNeverThrowsFromTheCommit`, `testADeliveredBundleToAStoreKeepingNoAttachmentsFollowsTheRule`,
  `testABundleReachesAStoreThatKeepsAttachments`
- `tests/Unit/Delivery/CaptureSignalTest.php` `testTheFailureIsPassedOnOnce`, `testAThrowingCallbackIsContained`,
  `testDeferralIsKept`
- `tests/Feature/Capture/CaptureCoordinatorTest.php` `testAWriteFailureIsHandledOnce`,
  `testTheThrowFailureModeIsIgnored`
- `tests/Unit/Records/EnvelopeCodecTest.php` `testTheBundleVersionsArePinned`, `testARecordWithAnAttachmentIsABundle`,
  `testABundleRoundTripsByteForByte`, `testTheGoldenBundleDecodes`, `testAnUnsupportedBundleVersionIsRefused`,
  `testAnAttachmentThatDoesNotMatchTheSignedDescriptorIsMalformed`, `testABundleOverTheBoundIsOversize`
- `tests/Feature/Stores/FailureSpillTest.php` `testASpilledBundleHoldsItsAttachment`
- `tests/Feature/Delivery/DeliveryCoordinatorTest.php` `testADestinationKeepingNoAttachmentsFailsAndTheOthersAreTried`,
  `testARecordWithoutAnAttachmentAsksNoDestination`, `testABundleReachesEachDestinationWhole`
- `tests/Feature/Delivery/OutboxDrainerTest.php` `testABundleIsDeliveredWhole`,
  `testABundleToAStoreKeepingNoAttachmentsIsKeptForRetry`
- `tests/Feature/Delivery/ReplayerTest.php` `testASpilledBundleIsReplayedWhole`,
  `testABundleToAStoreKeepingNoAttachmentsIsCountedFailed`, `testAReplayedBundleThatIsStoredAlreadyIsANoOp`
- `tests/Integration/Delivery/BundleDeliveryEnginesTest.php` `testAnOutboxBundleIsDrainedWhole`,
  `testASpilledBundleReplaysWhole`, `testTwoConcurrentReplaysOfOneBundleLeaveOneEntryAndOneArtifact`,
  `testADrainToAStoreKeepingNoAttachmentsKeepsTheRow`
- `tests/Feature/Delivery/StoreCapabilitiesTest.php` `testAStoreWithoutTheContractAcceptsNoAttachments`,
  `testAStoreThatSaysSoAcceptsAttachments`
- `tests/Unit/Stores/StackAuditStoreTest.php` `testAStackAcceptsAttachmentsOnlyWhenEveryDestinationDoes`
- `tests/Unit/Documentation/DocumentationTest.php` `testTheDocumentedChannelIsTheTestedOne`,
  `testTheSpillAndOutboxArePersonalData`
- `tests/Feature/Delivery/PrunedRedeliveryTest.php` `testTheDrainCompletesAPrunedRowAsPruned`,
  `testNoDestinationIsCalledForAPrunedRow`, `testNoAuditRecordedIsDispatchedForAPrunedRow`,
  `testARowWhoseTombstonesCannotBeReadIsRetried`, `testASpillReplayCountsAPrunedLineAndStoresNothing`,
  `testADryRunCountsAPrunedLine`, `testAnOutboxReplayOfAPrunedRowCompletesItAsPruned`,
  `testAFreshCaptureIsNeverChecked`, `testADirectStoreOfAPrunedRecordIsReportedResurrected`
- `tests/Integration/Stores/PrunedRecordConflictTest.php` `testAUniqueViolationOfAPrunedIdIsAlreadyPruned`,
  `testAFreshInsertOfAPrunedIdIsNotRefused`
- `tests/Integration/Lifecycle/PruneTombstonesTest.php` `testASealedMemberAbsentFromTheEntriesIsPruned`,
  `testAnUnsealedIdIsNot`
- `tests/Performance/DrainQueryBudgetTest.php` `testEachRowCostsOneTombstoneCheck`
- `tests/Feature/Console/DrainCommandTest.php` `testAPrunedRowIsPrintedAndExitsZero`
- `tests/Feature/Console/ReplayCommandTest.php` `testPrintsThePrunedAndExitsZero`
- `tests/Feature/Lifecycle/PendingDeliveriesTest.php` `testAnUndeliveredReceiptIsPending`, `testADeliveredReceiptIsNot`
- `tests/Feature/Lifecycle/PrunerTest.php` `testAPendingDeliverySurvivesAndIsCounted`,
  `testArtifactsAndReceiptsGoWithTheirEntries`, `testAFailedDeliveryKeepsItsEntryUntilReplayed`
- `tests/Feature/Lifecycle/AuditImporterTest.php` `testImportedRowsAreNotDispatchedOrDelivered`, `testItRefusesItsOwnSource`

## Change Triggers

Update this note when any of the following change:

- a stored value of `FailureMode`, `DeliveryMode`, `FailedOperation` or `EnvelopeFailure`
- what the outbox row holds, how it is encrypted, or the envelope's bound
- how a row is claimed, fenced or renewed, or when it is retried, failed or deleted
- what a receipt holds, when it is written, whether it is kept, or when a prune deletes it
- which paths check the tombstones, or what a pruned record is completed as
- the documented spill channel, how a line reaches it, the line's format or what the reader accepts
- what a replay verifies, what it skips or what it may change
- what a store says of itself, or how a stack answers for its destinations
- the rule a capture follows, when its signal is told, or what leaves a deferred capture's commit
- the bundle's keys or version, what the attachment holds, or who is asked whether it keeps one
- the pinned OCSF version, the base attributes, the fallback, or the CEF header or extension
- what a package write guarantees, what acknowledges it, or what accepted and delivered mean
