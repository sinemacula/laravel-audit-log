# Lifecycle

## Purpose

This note records what the package does to the log after it is written: holds, retention and pruning one entry at a
time, imports from another system, and the journalled maintenance of owners' keys (erasure, reinstatement, rewrap and
the reconciliation of a restore). Every destructive or privileged operation is journalled in a chained, signed journal
that every seal commits to, and every decision to delete is read from that verified journal inside one lock, never from
a table anyone could edit. Two guarantees are stated apart, here as everywhere. Database credentials can still destroy
rows; the package's cryptographic evidence makes unauthorised destruction detectable, never impossible. A hold, a
retention policy and the journal decide what the package itself deletes, and stop no one else. What none of this
promises is in `threat-model.md`; how a prune is verified is in `integrity.md`.

## Invariants

- Every maintenance operation, a hold, a release, each prune chunk and each prune run's start and finish rows, an
  import's journal rows, a projection rebuild, an erasure, a reinstatement, each rewrap batch and a reconciled
  restore, is one outermost transaction on `storage.maintenance_connection`,
  through `Lifecycle\MaintenanceTransaction`. It is refused while the maintenance or the storage connection is already
  in a transaction, so it is never a savepoint of the host's and commits on its own. Nothing else writes the journal or
  the holds projection.
- The first statement of every maintenance transaction is the lock row's `UPDATE`: `lifecycle.lock_table`'s one row,
  `id` 1, seeded by its migration, set to a token of the operation id, a colon and 16 random hex characters drawn for
  each attempt, and the clock's time. The token always changes, so the update changes the row and its affected count is
  1 on every engine; a missing row is refused with a `Lifecycle\LifecycleLockException`. On MySQL `READ COMMITTED` is
  set immediately before the transaction begins; on PostgreSQL the transaction's isolation is read after the lock and
  must be `read committed`, its default. The transaction is the framework's, and the lock is a real write, so on SQLite
  it takes the database's write lock on PHP 8.3 as on 8.4, before the transaction has read anything.
- Every decision read of an operation follows the lock, inside its transaction: the journal's chain and head, the
  active holds, a prune's resume cursor and boundary, its candidates' full rows and their eligibility, the receipts and
  the outbox. Nothing read before the lock decides a deletion.
- The lock gives exclusion, not fairness. An operation waiting for it is promised no turn ahead of one that asks later,
  and nothing bounds how long it waits but the engine's lock wait.
- An attempt lost to a concurrent operation (a deadlock, a serialisation failure, a lock wait timeout, a locked SQLite
  database) is rolled back whole and made again, its work run afresh, after `random_int(0, min(1000, 20 * 2 **
  (attempt - 1)))` milliseconds, up to 3 times; the fourth loss is a `Lifecycle\LifecycleContentionException`. A lost
  connection is never retried, since its commit may have happened, and anything else propagates. The work's result is
  kept only once its transaction has committed.
- The journal is chained, signed and sealed, and written only under the lock, onto the head the operation verified
  there. A destructive decision replays the verified chain; it never reads the holds projection.
- The projection is a convenience index, never trusted: `lifecycle.holds_table` lists holds for `audit-log:holds` and
  `audit-log:check`, and a prune or a release decides from the journal alone, so a projection row deleted, inserted or
  edited by hand changes nothing either does.
- Every lifecycle operation confirms the installation first, once and never in a dry run: the installation id,
  `installation.id` in `integrity.state_table`, is ensured through the storage connection's writer and must read the
  same through the maintenance connection (`Database\InstallationIdentity`), so the operation's deletions and journal
  rows land in the database that holds the entries and the seals. The id is a UUID version 7 seeded by the migration
  that creates `integrity.state_table`, with an insert that never replaces one; a seal run or a lifecycle operation
  writes it again only when the seeded row was lost, and `audit-log:check` only reads it, reporting one that is
  missing. A mismatch is refused with a `Database\InstallationMismatchException`, before the lock, naming no value.
- The journal row commits with what it describes; the activity record follows the commit. `audit_log.pruned`,
  `audit_log.held`, `audit_log.released`, `audit_log.imported`, `audit_log.subject_erased`, `audit_log.keys_reinstated`
  and `audit_log.keys_rewrapped` are written after the lifecycle transaction commits, their evidence built by
  `Lifecycle\LifecycleRecords` and written by `Lifecycle\LifecycleRecorder`, fail-closed and immediate whatever
  `failure.mode` says. Fail-closed names the recording attempt only: a record that cannot be written never undoes the
  operation, is reported as a payload-free `Lifecycle\LifecycleRecordFailedException`, and shows as `recorded: false`
  on the result, and `audit-log:reconcile` writes it later from the journal, once per operation id. Each of the seven
  codes is category `audit`. A refusal that wrote nothing, a release of a hold that is not active, a refused erasure
  and a reinstatement of an owner who is not erased, is recorded `denied` and rethrown; an erasure or a rewrap that
  fails is recorded as a failure, with `journal_broken`, `erasure_failed` or `rewrap_failed`, a code and never the
  failure's message, and rethrown.
- Only `audit_log.trail_exported` is protected from retention (`PackageActivity::isProtected()`), and no policy can
  change that. Every other code, the package's own included, follows its category's policy.
- The package records the basis it is given and never decides legal necessity. A hold's basis, its external reference
  and its review date are what an operator asserted, journalled and signed as given; whether a hold is needed, and
  for how long, is never the package's to judge.
- The package is no write-once archive and claims no compliance. Rules that require records kept on WORM media or in
  an external compliant archive, such as SEC Rule 17a-4 and FINRA Rule 4511, or a period of them immediately available,
  such as PCI DSS requirement 10.5.1's three months of a year's audit history, are met, or not, by where an operator
  keeps the log and its exports and for how long: retention and holds here only decide what this database deletes, and
  the anchor is evidence of the seals, not an archive of the entries.
- A hold is not a blanket exemption under Article 17 for every fragment of a person. It keeps the entries its scope
  matches from the package's own pruning, for the basis it names; it is no reason to keep anything else about a data
  subject, and erasing what a hold does not need stays the controller's decision.
- Export artifacts need `app.key` kept, or listed in `app.previous_keys`, for as long as their verification is promised.
  An `audit_log.trail_exported` entry is never pruned, but its artifact's members are encrypted under `app.key`, so a
  key rotated away and then dropped leaves an export that can no longer be verified.
- `--by-type`, `--by-id` and every `Lifecycle\Authority` assert who asked and prove nothing: the package authorises no
  lifecycle operation, and the boundary is the maintenance connection's credentials and the application's own checks
  before it calls.

## Success Path

- With no retention settings nothing is pruned and `audit-log:prune` is not scheduled.
- With `retention.after_days` or `retention.categories` set, the scheduler runs `audit-log:prune` at
  `retention.schedule`. The run journals the policy's version when it is new and a `prune_run` start row, walks the
  seals oldest first, deletes each chunk of sealed entries past retention that no hold keeps and no delivery awaits,
  journals a signed prune record of exactly what each chunk deleted, journals its finish row, writes
  `retention.last_run` and records `audit_log.pruned`.
- `AuditLog::lifecycle()->hold(...)` or `audit-log:hold` journals the hold and inserts its projection row in one
  transaction, then records `audit_log.held`; every later prune keeps what it matches until
  `AuditLog::lifecycle()->release(...)` or `audit-log:release` journals its release.
- `audit-log:import` hashes its file, inserts its batch `running`, journals `import_started` (and the hold, with
  `--hold`) before its first entry, writes the lines in chunks, journals `import_finished`, and records
  `audit_log.imported`.
- `audit-log:verify` verifies the whole journal on every run, each seal's commitment to it, and every pruned member
  against the prune records the journal holds.
- `AuditLog::lifecycle()->erase(...)` or `audit-log:erase` journals the owner's erasure, tombstones the owner's keys
  and marks the owner in one transaction, then records `audit_log.subject_erased`; `reinstate()` and
  `audit-log:reinstate` journal a reinstatement and record `audit_log.keys_reinstated`; `rewrap()` and
  `audit-log:rewrap` journal each batch and record `audit_log.keys_rewrapped` once the run ends. How each decides what
  it destroys or changes is in `privacy.md`.
- After a restore, `audit-log:erase --reapply=<file>` (`AuditLifecycle::reapplyErasures()`) erases again each owner
  the file names, each as `erase()` erases and records one, in part and accepting pending deliveries, and journals
  `restore_reconciled`, naming the file's SHA-256, its counts and the anchor's head, once every owner ended `complete`
  or `already_erased` and every line named an owner.

## Failure / Edge Cases

- A broken chain (a missing, repeated or reordered row, a broken link, a row of another log, a signature or payload
  digest that fails, a key the ring does not hold, a row that cannot be read) refuses the operation with a
  `Lifecycle\JournalBrokenException` naming the finding and the row: a hold, a release and a prune each fail closed and
  change nothing. A prune so refused ends `failed` with `journal_broken` and is recorded; `audit-log:verify` reports the
  finding.
- An invalid transition is refused the same way: a release of a hold never placed or released already throws a
  `Lifecycle\UnknownHoldException`, writes nothing and is recorded `denied` with `unknown_hold`; a hold id placed twice,
  released or not, is refused.
- A seal failing authentication, its digest, signature or members digest, is skipped for the run and named, and the run
  ends `partial`; nothing of it is deleted.
- A tampered candidate, a row whose HMAC fails, whose HMAC is not the one its member was sealed with, or that is not a
  member of the authenticated seal, deletes nothing of its chunk and skips its seal for the run, so a prune never
  erases evidence of tampering.
- A refused erasure, a refused reinstatement and a dry-run rewrap write no row; a reapply whose file changed between
  its two reads, or holds more than 100,000 lines that are not blank, journals no reconciliation, and an owner it
  could not erase whole leaves the restore unreconciled, `audit-log:check` with it.
- An affected-count mismatch, a delete of entries that affects other than the rows it names, rolls the chunk back with a
  `Lifecycle\PruneMismatchException`; the chunk is retried once from a fresh read, then its seal is skipped.
- A policy exception, an answer out of range, or a custom policy retaining a category for less than it is preserved
  stops the run, which ends `failed` with `policy_failed` or `configuration_refused`; the chunks it committed stand,
  each with its record. A malformed retention setting refuses the run before it starts, and `audit-log:check` names it.
- A recording failure leaves the operation committed and its result `recorded: false`; the command warns, and
  `audit-log:reconcile`, never scheduled and run one at a time, writes the record from the journal.
- A crashed import leaves its batch `running`; `audit-log:check` notes it once it has not been written for 3600 seconds
  (`ImportSettings::STALE_SECONDS`), and `audit-log:import --close=<batch>` brings it to its end: journalled
  `interrupted` when the journal holds its start and no finish, made final with the status journalled when it holds
  its finish, and marked `interrupted` with nothing journalled when its start never committed. Its hold, placed with
  its start, stays.
- A conflicting import, a line whose source and source record id a row holds under another source digest, is counted
  and listed, never written over the row; a chunk that meets a concurrent import's row is rolled back and classified
  once more, and a second violation makes its new lines conflicts and the batch `partial`.
- A lock that waits holds its operation until the operation holding the lock commits or rolls back, or until the
  engine's lock wait times out, which is retried as a concurrency failure.
- A prune record without its deletion, a pruned record stored again by hand or restored, is `resurrected`, an
  incomplete finding: detected, not prevented.

## Journal

- `lifecycle.journal_table` (`audit_log_lifecycle` by default) holds one row per lifecycle event, in 17 columns: `id`,
  `sequence`, `log_id`, `kind`, `operation_id`, `occurred_at`, `authority_type`, `authority_id`, `reason`,
  `external_reference`, `seal_id`, `hold_id`, `payload`, `payload_digest`, `previous_hmac`, `key_id` and `hmac`. It is
  append-only: never updated and never deleted, by a prune or anything else, and the documented triggers refuse both
  with no maintenance exception.
- A row's kind is one of `Integrity\Enums\JournalKind`: `policy` (a retention policy version, the first time a run is
  under it), `prune_run` (a prune run's start and its finish), `prune` (one committed chunk, holding its prune record),
  `hold` (a hold placed), `release` (a hold released), `import_started` (an import, before its first entry),
  `import_finished` (an import's end, or its close), `erasure` (an owner's erasure: the keys it destroyed, the keys it
  kept and why, and the generation floor it set), `reinstate` (an erased owner's reinstatement, so keys may be created
  again above that floor), `rewrap` (one committed batch of a rewrap, each key's wrapping before and after) and
  `restore_reconciled` (a restored database reconciled, once every owner its erasures file names is erased again). A
  hold, a release, an import's rows, an erasure, a reinstatement, a rewrap batch and a reconciled restore name their
  authority; the others name none. The pruner replays the payloads of the policy, hold and release rows alone; no
  privacy kind's payload decides what a prune keeps.
- The chain: `sequence` runs 1, 2, 3 and so on with no gap, under a unique index; row 1's `previous_hmac` is `null` and
  every later row's is the `hmac` of the row before; every row names the log, `integrity.log_id`.
- The payload is the canonical JSON text of a map, kept as `longText` and never in a JSON column, which MySQL would
  reorder; `payload_digest` is the lower-case hex SHA-256 of that text.
- The signature: `hmac` is the lower-case hex HMAC-SHA256, under
  `hash_hkdf('sha256', $secret, 32, 'sinemacula/audit-log:lifecycle:v1', '')` of the signing ring key named by
  `key_id`, of the label `audit-log:lifecycle:<kind>:v1`, a line feed, and the SHA-256 of the canonical encoding of
  every column but `payload` and `hmac`. The payload is covered through its digest, so the chain is verified from its small
  columns, and a row signed as one kind never verifies as another.
- Every seal commits to the journal's head: `journal_sequence` and `journal_head`, the last row's sequence and HMAC,
  or both `null` for an empty journal, are fields of the signed seal envelope, read inside the seal's transaction. The
  journal is therefore anchored as the entries are, and a journal edited, deleted or cut off behind a seal, or restored
  from an older database, contradicts that seal.
- A row is appended only by `Lifecycle\Journal`, inside a maintenance transaction, after the operation verified or
  advanced its `Lifecycle\JournalReplay` in that transaction: the stored head must be the replay's head, by sequence and
  HMAC, or nothing is appended. A replay is a value, and an operation keeps only the replay a committed transaction
  returned, so a retried attempt never starts ahead of the database.
- The payload of each privacy kind: `erasure` holds `owner_fingerprint`, `fingerprint_key`, `generation_floor`,
  `partial`, `pending_accepted`, `pending_rows`, `destroyed` (each key's `key_id`, `unit` and `generation`, its
  `before`, `state`, `hmac`, `wrapped_digest` and `wrap_key_id`, and its `after`, `state` `erased`, sorted by key id),
  `kept` (each kept key's `key_id`, `unit`, `generation` and `reasons`) and `entries_affected`; `reinstate` holds
  `owner_fingerprint`, `fingerprint_key` and `generation_floor`; `rewrap` holds `run_id`, `rotate`, `keys` (each key's
  `key_id` and its `before` and `after`, `state`, `wrapped_digest` and `wrap_key_id`), `skipped`, the ids of the keys
  it could not authenticate or unwrap, each a UUID, and `skipped_unnamed`, only when some skipped key's id is not one,
  how many; and `restore_reconciled` holds `file_sha256`, `owners`, `erased`,
  `already_erased`, `anchored_sequence` and `anchored_digest`, both `null` when the anchor cannot report its head. A
  `wrapped_digest` is the lower-case hex SHA-256 of the stored wrapped key. The owner is named by a keyed fingerprint
  alone, which is personal data while it can be linked to the owner.
- A rewrap run's batches share its operation id, so `audit-log:reconcile` records the run once, summing the batches it
  finds in its window; an erasure's and a reinstatement's record are rebuilt from their one row
  (`Lifecycle\ReconciledOperations`).
- Before a destructive decision the whole chain is verified, every signature, link and transition, the payloads of the
  policy, hold and release rows checked against their digests, and the latest seal's commitment and the highest
  commitment of any seal must each name a row of the chain; a seal is never written over a journal behind the last
  seal's commitment, so commitments never run backwards. `audit-log:verify` reads every payload too, and also pairs each
  prune run's and each import's finish with its start.

## Holds

- A hold keeps the entries its `Lifecycle\HoldScope` matches from being pruned until it is released. A scope starts
  from `all()`, `tenants()` (each tenant matched by its type and id together) or `tenantless()` (the entries of no
  tenant), and is narrowed by `withTenantless()`, `about()` (actor or subject), `categories()`, `occurredBetween()` (a
  half-open window) and `importBatch()`. Its dimensions are ANDed; narrowing one again intersects it; an empty list, a
  scope that would keep nothing, and more than 100 tenants, 100 references or 50 categories are refused.
- A hold is matched in PHP over each row read, never in SQL (`HoldScope::matches()`), so any number of holds reads alike
  on every engine, and a tenant's hold never keeps an entry of no tenant unless the scope adds them. A row whose time
  cannot be read is kept by any window, so a hold never lets go of an entry it cannot place.
- A hold records its basis, one of `Lifecycle\Enums\HoldBasis`: `legal_claim`, `regulatory`, `investigation` or `other`;
  an external reference, the ticket or case, 1 to 191 clean characters; a reason code; its authority; and a review date,
  which `audit-log:check` notes once it has passed. Nothing releases a hold but a release.
- Overlapping holds each count: an entry two holds match is kept until both are released, and a release removes only
  its own hold.
- A hold id is a UUID version 7, placed once: an id the chain ever placed, active or released, is never placed again.
- The projection, `lifecycle.holds_table` (`audit_log_holds`), has one row per active hold, inserted with its `hold`
  row and deleted with its `release` row in the same transaction, and rebuilt from the verified chain under the lock by
  `AuditLog::lifecycle()->rebuildHolds()` or `audit-log:holds --rebuild`. `audit-log:check` reports drift, a hold
  missing from it, a row of no active hold, or a row unlike its hold, naming the holds; `audit-log:holds` and
  `AuditLog::lifecycle()->holds()` list the holds replayed from the verified chain, not the projection.

## Retention And Pruning

- `Contracts\RetentionPolicy` answers three questions. `version()` names the policy, 1 to 64 clean characters, and must
  change whenever an answer could. `retainFor($category, $tenant)` is the days an entry may be kept, 1 to 36500, or
  `null` for forever. `preserveFor($category, $tenant)` is the days an entry must stay readable, 1 to 36500,
  `PHP_INT_MAX` for forever, or `null` for no obligation. Deletion eligibility and preservation are separate answers,
  and a retention shorter than its preservation is refused with a `Lifecycle\RetentionConflictException`, never quietly
  lengthened.
- `Lifecycle\ConfiguredRetentionPolicy`, bound by default, reads `retention.after_days`, `retention.categories` and
  `retention.preserve`, `0` meaning forever in each, and is validated before any run, so a configured conflict prunes
  nothing at all. Its version is `config:` and the first 16 hex characters of the unkeyed SHA-256 of its canonical
  settings, so it changes with the settings and never with the keys.
- The cut-off of a run is the UTC midnight of the run's start less the pair's retention; an entry is eligible when it
  occurred strictly before it. The policy is asked once per category and tenant pair per run, and its answer is frozen
  for the rest of the run (`Lifecycle\RetentionDecisions`). A run journals its policy's version in a `policy` row the
  first time a run is under it.
- The prune unit is the entry: pruning is per entry and never per segment. An entry is eligible only when it is
  sealed, past its pair's cut-off, not under a protected code, matched by no active hold of the verified chain, and has
  no pending delivery, neither an outbox row, pending, claimed or failed, nor a receipt not yet delivered. An unsealed
  entry is never a candidate, so a run past the threshold over unsealed rows deletes nothing.
- A run plans chunks of `retention.batch` ids per seal from a read that decides nothing; each chunk, under the lock,
  reads its candidates' full rows again, verifies each, decides each again from that verified row, and deletes the
  artifacts and receipts of what is left, then the entries, `WHERE id IN`, at most 500 ids to a statement, with the
  affected count compared. On SQLite the documented delete triggers present are dropped and created again in the same
  transaction. A prune never deletes a checkpoint or a member, so every seal still verifies its members digest and its
  chain.
- Each committed chunk journals one `prune` row holding prune record version 2 (`Integrity\PruneRecord`) of its seal:
  the bitmap `pruned` sets exactly the positions of the members the chunk read, verified and deleted, members ordered
  by their canonical lower-case ids compared bytewise, bit `i % 8` of byte `i / 8`, least significant first, as strict
  base64url of exactly `ceil(member_count / 8)` bytes with zero padding bits, `pruned_count` its popcount, at least 1.
  Coverage is never issued for a member already missing. Several chunks or runs over one seal write several records,
  whose bitmaps share no member. `integrity.md` has the record's fields, its signature and how verification reads it.
- A run has a run id, which every row of the run names, and freezes its boundary: only seals sealed before it started.
  Its start row holds the policy version, the boundary sequence, the cut-off midnight and where it resumes; its finish
  row its status, one of `Lifecycle\Enums\PruneStatus` (`complete`, `partial` or `failed`), the reason a failed run
  gave, its counts, its cursor (the last seal it walked), the seals remaining, the deletions per category, the number of
  tenants it deleted from, and the distinct decisions it made, at most 1,000 of them with the count beyond and a digest
  of every pair's decision, so the row is bounded whatever the tenants and `audit-log:reconcile` writes the run's record
  exactly as the run would have.
  A run that committed its start row writes its finish row whatever happened.
- A run resumes after the last finish row's cursor only when that run stopped on its time budget before its boundary;
  after any other run the walk starts again at the first seal, so an entry a released hold or a finished delivery frees
  is reached by the next run. A start with no finish, a crashed run, is passed over. The cursor is read from the
  verified chain after the lock, never from progress. `retention.max_seconds`, or `--max-seconds`, is checked between
  chunks.
- `retention.last_run` is written by every run that is not a dry run; it is progress, never read by a prune.
  `audit_log.pruned` carries the run id, status, policy version, counts, the 50 largest categories with the rest under
  `_other`, and the number of tenants affected: never a cut-off per tenant, which only the journal holds.
- A dry run takes no lock and writes nothing: it verifies the journal read-only and counts per pair and per seal,
  counting held entries with the same `matches()` a chunk uses. It is a plan, not a promise.
- Tombstones on every re-delivery path: a seal's members and its prune records outlive its entries, so a sealed member
  whose entry is gone and whose position a valid prune record sets is a pruned record (`Lifecycle\PruneTombstones`); one
  no valid record covers was removed outside retention and is never relabelled as pruned. The outbox drain and the spill
  replay check every id they would hand the store, and the store's conflict path the id it could not insert; a pruned
  record is completed as `pruned`, never stored and never delivered again, and counted. A fresh write mints a new id and
  is never checked. The spill replay checks and stores each record behind the lifecycle lock, so no prune commits
  between the two; a drained row's outbox row keeps its entry from every prune until the drain completes it.
- A direct store of a pruned record is detected (`resurrected`), not prevented: an insert of a pruned id violates no
  index, so a record an application keeps and stores again by hand through `AuditStore::store()` is inserted, and
  verification reports the member a valid record covers that is present again as `resurrected`.

## Import

- Two formats, both versioned, are read, one of `Lifecycle\Enums\ImportFormat`: `audit-log-import/v1`, one JSON object
  per line documented field by field in the import guide, and `audit-log-export/v1`, with `--from-export`, this
  package's own NDJSON export lines from another installation, adapted by `Lifecycle\ExportLineAdapter`: a captured
  line's id is its source record id, an imported line keeps its upstream source and source record id, reserved
  `audit_log.` codes are rejected, the exporter's integrity fields, metadata and attachment are ignored, and a record
  whose source is this installation is rejected as `own_source`.
- No value shaped as an envelope is imported in either format: an object of exactly `v`, `k` and `c` at any depth of
  `properties` or `context`, and an `ip` holding one's JSON, is dropped and counted, so no source can plant a value the
  read path would take for this installation's ciphertext.
- A rejected line is counted by its reason, one of `Lifecycle\Enums\ImportRejection`, and never written.
- The local signature attests what this installation accepted, not the truth of the event. An imported row is
  this installation's acceptance of a foreign assertion: signed by this ring, sealed in this chain, marked `imported`
  with its source, never dispatched as `AuditRecorded` and never delivered to a destination. Every batch records
  `externally_verified` as `false`, since the package verified nothing at the source.
- Each imported row keeps `source_digest`, the lower-case hex HMAC-SHA256 of the canonical source assertion (code,
  occurred at, outcome, references, reason, correlation id, properties, context, origin and ip as given), taken before
  minimisation or encryption under `hash_hkdf('sha256', $secret, 32, 'sinemacula/audit-log:source-digest:v1', '')`
  of the ring key that signs the row; the column is covered by the row's HMAC. A line whose source and source record
  id a row already holds is a duplicate when the digests are equal and a conflict when they differ, within one chunk
  too, and a changed event definition changes neither.
- The guarantee holds while the earlier row survives: a re-import after a prune creates new rows, since nothing of the
  pruned row is left to compare with.
- The file's SHA-256 is read whole before the first entry and again while it is imported; a file that changed between
  the two reads fails the batch. An imported row's id is a UUID version 7 drawn at import, and its `recorded_at` is the
  later of the clock and `occurred_at`; an `occurred_at` more than `import.max_skew_seconds` ahead is rejected.
- Entries and the batch row are written on the storage connection's writer; the journal rows and the hold through the
  maintenance connection. The lines are written in chunks of `import.chunk`, each one storage transaction with the
  batch's counts, refused inside a host transaction, so no savepoint is ever opened: built first, then classified,
  then inserted, 24 rows to a statement on SQLite and up to 1,000 on MySQL and PostgreSQL.
- The batch state machine, `Lifecycle\Enums\ImportStatus`: a batch starts `running` and ends `complete`, `partial`,
  `failed` or `interrupted`, and a final status never changes. The batch row is inserted before its `import_started`
  row, and the start commits with the hold `--hold` asks for, so the hold is on the batch before its first entry; a
  start that fails marks the batch `failed` with no entry written. `import_finished` closes it, journalled behind the
  lock only while the verified journal holds the batch's start and no finish (`Lifecycle\ImportJournal`), and the
  batch is made final after it, so a batch's finish is journalled at most once, never without its start, and a batch
  is final only once its finish is journalled; on failure the hold stays. A chunk lost to a concurrent one is retried,
  up to four attempts, and a failed statement leaves the importer masked. The first 100 conflicting source record ids
  are kept on the batch, fewer once their list would pass 60,000 bytes.
- A dry run reads, validates, minimises encrypting nothing and classifies: it creates no key, opens no batch, writes no
  journal row and dispatches nothing.

## Seams Left

- External verification of an imported bundle: every batch records `externally_verified` as `false`, since the
  package verifies nothing a source signed, and a source's own seals or anchor are not checked on import.

## Implementation Anchors

- `src/Contracts/RetentionPolicy.php`: `version()`, `retainFor()`, `preserveFor()`;
  `src/Lifecycle/ConfiguredRetentionPolicy.php`: `VERSION_PREFIX`; `src/Lifecycle/RetentionSettings.php`: `validate()`,
  `retainsAnythingForLess()`, `MAX_DAYS`; `src/Lifecycle/RetentionDecisions.php`: `for()`, `midnight()`;
  `src/Lifecycle/RetentionDecision.php`, `src/Lifecycle/RetentionConflictException.php`.
- `src/Lifecycle/AuditLifecycle.php`: `hold()`, `release()`, `prune()`, `import()`, `closeImport()`, `holds()`,
  `rebuildHolds()`, `reconcile()`, `erase()`, `reinstate()`, `rewrap()`, `reapplyErasures()`, `rebuildKeyUses()`;
  `src/Lifecycle/Authority.php`; `src/Lifecycle/HoldResult.php`, `src/Lifecycle/ReleaseResult.php`,
  `src/Lifecycle/PruneResult.php`, `src/Lifecycle/ImportResult.php`, `src/Lifecycle/ReconcileResult.php`,
  `src/Lifecycle/ReapplyResult.php`.
- `src/Lifecycle/MaintenanceTransaction.php`: `confirm()`, `run()`, `MAX_ATTEMPTS`, `JITTER_BASE_MS`, `JITTER_MAX_MS`;
  `src/Lifecycle/LifecycleContentionException.php`, `src/Lifecycle/LifecycleLockException.php`.
- `src/Database/InstallationIdentity.php`: `ensure()`, `confirm()`, `check()`, `NAME`;
  `src/Database/InstallationMismatchException.php`; `src/Database/LifecycleTables.php`.
- `src/Integrity/Enums/JournalKind.php`; `src/Integrity/JournalRow.php`, `src/Integrity/JournalSigner.php`,
  `src/Integrity/JournalChain.php`, `src/Integrity/JournalVerifier.php`.
- `src/Lifecycle/Journal.php`: `append()`; `src/Lifecycle/JournalReplay.php`: `start()`, `verify()`, `advance()`,
  `accept()`, `lastRunFinish()`; `src/Lifecycle/JournalBrokenException.php`.
- `src/Lifecycle/HoldScope.php`: `matches()`, `digest()`, `fromArray()`, `MAX_TENANTS`, `MAX_ABOUT`,
  `MAX_CATEGORIES`; `src/Lifecycle/Hold.php`; `src/Lifecycle/Enums/HoldBasis.php`; `src/Lifecycle/HoldKeeper.php`:
  `place()`, `placeIn()`, `release()`, `rebuild()`, `active()`; `src/Lifecycle/HoldProjection.php`: `rebuild()`,
  `drift()`; `src/Lifecycle/UnknownHoldException.php`.
- `src/Lifecycle/Pruner.php`: `run()`; `src/Lifecycle/PruneSeals.php`, `src/Lifecycle/PruneSeal.php`;
  `src/Lifecycle/PruneChunk.php`: `run()`, `STATEMENT_IDS`; `src/Lifecycle/PendingDeliveries.php`;
  `src/Lifecycle/SqliteDeleteTriggers.php`; `src/Lifecycle/PruneTally.php`: `MAX_DECISIONS`;
  `src/Lifecycle/PruneMismatchException.php`; `src/Lifecycle/Enums/PruneStatus.php`;
  `src/Lifecycle/JournalPruneLedger.php`.
- `src/Lifecycle/PruneTombstones.php`: `prunedAmong()`, `isPruned()`; `src/Delivery/OutboxDrainer.php`,
  `src/Delivery/Replayer.php`, `src/Stores/DatabaseAuditStore.php`.
- `src/Lifecycle/LifecycleRecorder.php`: `record()`; `src/Lifecycle/LifecycleRecords.php`: `blocked()`,
  `MAX_BLOCKED`; `src/Lifecycle/LifecycleEvidence.php`; `src/Lifecycle/LifecycleRecordFailedException.php`;
  `src/Lifecycle/Reconciler.php`: `reconcile()`; `src/Lifecycle/ReconciledOperations.php`: `erased()`,
  `reinstated()`, `rewrapped()`; `src/Querying/Enums/PackageActivity.php`: `isProtected()`.
- `src/Lifecycle/ErasureReapplier.php`: `reapply()`, `MAX_LINES`, `MAX_LINE_BYTES`; `src/Lifecycle/Eraser.php`,
  `src/Lifecycle/Reinstater.php`, `src/Lifecycle/Rewrapper.php`, `src/Keys/KeyUseRebuilder.php`.
- `src/Lifecycle/AuditImporter.php`: `import()`, `close()`; `src/Lifecycle/ImportSource.php`,
  `src/Lifecycle/ImportFile.php`, `src/Lifecycle/ImportLineParser.php`: `REQUIRED`, `OPTIONAL`,
  `isEnvelopeShaped()`; `src/Lifecycle/ExportLineAdapter.php`; `src/Lifecycle/SourceDigest.php`: `DERIVATION_INFO`;
  `src/Lifecycle/ImportRecordBuilder.php`, `src/Lifecycle/ImportClassifier.php`, `src/Lifecycle/ImportWriter.php`:
  `SQLITE_ROWS_PER_INSERT`, `ROWS_PER_INSERT`; `src/Lifecycle/ImportBatches.php`, `src/Lifecycle/ImportTally.php`:
  `MAX_CONFLICT_IDS`; `src/Lifecycle/ImportSettings.php`: `STALE_SECONDS`; `src/Records/ImportedSource.php`.
- `src/Lifecycle/Enums/ImportFormat.php`, `src/Lifecycle/Enums/ImportStatus.php`,
  `src/Lifecycle/Enums/ImportRejection.php`.
- `src/Console/PruneCommand.php`, `src/Console/HoldCommand.php`, `src/Console/ReleaseCommand.php`,
  `src/Console/HoldsCommand.php`, `src/Console/ImportCommand.php`, `src/Console/ReconcileCommand.php`,
  `src/Console/EraseCommand.php`, `src/Console/ReinstateCommand.php`, `src/Console/RewrapCommand.php`,
  `src/Console/KeysCommand.php`, `src/Console/LifecycleOptions.php`, `src/Console/LifecycleChecks.php`,
  `src/Console/IntegritySchedule.php`.
- `database/migrations/2026_11_02_000700_create_audit_log_lifecycle_table.php`,
  `database/migrations/2026_11_02_000800_create_audit_log_holds_table.php`,
  `database/migrations/2026_11_02_000900_create_audit_log_lifecycle_lock_table.php`,
  `database/migrations/2026_11_02_001000_create_audit_log_import_batches_table.php`.

## Authoritative Tests

- `tests/Feature/Lifecycle/MaintenanceTransactionTest.php` `testTheLockIsTheFirstStatement`,
  `testItRefusesInsideATransactionOnTheMaintenanceConnection`, `testItRefusesInsideATransactionOnTheStorageConnection`,
  `testAMismatchedInstallationRefusesBeforeTheLock`, `testAMissingLockRowRefuses`,
  `testTheWorkRunsOnTheMaintenanceConnection`, `testAConcurrencyFailureIsRetriedThreeTimesThenFails`,
  `testEachRetryWaitsAJitteredTime`, `testALostConnectionIsNeverRetried`,
  `testTheTokenNamesTheOperationAndChangesOnEveryAttempt`,
  `testARetriedAttemptRunsTheWorkAfreshAndReturnsOnlyTheCommittedResult`,
  `testOnMySqlTheIsolationIsSetBeforeTheTransaction`, `testOnPostgresTheIsolationIsAsserted`
- `tests/Integration/Lifecycle/LifecycleLockEnginesTest.php` `testASecondOperationWaitsForTheFirstsCommit`,
  `testAReadAfterTheLockSeesARowCommittedWhileWaiting`, `testOnSqliteTheLockIsTakenInsideTheFrameworksTransaction`,
  `testTwoOperationsNeverInterleave`
- `tests/Integration/Database/InstallationIdentityTest.php` `testTheFirstWriteWinsAndIsNeverReplaced`,
  `testConfirmRefusesConnectionsReachingDifferentDatabases`, `testTheRefusalNamesNoValue`
- `tests/Feature/Lifecycle/JournalTest.php` `testEachRowLinksToTheHead`, `testItRefusesToChainOntoAForgedHead`,
  `testAppendRefusesAHeadThatIsNotTheReplays`, `testASequenceCollisionIsALogicException`,
  `testItRefusesOutsideATransaction`
- `tests/Feature/Lifecycle/JournalReplayTest.php` `testABrokenChainRefuses`, `testAnInvalidTransitionRefuses`,
  `testATruncatedJournalAgainstTheLatestSealRefuses`, `testAdvanceFindsATruncatedTail`, `testAReplayIsAValue`,
  `testOnlyPolicyHoldAndReleasePayloadsAreRead`, `testAProjectionRowDeletedChangesNothing`
- `tests/Integration/Lifecycle/JournalCommitmentEnginesTest.php` `testRestoringAnOlderJournalContradictsTheSeals`
- `tests/Feature/Integrity/JournalTamperingTest.php` `testEachTamperingIsFoundAndExitsNonZero`
- `tests/Unit/Lifecycle/HoldScopeTest.php` `testATenantHoldNeverMatchesATenantlessRow`, `testDimensionsAreAnded`,
  `testTheWindowIsHalfOpen`, `testARowWhoseTimeCannotBeReadIsKeptByAnyWindow`, `testRefusesMoreThanItsLimits`,
  `testTheCanonicalFormIsSortedAndStable`
- `tests/Feature/Lifecycle/HoldKeeperTest.php` `testAHoldIsJournalledAndProjectedInOneTransaction`,
  `testOverlappingHoldsEachCount`, `testReleasingAnUnknownHoldIsRefusedAndWritesNothing`, `testADoubleReleaseIsRefused`,
  `testAReleasedHoldIdIsNeverPlacedAgain`, `testAHoldOnABrokenChainIsRefused`, `testTheRebuildReplaysTheVerifiedChain`,
  `testHoldsAreReadOnlyFromTheVerifiedChain`, `testAReleaseIsDecidedFromTheChainNotTheProjection`
- `tests/Feature/Lifecycle/HoldProjectionTest.php` `testTheRebuildEqualsTheLiveProjection`,
  `testDriftNamesMissingExtraAndChangedHolds`
- `tests/Unit/Lifecycle/Enums/HoldBasisTest.php` `testTheStoredValuesArePinned`
- `tests/Unit/Lifecycle/ConfiguredRetentionPolicyTest.php` `testZeroIsForever`, `testPreservationZeroIsForever`,
  `testNoPreservationIsNull`, `testTheVersionChangesOnlyWithTheSettings`, `testTheVersionDoesNotChangeWithTheRing`
- `tests/Unit/Lifecycle/RetentionSettingsTest.php` `testRefusesARetentionShorterThanItsPreservation`,
  `testAForeverPreservationNeedsAForeverRetention`, `testRetainsAnythingForLess`
- `tests/Unit/Lifecycle/RetentionDecisionsTest.php` `testThePolicyIsAskedOncePerPair`,
  `testTheCutoffIsMidnightLessTheDays`, `testOneMicrosecondEitherSideOfTheCutoff`, `testRefusesAnAnswerOutOfRange`,
  `testRefusesARetentionShorterThanAPreservation`
- `tests/Feature/Lifecycle/PruneChunkTest.php` `testItDeletesOnlyWhatItReadUnderTheLock`,
  `testAnIdAlreadyGoneIsNeverCovered`, `testTheRecordCoversExactlyTheDeletedPositions`,
  `testAnAffectedCountMismatchRollsBack`, `testAHoldPlacedBeforeTheLockIsSeen`,
  `testEligibilityIsDecidedFromTheVerifiedRow`, `testAnOutboxRowWrittenBeforeTheLockKeepsItsEntry`,
  `testATamperedCandidateDeletesNothing`
- `tests/Feature/Lifecycle/PrunerTest.php` `testNothingIsPrunedByDefault`, `testTheFrozenClockBoundary`,
  `testTwoCategoriesPruneIndependentlyInsideOneSeal`, `testAHeldRowSurvives`, `testAnUnsealedRowSurvives`,
  `testAProtectedExportSurvivesAndStillVerifies`, `testAPendingDeliverySurvivesAndIsCounted`,
  `testArtifactsAndReceiptsGoWithTheirEntries`, `testThePolicyRowIsWrittenOncePerVersion`,
  `testTheRunRowsCarryStatusCountsCursorAndCutoffs`, `testTheFinishRowIsBoundedWhateverTheTenants`,
  `testTheTimeBudgetStopsBetweenChunks`, `testAPartialRunResumesWhereItStopped`,
  `testACompleteRunStartsAgainFromTheFirstSeal`, `testAPartialRunThatReachedItsBoundaryStartsAgainFromTheFirstSeal`,
  `testARowReleasedAfterAPartialRunIsPrunedByTheNext`, `testTheCursorIsReadFromTheVerifiedChainAfterTheLock`,
  `testASealThatFailsAuthenticationIsSkippedAndReported`, `testATamperedCandidateSkipsItsSealAndDeletesNothing`,
  `testAPolicyExceptionStopsTheRunAndCommittedChunksStand`, `testACustomPolicysConflictStopsTheRun`,
  `testABrokenJournalRefusesTheRun`, `testADeletedProjectionRowStillHolds`,
  `testTheDryRunCountsHeldRowsAsTheRunWould`, `testTenThousandUnsealedRowsPastTheThresholdDeleteNothing`,
  `testAMismatchIsRetriedOnceThenTheSealIsSkipped`, `testARetriedChunkStartsFromTheCommittedReplay`,
  `testASealMadeDuringTheRunIsNotPruned`, `testTheCutoffIsFixedForTheRun`,
  `testAFailedRunAfterItsStartStillWritesItsFinishRow`
- `tests/Feature/Lifecycle/PendingDeliveriesTest.php` `testAFailedOutboxRowIsPending`,
  `testAnUndeliveredReceiptIsPending`, `testAnOutboxOnAnotherConnectionIsReadAfterTheLock`
- `tests/Feature/Lifecycle/SqliteDeleteTriggersTest.php` `testARollbackRestoresTheTriggers`,
  `testTheRecreatedTextIsTheDocumentedText`
- `tests/Integration/Lifecycle/PruneEnginesTest.php` `testVerifyAfterARealPrunePasses`,
  `testOnSqliteTheDocumentedTriggersAreDroppedAndRestored`
- `tests/Integration/Lifecycle/PruneRacesTest.php` `testAHoldRacingAPruneNeverLosesAHeldRow`,
  `testTwoPrunesNeverCoverOneMemberTwice`, `testAReleaseRacingAPruneIsOrdered`
- `tests/Integration/Integrity/PruneBoundariesTest.php`
  `testACrashAfterTheStartRowIsResumedFromTheLastFinishedRunsCursor`, `testARecordWithoutItsDeletionIsResurrected`
- `tests/Unit/Lifecycle/PruneResultTest.php` `testTheCategoriesAreBoundedAtFifty`
- `tests/Feature/Delivery/PrunedRedeliveryTest.php` `testTheDrainCompletesAPrunedRowAsPruned`,
  `testASpillReplayCountsAPrunedLineAndStoresNothing`, `testAnOutboxReplayOfAPrunedRowCompletesItAsPruned`,
  `testNoDestinationIsCalledForAPrunedRow`, `testAFreshCaptureIsNeverChecked`,
  `testADirectStoreOfAPrunedRecordIsReportedResurrected`
- `tests/Integration/Stores/PrunedRecordConflictTest.php` `testAUniqueViolationOfAPrunedIdIsAlreadyPruned`,
  `testAFreshInsertOfAPrunedIdIsNotRefused`
- `tests/Integration/Delivery/PrunedRedeliveryEnginesTest.php` `testAPrunedEntryIsNeverResurrectedByTheDrain`,
  `testAPrunedEntryIsNeverResurrectedBySpillReplay`
- `tests/Feature/Lifecycle/LifecycleRecorderTest.php` `testItWritesThroughThePackageWriteFailClosedAndImmediate`,
  `testAFailedRecordIsReportedOnceAndReturnsFalse`, `testNothingIsRethrown`, `testTheCategoryIsAudit`
- `tests/Feature/Lifecycle/AuditLifecycleTest.php` `testAHoldIsRecordedAfterItCommits`,
  `testARecordingFailureLeavesTheHoldCommittedAndRecordedFalse`, `testAnUnknownReleaseIsRecordedDeniedAndRethrown`,
  `testAFailedPruneIsRecordedAsAFailure`, `testAnImportsHoldIsRecordedHeld`, `testHoldsAreReadFromTheVerifiedChain`,
  `testAnErasureIsRecordedAfterItsCommit`, `testARefusedErasureIsRecordedDeniedAndRethrown`,
  `testARecordingFailureLeavesTheErasureCommitted`, `testAReinstatementIsRecorded`, `testARewrapIsRecorded`,
  `testTheSubjectErasedRecordReachesTheDestinations`
- `tests/Feature/Lifecycle/LifecycleRecordsTest.php` `testEachRefusalIsRecordedDenied`,
  `testAFailedErasureIsRecordedWithACode`, `testTheBlocksAreBoundedAtFifty`
- `tests/Feature/Lifecycle/ReconcilerTest.php` `testAMissingRecordIsRecordedAgain`,
  `testAnOperationRecordedAlreadyIsSkipped`, `testOnlyTheWindowIsReconciled`, `testNoJsonPathQueryIsIssued`,
  `testAnErasureMissingItsRecordIsRecorded`, `testRewrapsAndReinstatementsAreReconciled`
- `tests/Unit/Lifecycle/ReconciledOperationsTest.php` `testARewrapRunIsSummedOverItsBatches`,
  `testARunWithABatchThatDescribesNoBatchIsNull`
- `tests/Feature/Lifecycle/ErasureReapplierTest.php` `testEachOwnerIsErasedPartiallyWithPendingAccepted`,
  `testAPartiallyErasedOwnerLeavesTheRestoreUnreconciled`,
  `testAllOwnersErasedJournalsTheReconciliationWithTheAnchoredHead`, `testAMalformedLineIsCounted`,
  `testAFileChangedDuringTheRunFails`
- `tests/Feature/Console/EraseCommandTest.php` `testAFailurePrintsItsClassNotItsMessage`,
  `testAReapplyReconcilesTheRestore`
- `tests/Unit/Querying/Enums/PackageActivityTest.php` `testOnlyTheExportIsProtected`, `testNoLifecycleCodeIsARead`
- `tests/Feature/Lifecycle/AuditImporterTest.php` `testADryRunWritesNothing`, `testEveryColumnOfAnImportedRow`,
  `testTheBatchIsNotExternallyVerified`, `testImportedRowsAreNotDispatchedOrDelivered`,
  `testTheHoldIsPlacedBeforeTheFirstEntry`, `testTheStartAndTheHoldCommitTogether`,
  `testAJournalFailureAtStartFailsTheBatchAndWritesNoEntry`, `testOnFailureTheHoldStays`,
  `testAFileChangedDuringTheImportFailsTheBatch`, `testItRefusesItsOwnSource`, `testAReimportAfterAPruneCreatesNewRows`,
  `testCloseMarksARunningBatchInterruptedAndJournalsIt`, `testCloseRefusesAFinishedBatch`,
  `testEntriesAndTheBatchAreOnTheStorageWriterAndTheJournalOnTheMaintenanceConnection`
- `tests/Feature/Lifecycle/ImportLineParserTest.php` `testEnvelopeShapedValuesAreDroppedAtAnyDepth`,
  `testAnEnvelopeShapedIpIsDropped`, `testTheFutureSkewIsTheSetting`
- `tests/Feature/Lifecycle/ExportLineAdapterTest.php` `testAnImportedLineKeepsItsUpstreamIdentity`,
  `testAnUpstreamSourceOfThisInstallationIsRejected`, `testForeignEnvelopesAreDroppedAndCounted`,
  `testIntegrityFieldsAreIgnored`
- `tests/Unit/Lifecycle/SourceDigestTest.php` `testTheDigestIsKeyedUnderItsOwnInfo`,
  `testMinimisationDoesNotChangeIt`
- `tests/Feature/Lifecycle/ImportClassifierTest.php` `testDuplicatesWithinOneChunk`, `testAConflictWithinOneChunk`,
  `testADefinitionChangedBetweenImportsStillFindsTheDuplicate`
- `tests/Feature/Lifecycle/ImportWriterTest.php` `testAChunkIsOneTransactionWithNoSavepoint`,
  `testARejectedLineIsNeverTheCandidateOfItsPair`, `testRowsPerInsertFollowTheEngine`
- `tests/Feature/Lifecycle/ImportRecordBuilderTest.php` `testADryRunEncryptsNothing`
- `tests/Integration/Lifecycle/ImportUniquenessEnginesTest.php` `testTwoConcurrentImportsStoreEachRecordOnce`,
  `testAUniqueViolationRollsTheChunkBackAndReclassifies`, `testASecondViolationMakesTheBatchPartial`,
  `testAnInterruptedImportIsReportedAndClosed`
- `tests/Unit/Lifecycle/Enums/ImportStatusTest.php` `testEveryStatusButRunningIsFinal`
- `tests/Feature/Console/LifecycleChecksTest.php` `testProjectionDriftIsAProblemNamingTheHolds`,
  `testAPassedReviewDateIsANoteNotAProblem`, `testAStaleRunningImportIsANote`, `testAMismatchedInstallationIsAProblem`
- `tests/Integration/Lifecycle/LifecycleTriggersTest.php` `testAJournalDeleteIsRefusedEvenForTheMaintenanceUser`,
  `testAHoldDeleteIsRefusedButForTheMaintenanceUser`
- `tests/Unit/Documentation/LifecycleDocumentationTest.php` `testTheLifecycleNoteHasItsSectionsInOrder`,
  `testEachLifecycleStatementIsMade`

## Change Triggers

Update this note when any of the following change:

- the lock protocol: the lock row, its token, the isolation, the retries or what is read after the lock
- the journal's columns, kinds, label, derivation or chain, or what a seal commits to of it
- what decides a deletion, or what a destructive decision reads
- a hold scope's dimensions, limits or matching, a hold's basis, or what the projection is trusted for
- the retention policy's questions, their ranges, the configured policy's version or the cut-off
- what makes an entry eligible, what a chunk deletes with it, or what a prune never deletes
- a prune run's rows, statuses, cursor, resume rule or bounds
- the paths that check the tombstones
- an import format, the source digest, the classification, the chunks, the batch states or the hold an import places
- the installation identity, or which connection each operation writes through
- the activity codes, what they retain or when they are written, or what a refusal or a failure records
- a privacy kind's payload, how a rewrap run is reconciled, or what reconciles a restore
- the basis, archive, Article 17 or export key statements
