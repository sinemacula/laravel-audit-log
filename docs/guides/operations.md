# Operations

Sealing, anchoring and verification run as commands, on Laravel's scheduler, beside the application. This guide covers
what to schedule, what to watch, where to anchor, which keys to keep, and what sealing costs. How each step works, and
what each status and finding means, is in [the integrity note](../design/integrity.md); what none of it promises is in
[the threat model](../design/threat-model.md).

## Schedule

The package registers three runs on Laravel's scheduler, so the scheduler itself must run: `php artisan schedule:run`
every minute from cron, or `php artisan schedule:work`. `php artisan schedule:list` shows the runs the package
registered.

| Run                                       | Setting                         | Default       | What it does                                                   |
|-------------------------------------------|---------------------------------|---------------|----------------------------------------------------------------|
| `audit-log:seal`                          | `integrity.seal.schedule`       | `*/5 * * * *` | Seals the entries recorded since the last seal, then anchors   |
| `audit-log:seal --sweep`                  | `integrity.seal.sweep_schedule` | `15 3 * * *`  | Seals whatever the recent passes missed, from a saved cursor   |
| `audit-log:verify --strict --sweep-first` | `integrity.verify.schedule`     | `45 3 * * *`  | Sweeps, then verifies the whole log and its anchoring, records |

- Each run is started with `runInBackground()`, so a long sweep or verification never holds up the application's own
  tasks due in the same minute, and `schedule:work` keeps ticking while one runs.
- Each run is registered with `withoutOverlapping()`, so a run still going when the next is due is not started twice.
  Its lock lapses well inside the run's period, after 15 minutes for sealing and 23 hours for the sweep and the
  verification, so a run killed before it released its lock (a deploy, a restart, the memory limit) skips at most the
  runs due within that time, never the next day's. `php artisan schedule:clear-cache` clears a lock a killed run left.
- Each run is registered with `onOneServer()` only when the cache store the scheduler takes its locks in is `redis`,
  `memcached`, `database` or `dynamodb`, the stores every server shares. That store is the one `Schedule::useCache()`
  was given, which Laravel sets from `cache.schedule_store` or the `SCHEDULE_CACHE_DRIVER` environment variable, and the
  default store when there is none. On a `file` or `array` store every server runs each command; that is safe, since
  sealing is safe beside another sealer, but it is wasted work, so give the scheduler a shared store.
- `audit-log:seal` also takes a cache lock for up to 900 seconds when the store can lock: `audit-log:seal` for the recent
  pass and `audit-log:seal:sweep` for the sweep, which are safe beside each other, so a long sweep never stops the
  recent pass from sealing and anchoring. A run that finds its own lock held prints "Another sealer holds the lock." and
  exits 0. The lock only saves work: a store that cannot lock, or that fails, costs nothing else.
- Set a run's schedule to `null` or empty (`AUDIT_LOG_INTEGRITY_SEAL_SCHEDULE=`) to register nothing for it, and
  schedule the command yourself, for example in `routes/console.php`:

  ```php
  use Illuminate\Support\Facades\Schedule;

  Schedule::command('audit-log:seal')->everyFiveMinutes()->withoutOverlapping(15)->runInBackground()->onOneServer();
  Schedule::command('audit-log:seal --sweep')->dailyAt('03:15')->withoutOverlapping(1380)->runInBackground()->onOneServer();
  Schedule::command('audit-log:verify --strict --sweep-first')->dailyAt('03:45')->withoutOverlapping(1380)->runInBackground()->onOneServer();
  ```

- A schedule that is no cron expression registers nothing for its run and is reported; it never throws, so the
  application's other tasks still run, and `php artisan audit-log:check` names it before a deploy.

The commands can be run by hand too:

- `audit-log:seal` seals and anchors; `--sweep` reads the whole table from the sweep's cursor instead of the lookback.
  It exits 1 when sealing or anchoring fails, and 0 when the anchor is only unavailable, which it prints as a warning.
- `audit-log:verify` verifies the whole log, or the seals from `--from` to `--to` by sequence; `--json` writes each line
  as one JSON object; `--strict` also fails on any seal the configured anchor does not confirm; `--sweep-first` runs
  `audit-log:seal --sweep` before verifying, so an entry inserted late since the last sweep is sealed rather than found
  overdue. It exits 0 when the log passes, 1 when it fails, the run stops or the sweep before it fails, and 2 for a
  range it refuses. A ranged run checks every seal of its range, a seal missing at either end of it included, and says
  that it does not establish the integrity of the whole log, so schedule the complete one.

## Monitor

A failure raises an alarm; a run that does not happen raises none.

- Each of these dispatches `IntegrityCheckFailed` and reports an `IntegrityCheckFailedException`: a verification that
  fails or stops, and, in sealing, a refused head, an entry that cannot be sealed, an anchor conflict or a refused seal.
  Any other failure that stops sealing or anchoring, a malformed anchor setting among them, is reported as a
  `SealFailedException` naming its class, and sealing still runs when only anchoring cannot. Route the package's
  reports where someone answers them; [the events guide](events.md) shows a listener. A listener that fails is reported
  as it threw, and the alarm is still reported after it.
- An unavailable anchor only warns: the class of its failure is kept on the seal and in `anchor.last_failure`, and the
  next run tries again. Only a strict verification fails on it.
- Nothing alarms on a run that does not happen: a missed scheduled run raises nothing, since a stopped scheduler, a
  server that is down or a cron line that was lost dispatches no event and reports nothing. So read the progress the
  package records, and alert when it goes stale.

The progress is in `integrity.state_table` (`audit_log_integrity_state` by default), one row per name, with the time it
was written in `updated_at`. It is operational, never evidence: a monitor may read it, and nothing it says changes what
verification finds.

```sql
SELECT name, value, updated_at FROM audit_log_integrity_state ORDER BY name;
```

| Name                  | Written                                    | Value                                  | Stale means                                                         |
|-----------------------|--------------------------------------------|----------------------------------------|---------------------------------------------------------------------|
| `seal.last_run`       | When a seal run ends without a failure     | `at`, `seals`, `entries`, `sweep`      | Older than a few seal intervals: the scheduler or sealing stopped   |
| `seal.last`           | After each seal commits                    | `sequence`, `id`, `sealed_at`          | Old while entries are being recorded: nothing is being sealed       |
| `seal.recent`         | After a recent pass's seal moves it on     | `last_recorded_at`                     | Old while entries are being recorded: the recent pass stopped       |
| `sweep.cursor`        | After each window of an unfinished sweep   | `recorded_at`, `id`, `from_its_time`   | Present for days: the sweep keeps stopping before its end           |
| `sweep.completed`     | When a sweep reaches the end of the table  | `at`                                   | Older than a day and a sweep's length: the sweep is overdue         |
| `anchor.last`         | After a pass that anchored a seal          | `sequence`, `anchor`, `anchored_at`    | Behind `seal.last`: anchoring lags sealing                          |
| `anchor.last_failure` | When anchoring fails                       | `sequence`, `class`, `at`              | Newer than `anchor.last`: the anchor is down                        |
| `verify.last_full`    | When a complete verification ends          | `at`, `head`, `passed`, `strict`       | Older than a day, or `passed` false: the verification did not pass  |

- `verify.last_full` records whether the run passed at the strictness it ran at, and that strictness in `strict`: the
  scheduled run is strict, so a run that failed only on its anchoring records `passed` false with `strict` true. A
  monitor should alert on a stale row and on `passed` false alike.
- `seal.recent` is where the recent pass reads from, less the lookback: the latest entry time a recent pass sealed,
  which only a recent pass moves forward, so a sweep's seal of old rows never pulls the recent pass back to them.

- **Anchor lag** is the distance between `seal.last` and `anchor.last` by sequence. Each seal run anchors up to
  `integrity.anchor.batch` seals after it seals, so a lag that grows run after run means the anchor is failing or slower
  than sealing; `audit-log:verify` also prints how many seals still await their first anchoring.
- **An overdue sweep** leaves a late entry older than the lookback unsealed. Once one is older than
  `integrity.verify.max_unsealed_age_seconds` (25 hours by default) verification reports it `overdue_unsealed` and the
  log `incomplete`, so a sweep that stops is found by the next verification as well as by its progress.
- **Replayed records**, such as those spilled during an outage and replayed later, keep the time they were recorded,
  so one older than the lookback waits for the next sweep, and one older than the allowed age would be overdue the
  moment it is inserted. The scheduled verification sweeps first, so a replay inserted after the daily sweep is sealed
  before it is verified; a verification run by hand without `--sweep-first` reports such a replay overdue until a sweep
  seals it.
- **An entry recorded far ahead of the clock**, more than the lookback beyond the verification's own clock, is never
  taken by a seal while it stays ahead, so verification reports it `future_unsealed` and the log `incomplete` rather
  than counting it pending. A clock that runs that far ahead on a recording server shows up here first.
- Run `php artisan audit-log:check` in the deploy pipeline: it reports a malformed integrity setting, a missing or
  misshapen integrity table and an anchor disk that is not configured, and writes nothing.

## Anchor outside the application

An anchor is worth only what the application cannot change. With the default, `null`, seals are kept only in the
database and are reported `unanchored`, and a truncated tail cannot be found.

The package's own anchor writes each seal's summary to a Laravel filesystem disk, once:

```php
// config/filesystems.php, under 'disks'
'audit-anchor' => [
    'driver' => 's3',
    'key'    => env('AUDIT_ANCHOR_ACCESS_KEY_ID'),
    'secret' => env('AUDIT_ANCHOR_SECRET_ACCESS_KEY'),
    'region' => env('AUDIT_ANCHOR_REGION'),
    'bucket' => env('AUDIT_ANCHOR_BUCKET'),
    'http'   => ['connect_timeout' => 5, 'timeout' => 10],
],
```

The anchor disk must have bounded timeouts. Anchoring runs inside `audit-log:seal`, after sealing, and the S3 client
waits without limit by default, so during an outage that drops packets rather than refusing them, a run with no timeout
holds its database connection and its lock until the outage ends, and the runs after it pile up behind it. With a
timeout, the anchor is unavailable for that run, the run warns and ends, and the next run tries again.

```dotenv
AUDIT_LOG_INTEGRITY_ANCHOR_DRIVER=disk
AUDIT_LOG_INTEGRITY_ANCHOR_DISK=audit-anchor
AUDIT_LOG_INTEGRITY_ANCHOR_PATH=audit-log-anchors
```

- The anchor writes a marker at `{path}/{log_id}/by-sequence/{sequence}`, then the object at
  `{path}/{log_id}/{sequence}-{seal_digest}.json`, each sequence padded to 20 digits. It reads before it writes, never
  writes over a path and never deletes one, so its credentials need to read and create objects, and nothing more; it
  never lists. A path that holds part of a write, as another anchorer still making it leaves it, is read as the anchor
  unavailable for that run, never as a conflict, so only a whole marker or summary that differs raises a tamper alarm.
- The anchor's head is found from its markers, which the anchorer writes in sequence order from 1: about two existence
  checks per doubling of the log (some 40 for a million seals), and a read of the head's marker and object.
- Which seals to anchor is the anchor's own answer: each run anchors every seal after the anchor's head, whatever the
  anchor columns kept beside the seals say, and below the head only a seal whose receipt was never written. Each read
  is by the sequence or the anchoring index, so a run never reads the seals already anchored.
- Object Lock protects versions, not keys, and a delete marker or a new version is what an ordinary read then sees. The
  anchor on S3 therefore needs Object Lock in compliance mode with a retention period and a bucket policy denying
  version deletion. A new version hides an anchored object from an ordinary read, so the anchor also needs writes that
  cannot replace an existing object: credentials and a bucket policy under which the application can create an object
  but never write over one, or another write-once (WORM) store. These guarantees are conditional on that configuration.
  A disk the application can overwrite or delete is evidence only against someone who cannot reach it.
- Keep the bucket under another account and other credentials than the database's, so that whoever takes over the
  application or its database does not also hold the anchor.
- The package has no S3 SDK dependency: the disk is any Laravel filesystem disk, and the `s3` driver's Flysystem adapter
  is the application's to install.
- The anchor's name is its location, so changing `integrity.anchor.disk` or `integrity.anchor.path` anchors every seal
  again at the new one, `integrity.anchor.batch` seals a run.
- `integrity.log_id`, or `source.id` when it is not set, names the log inside the namespace. Set it before the first
  seal and never change it: a changed log id stops sealing, so two logs are never mixed in one chain.
- To anchor elsewhere, bind your own `SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor`. One whose
  `supportsDiscovery()` is `false` fails every strict verification, because a truncated tail could not be found.

## Keys and their lifetimes

The integrity key ring signs every entry, and each seal is signed under a key derived from the ring key it names, so the
ring decides for how long the log can be verified.

| Key                    | Protects                                                                 | Keep it                                              |
|------------------------|--------------------------------------------------------------------------|------------------------------------------------------|
| Encryption keys        | The outbox and bulk manifests (`app.key`) and encrypted fields (owners') | Until no row needs decrypting; destroying one erases |
| Row-HMAC keys          | Each entry's `hmac`, under its `key_id`                                  | As long as the entries they signed                   |
| Seal-verification keys | Each seal's `signature`, under its `key_id`                              | As long as the seals, which pruning keeps            |

- These are separate lifetimes, though one ring key may serve as both a row-HMAC and a seal-verification key: an
  encryption key may be retired or destroyed on its own schedule, while a ring key is kept for as long as a seal names
  it, which is as long as the log is kept.
- A retired `app.key` must stay in `app.previous_keys` for as long as the artifacts sealed under it are kept, or their
  manifests can no longer be read and `audit-log:verify` reports them `manifest_unreadable`, though their entries still
  verify.
- Use a managed ring (`integrity.keys` and `integrity.current`) before going live. A key derived from `app.key` ties the
  log to it: after a rotation the old key has to stay in `app.previous_keys` for as long as the log, and dropping it
  leaves every row and seal it signed unverifiable.
- Rotate by adding a key to the ring and pointing `integrity.current` at it. Keep the old key in the ring: verification
  selects each key by the id stored with the row or seal. Choose each id once, since a key id is never reused for
  different material.
- Keep the ring's secrets out of the database and its backups, and away from whoever administers the anchor: anyone
  holding the ring can sign rows and seals.

## Grants and triggers

The Grants And Triggers section of [the storage note](../design/storage.md) has the grants and the optional append-only
triggers for each engine, as SQL that its tests run as written.

- The application's user inserts and selects entries, artifacts, seals and members, may update only a seal's four
  anchor columns, and needs `SELECT`, `INSERT`, `UPDATE` and `DELETE` on the integrity state table; it is granted no
  DDL.
- The maintenance user is the only one that may delete an entry or its artifact, and nothing else, since pruning
  deletes an entry's artifact with it and keeps every seal and member.
- Run `audit-log:verify` as a user that can read the tables and write the integrity state table.
- The triggers guard against the application's users. The tables' owner can drop them, so keep the owner's credentials
  out of the application.

## Sealing at volume

Each seal run's recent pass starts `integrity.seal.lookback_seconds` before the latest entry a recent pass sealed, so
the recent pass reads the whole lookback window every run, sealed rows included, whatever it finds to seal. A longer
lookback catches later arrivals without waiting for the sweep, and costs a longer read on every run: the lookback trades
latency against cost. The lookback must exceed the worst clock skew between the servers that record, because an entry
stamped by a clock running ahead can move the window past entries not yet sealed, which then wait for the daily sweep.

- The sweep reads the table in windows of `integrity.seal.batch` entries, saving its cursor after each, so its cost is
  one read per window and it resumes where it stopped. `integrity.seal.max_batches` bounds the seals one run writes (at
  the defaults, 500,000 entries); a backlog larger than that is sealed over several runs.
- A seal of `integrity.seal.batch` entries is one transaction that inserts its members 300 at a time. A smaller batch
  holds the writer for less time; a larger one writes fewer seals.
- On SQLite use WAL: in rollback-journal mode a sealer's read blocks every writer's commit until its transaction ends.
  In WAL mode readers and the writer do not block each other, though SQLite still has one writer at a time.
- On every verification, the anchor is asked for its head once. When the local seal at that head has the head's digest
  and the run reaches it, the head settles every seal's anchoring with no further request, since its digest commits to
  the chain the run checks link by link. Only a ranged run that ends before the head, a head the local log contradicts,
  or an anchor that cannot report its head puts each seal's receipt to the anchor, which is two requests a seal for the
  disk anchor. A complete run therefore costs the anchor the discovery requests above, whatever the size of the log.

What follows was measured once, for this guide. The machine was an 18-core Apple silicon laptop with 128 GB of memory,
running macOS 27.0.1 and PHP 8.4.23, with MySQL 8.4.11 and PostgreSQL 17.11 each in a Linux container on the same
machine, in the configuration the package's own test runs use and with no tuning. Each table held copies of one stored
record of 36 columns, with distinct ids, HMACs and times, one a second, and in the larger table two a second over its
newest 100,000 seconds, every table analysed before each measurement; the settings were the defaults but
`integrity.seal.max_batches`, raised so that one sweep sealed the whole table. Times are the wall-clock time of one run
of the sealer, from PHP. These measurements show one machine and claim nothing beyond it.

| Run                             | Entries   | MySQL 8.4 | PostgreSQL 17 | Statements |
|---------------------------------|-----------|-----------|---------------|------------|
| Sweep sealing an unsealed table | 100,000   | 2.09 s    | 1.76 s        | 446        |
| Sweep sealing an unsealed table | 1,000,000 | 21.45 s   | 21.82 s       | 4,406      |
| Sweep of a sealed table         | 100,000   | 0.28 s    | 0.22 s        | 66         |
| Sweep of a sealed table         | 1,000,000 | 3.45 s    | 10.23 s       | 606        |
| Recent pass over a sealed table | 100,000   | 0.008 s   | 0.009 s       | 4          |
| Recent pass over a sealed table | 1,000,000 | 0.017 s   | 0.007 s       | 4          |

Each sweep read every entry once, in windows of at most 5,000 rows: 21 windows at 100,000 entries and 201 at 1,000,000.
Sealing wrote 20 and 200 seals of 5,000 entries. The recent pass read the newest hour, 3,601 entries at 100,000 and
7,201 at 1,000,000, and found nothing to seal.

The recent pass's candidate query, as the sealer ran it:

```sql
select e.id, e.hmac, e.recorded_at
from audit_log_entries as e
left join audit_log_checkpoint_members as m on m.entry_id = e.id
where e.recorded_at <= ? and e.recorded_at >= ? and m.entry_id is null
order by e.recorded_at asc, e.id asc
limit 5000
```

The sweep's window query, for a window after the cursor:

```sql
select w.id, w.hmac, w.recorded_at, m.entry_id as member_entry_id
from (
    select id, hmac, recorded_at from audit_log_entries
    where recorded_at <= ? and recorded_at >= ? and (recorded_at > ? or (recorded_at = ? and id > ?))
    order by recorded_at asc, id asc
    limit 5000
) as w
left join audit_log_checkpoint_members as m on m.entry_id = w.id
order by w.recorded_at asc, w.id asc
```

The window is bounded below by the cursor's time on its own as well as by the cursor's `or`, so that an engine can start
its read of `<table>_recorded_index` at the cursor rather than at the beginning of the table.

On MySQL 8.4, `EXPLAIN FORMAT=TREE` of the candidate query over 100,000 sealed entries reads the lookback as a range of
`<table>_recorded_index` and probes the members' unique entry index once for each entry:

```text
-> Limit: 5000 row(s)  (cost=5205 rows=5000)
    -> Filter: (m.entry_id is null)  (cost=5205 rows=6506)
        -> Nested loop antijoin  (cost=5205 rows=6506)
            -> Index range scan on e using audit_log_entries_recorded_index over ('2026-11-03 05:21:06.000000' <= recorded_at <= '2026-11-03 07:21:19.275995'), with index condition: ((e.recorded_at <= TIMESTAMP'2026-11-03 07:21:19.275995') and (e.recorded_at >= TIMESTAMP'2026-11-03 05:21:06'))  (cost=2928 rows=6506)
            -> Single-row covering index lookup on m using audit_log_checkpoint_members_entry_unique (entry_id=e.id)  (cost=0.25 rows=1)
```

and of the window query, at the middle window, reads both bounds of the cursor as a range of the same index:

```text
-> Nested loop left join  (cost=19367 rows=5000)
    -> Sort: w.recorded_at, w.id  (cost=17617..17617 rows=5000)
        -> Table scan on w  (cost=10909..10974 rows=5000)
            -> Materialize  (cost=10909..10909 rows=5000)
                -> Limit: 5000 row(s)  (cost=10409 rows=5000)
                    -> Index range scan on audit_log_entries using audit_log_entries_recorded_index over (recorded_at = '2026-11-02 16:27:46.000000' AND '01a1a048-8ef1-7110-8a14-3d191362c3bf' < id) OR ('2026-11-02 16:27:46.000000' < recorded_at <= '2026-11-03 07:21:18.996031'), with index condition: ((audit_log_entries.recorded_at <= TIMESTAMP'2026-11-03 07:21:18.996031') and (audit_log_entries.recorded_at >= TIMESTAMP'2026-11-02 16:27:46') and ((audit_log_entries.recorded_at > TIMESTAMP'2026-11-02 16:27:46') or ((audit_log_entries.recorded_at = TIMESTAMP'2026-11-02 16:27:46') and (audit_log_entries.id > '01a1a048-8ef1-7110-8a14-3d191362c3bf'))))  (cost=10409 rows=48711)
    -> Single-row covering index lookup on m using audit_log_checkpoint_members_entry_unique (entry_id=w.id)  (cost=0.25 rows=1)
```

On PostgreSQL 17, `EXPLAIN (ANALYZE, BUFFERS)` of the candidate query over 100,000 sealed entries reads the lookback
through `<table>_recorded_index`, and the planner chose a hash anti-join that reads every member row:

```text
Limit  (cost=8673.12..8673.13 rows=1 width=89) (actual time=9.437..9.438 rows=0 loops=1)
  Buffers: shared hit=1833
  ->  Sort  (cost=8673.12..8673.13 rows=1 width=89) (actual time=9.437..9.437 rows=0 loops=1)
        Sort Key: e.recorded_at, e.id
        Sort Method: quicksort  Memory: 25kB
        Buffers: shared hit=1833
        ->  Hash Anti Join  (cost=3890.42..8673.11 rows=1 width=89) (actual time=9.435..9.436 rows=0 loops=1)
              Hash Cond: (e.id = m.entry_id)
              Buffers: shared hit=1833
              ->  Index Scan using audit_log_entries_recorded_index on audit_log_entries e  (cost=0.42..4769.79 rows=3553 width=89) (actual time=0.003..0.557 rows=3601 loops=1)
                    Index Cond: ((recorded_at <= '2026-11-03 07:23:31.632018'::timestamp without time zone) AND (recorded_at >= '2026-11-03 05:23:19'::timestamp without time zone))
                    Buffers: shared hit=193
              ->  Hash  (cost=2640.00..2640.00 rows=100000 width=16) (actual time=8.687..8.688 rows=100000 loops=1)
                    Buckets: 131072  Batches: 1  Memory Usage: 5712kB
                    Buffers: shared hit=1640
                    ->  Seq Scan on audit_log_checkpoint_members m  (cost=0.00..2640.00 rows=100000 width=16) (actual time=0.003..4.289 rows=100000 loops=1)
                          Buffers: shared hit=1640
Planning:
  Buffers: shared hit=20
Planning Time: 0.051 ms
Execution Time: 9.456 ms
```

Over 1,000,000 sealed entries the same query was planned as a nested-loop anti-join instead, probing the members' unique
entry index for each of the 7,201 entries and taking 4.2 ms.

The window query, at the middle window over 100,000 sealed entries, bounds the index by the cursor's time and the run's
end, so the scan starts at the cursor; the cursor's `or` is applied as a filter, which removed only the entry at the
cursor itself. The planner joined the window to the members by a hash join that reads every member row:

```text
Sort  (cost=5849.18..5861.68 rows=5000 width=105) (actual time=9.786..9.990 rows=5000 loops=1)
  Sort Key: audit_log_entries.recorded_at, audit_log_entries.id
  Sort Method: quicksort  Memory: 818kB
  Buffers: shared hit=1907
  ->  Hash Right Join  (cost=2476.99..5541.99 rows=5000 width=105) (actual time=5.261..9.553 rows=5000 loops=1)
        Hash Cond: (m.entry_id = audit_log_entries.id)
        Buffers: shared hit=1907
        ->  Seq Scan on audit_log_checkpoint_members m  (cost=0.00..2640.00 rows=100000 width=16) (actual time=0.009..3.994 rows=100000 loops=1)
              Buffers: shared hit=1640
        ->  Hash  (cost=2414.49..2414.49 rows=5000 width=89) (actual time=1.192..1.193 rows=5000 loops=1)
              Buckets: 8192  Batches: 1  Memory Usage: 689kB
              Buffers: shared hit=267
              ->  Limit  (cost=0.42..2414.49 rows=5000 width=89) (actual time=0.006..0.935 rows=5000 loops=1)
                    Buffers: shared hit=267
                    ->  Index Scan using audit_log_entries_recorded_index on audit_log_entries  (cost=0.42..12043.25 rows=24943 width=89) (actual time=0.005..0.761 rows=5000 loops=1)
                          Index Cond: ((recorded_at <= '2026-11-03 07:23:31.401107'::timestamp without time zone) AND (recorded_at >= '2026-11-02 16:29:59'::timestamp without time zone))
                          Filter: ((recorded_at > '2026-11-02 16:29:59'::timestamp without time zone) OR ((recorded_at = '2026-11-02 16:29:59'::timestamp without time zone) AND (id > '01a1a04a-9527-701d-a405-18e88a6fb76c'::uuid)))
                          Rows Removed by Filter: 1
                          Buffers: shared hit=267
Planning:
  Buffers: shared hit=50 read=1
Planning Time: 0.166 ms
Execution Time: 10.097 ms
```

Over 1,000,000 sealed entries the planner kept the hash join for the middle window, reading all 1,000,000 member rows
and taking 82.9 ms, which is why the sweep of the sealed table on PostgreSQL took 46 times as long at ten times the
entries, against 12 times on MySQL. In a separate run over a table filled the same way, the planner chose a nested-loop
join for the same window, probing the members' unique entry index for each of its 5,000 entries in 4.3 ms, and the
sweep of the sealed table took 1.80 s.

## Compliance

Installing the package is not compliance. It records activity, signs and seals it, and verifies what it holds; it does
not decide what an application records, how long the log is kept, who may read it or its keys, how the anchor is
configured, or who answers an alert. A control framework's requirements for audit logging are met, or not, by those
decisions and by the evidence that they were followed, and the limits in [the threat model](../design/threat-model.md)
hold whatever is configured.
