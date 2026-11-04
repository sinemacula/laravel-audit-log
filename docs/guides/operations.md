# Operations

Sealing, anchoring, verification and pruning run as commands, on Laravel's scheduler, beside the application, and
holds, imports, erasures, reinstatements, rewraps and reconciliation run as commands an operator starts. This guide
covers what to schedule, what to watch, where to anchor, which keys to keep, and what sealing costs. How each step
works, and what each status and finding means, is in [the integrity note](../design/integrity.md), [the lifecycle
note](../design/lifecycle.md) and [the privacy note](../design/privacy.md); retention, holds, imports and erasure are
in [the retention guide](retention.md), [the import guide](import.md) and [the privacy guide](privacy.md); what none of
it promises is in [the threat model](../design/threat-model.md).

## Schedule

The package registers four runs on Laravel's scheduler, so the scheduler itself must run: `php artisan schedule:run`
every minute from cron, or `php artisan schedule:work`. `php artisan schedule:list` shows the runs the package
registered.

| Run                                       | Setting                         | Default       | What it does                                                   |
|-------------------------------------------|---------------------------------|---------------|----------------------------------------------------------------|
| `audit-log:seal`                          | `integrity.seal.schedule`       | `*/5 * * * *` | Seals the entries recorded since the last seal, then anchors   |
| `audit-log:seal --sweep`                  | `integrity.seal.sweep_schedule` | `15 3 * * *`  | Seals whatever the recent passes missed, from a saved cursor   |
| `audit-log:verify --strict --sweep-first` | `integrity.verify.schedule`     | `45 3 * * *`  | Sweeps, then verifies the whole log and its anchoring, records |
| `audit-log:prune`                         | `retention.schedule`            | `30 3 * * *`  | Deletes the sealed entries retention no longer keeps, journals |

- The prune is registered only when it can delete something: when a category is kept for less than forever by
  `retention.after_days` or `retention.categories`, or when a `RetentionPolicy` of your own is bound. With the default
  settings everything is kept forever and `schedule:list` shows three runs. A bound policy that cannot be resolved is
  reported and the prune still registered, so the run refuses it and records that.
- Each run is started with `runInBackground()`, so a long sweep, verification or prune never holds up the application's
  own tasks due in the same minute, and `schedule:work` keeps ticking while one runs.
- Each run is registered with `withoutOverlapping()`, so a run still going when the next is due is not started twice.
  Its lock lapses well inside the run's period, after 15 minutes for sealing and 23 hours for the sweep, the
  verification and the prune, so a run killed before it released its lock (a deploy, a restart, the memory limit)
  skips at most the runs due within that time, never the next day's. `php artisan schedule:clear-cache` clears a lock a
  killed run left. A second prune started beside a first is still safe: each chunk takes the lifecycle lock, and two
  prunes never cover one member twice.
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
  Schedule::command('audit-log:prune')->dailyAt('03:30')->withoutOverlapping(1380)->runInBackground()->onOneServer();
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

The lifecycle commands are run by hand, but for the prune, which the scheduler runs. Each prints no value of an entry,
a statement or a binding, names a failure by its class, and exits 0 when it is done, 1 when it is refused or fails at
run time, and 2 for an argument or option it refuses, before anything runs. Each trusts the shell, as `audit-log:seal`
and `audit-log:verify` do: `--by-type` and `--by-id` assert the operator and prove nothing, `--reason` is a reason code
and `--reference` the ticket or case, so keep the maintenance connection's credentials to those who may run them.

| Command                           | Options                                                                                                                                                                       | What it does                                                                                          |
|-----------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------|
| `audit-log:prune`                 | `--dry-run`, `--max-seconds`, `--json`                                                                                                                                        | Prunes what retention no longer keeps; exits 1 when the run fails or skips a seal it cannot trust     |
| `audit-log:hold`                  | `--all`, `--tenant`, `--tenantless`, `--about`, `--category`, `--from`, `--to`, `--import-batch`, `--basis`, `--review-by`, `--by-type`, `--by-id`, `--reason`, `--reference` | Places a hold and prints its id                                                                       |
| `audit-log:release <hold>`        | `--by-type`, `--by-id`, `--reason`, `--reference`                                                                                                                             | Releases a hold; exits 1 for a hold that is not active                                                |
| `audit-log:holds`                 | `--rebuild`, `--json`                                                                                                                                                         | Lists the active holds from the verified journal, or rebuilds their projection                        |
| `audit-log:import [file]`         | `--source`, `--region`, `--from-export`, `--dry-run`, `--hold`, `--hold-basis`, `--close`, `--by-type`, `--by-id`, `--reason`, `--reference`, `--json`                        | Imports a file of another system's records as a batch, or closes a batch left running                 |
| `audit-log:reconcile`             | `--since`, `--json`                                                                                                                                                           | Writes the lifecycle records the journal says are missing, looking back `--since` days                |
| `audit-log:erase [type] [id]`     | `--by-type`, `--by-id`, `--reason`, `--reference`, `--partial`, `--pending`, `--reapply`                                                                                      | Erases an owner by destroying its keys, or with `--reapply` every owner a file names after a restore  |
| `audit-log:reinstate <type> <id>` | `--by-type`, `--by-id`, `--reason`, `--reference`                                                                                                                             | Reinstates an erased owner, so keys may be created for it again above its floor                       |
| `audit-log:rewrap`                | `--by-type`, `--by-id`, `--reason`, `--reference`, `--rotate`, `--dry-run`                                                                                                    | Rewraps every owner's key onto the current wrapping key, and with `--rotate` supersedes the live ones |
| `audit-log:keys`                  | `--rebuild-uses`, `--dry-run`                                                                                                                                                 | Adds the key uses missing from the entries whose HMAC verifies, and never removes one                 |

- `audit-log:prune --dry-run` takes no lock and writes nothing, and `--max-seconds`, from 60 to 86400, overrides
  `retention.max_seconds`. A run that stops on its time budget ends `partial` and the next resumes after it.
- `audit-log:replay` replays a spill file behind the lifecycle lock, so it uses the maintenance connection a prune
  uses and waits for a prune in progress.
- `audit-log:reconcile` is never scheduled: run it by hand, one at a time, after a lifecycle command warned that its
  record could not be written. `--since` is 1 to 3650 days, 7 by default.
- `audit-log:import --close=<batch>` brings a batch a dead import left `running` to its end, `interrupted` unless its
  finish was journalled; `audit-log:check` notes such a batch once it has not been written for an hour.
- `audit-log:erase` is all or nothing: a key a hold or preservation blocks refuses it, unless `--partial` destroys the
  keys nothing blocks and keeps the rest, and outbox rows older than the erasure refuse it, unless `--pending` accepts
  that their fields are erased with the keys. It prints the owner's keyed fingerprint, never the owner, and exits 0 for
  `complete`, `partial` and `already_erased`. `--reapply=<file>` takes no owner, `--partial` or `--pending`: after a
  restore it erases each owner the file names in part, accepting pending deliveries, and exits 0 only once the restore
  is journalled reconciled, which `audit-log:check` waits for.
- `audit-log:reinstate` creates no key: the owner's next write opens the generation above the erasure's floor.
- `audit-log:rewrap` runs in batches of `privacy.rewrap_batch`, each journalled, and the batches a failed run committed
  stand; `--dry-run` reads and unwraps what it would rewrap and writes nothing, and `--rotate` supersedes every live key
  so each unit opens its next generation on its next write.
- `audit-log:keys --rebuild-uses` takes no authority and journals nothing, since key uses are derived from the signed
  entries; `audit-log:verify` reports a key use still missing as `key_use_missing`.

## Monitor

A failure raises an alarm; a run that does not happen raises none. Wire `php artisan audit-log:check --freshness` into
cron or an uptime monitor: it is the one command that finds a scheduled run that stopped. Run it from outside Laravel's
scheduler, every few minutes, since a scheduler that stopped would stop it too. It is separate from the deploy-time
check, so a deploy never fails because a scheduled run is late.

```bash
*/5 * * * * cd /srv/app && php artisan audit-log:check --freshness
```

With `--freshness`, `audit-log:check` runs only these signals, and exits 1 when any is a problem and 0 otherwise. It
reads the progress below and, in outbox mode, the outbox's oldest row not failed, a fixed number of reads whatever the tables
hold, and writes nothing.

| Signal         | Reads                                | A problem when                                                                                   | Limit                          |
|----------------|--------------------------------------|--------------------------------------------------------------------------------------------------|--------------------------------|
| `sealing`      | `seal.last_run`                      | It is older than the limit                                                                       | `monitor.seal_minutes` (30)    |
| `sweep`        | `sweep.completed`                    | It is older than the limit                                                                       | `monitor.daily_minutes` (1560) |
| `verification` | `verify.last_full`                   | It is older than the limit, or `passed` is false                                                 | `monitor.daily_minutes` (1560) |
| `retention`    | `retention.last_run`                 | Retention is configured and it is older than the limit, or its `status` is `failed`              | `monitor.daily_minutes` (1560) |
| `anchoring`    | `anchor.last`, `anchor.last_failure` | An anchor is configured and `anchor.last_failure` is newer than `anchor.last`                    | none                           |
| `outbox`       | the outbox table                     | The delivery mode is `outbox` and the oldest row not failed was queued longer ago than the limit | `monitor.outbox_minutes` (15)  |

- Each signal prints one line, its status and, where it has them, its age and its limit in seconds, such as
  `[freshness] sealing: ok (age 120s, limit 1800s)`. The status is `ok`, `stale` (older than its limit), `failed` (the
  run recorded a failure), `never_run` (nothing recorded yet) or `not_applicable`: retention while nothing is kept for
  less than forever and no policy of your own is bound, anchoring while the anchor is `null`, and the outbox in `sync`
  mode. `--json` writes each signal as one JSON object instead, of exactly `signal`, `status`, `age_seconds` and
  `limit_seconds`, `null` where the signal has none.
- `never_run` is a problem only when that run's schedule is set and the oldest entry in the log is older than the
  signal's limit, so a fresh install is not stale. A run whose schedule is `null` or empty is still checked against
  what it recorded: you run that command elsewhere, and this is how you find out that it stopped.
- `monitor.seal_minutes` is 5 to 1440, `monitor.daily_minutes` 60 to 10080 and `monitor.outbox_minutes` 1 to 1440,
  each in minutes. A malformed one fails the freshness run, named under `[config]`, and the ordinary `audit-log:check`
  reports it too. Progress that cannot be read fails the run, named by the class of what was thrown.
- The outbox's age is when its oldest row not failed was queued (`created_at`), which a retry never moves, so a row
  that keeps failing and retrying ages until it is delivered or fails for good. It is read through the outbox's index
  on `failed_at` and `created_at`.
- A retention policy or an anchor that cannot be resolved makes its signal `failed`, naming the class of what was
  thrown on its line. The check reports nothing to the exception handler, since that would write to the log.

Route these to alerting as well:

- Each of these dispatches `IntegrityCheckFailed` and reports an `IntegrityCheckFailedException`: a verification that
  fails or stops, and, in sealing, a refused head, an entry that cannot be sealed, an anchor conflict or a refused seal.
  Any other failure that stops sealing or anchoring, a malformed anchor setting among them, is reported as a
  `SealFailedException` naming its class, and sealing still runs when only anchoring cannot. Route the package's
  reports where someone answers them; [the events guide](events.md) shows a listener. A listener that fails is reported
  as it threw, and the alarm is still reported after it.
- An unavailable anchor only warns: the class of its failure is kept on the seal and in `anchor.last_failure`, and the
  next run tries again. Only a strict verification fails on it.
- Nothing alarms on a run that does not happen: a missed scheduled run raises nothing, since a stopped scheduler, a
  server that is down or a cron line that was lost dispatches no event and reports nothing. So run
  `audit-log:check --freshness`, or read the progress the package records, and alert when it goes stale.
- A lifecycle operation whose activity record cannot be written stays committed: its result says `recorded: false`,
  its command warns, and the failure is reported as a `LifecycleRecordFailedException` naming its class. Run
  `audit-log:reconcile` then, which writes the missing records from the journal.
- A prune refused on a broken journal ends `failed` with `journal_broken`, and `audit-log:verify` reports the journal's
  finding and fails. Every run of `audit-log:verify` verifies the whole lifecycle journal and prints its line.

The progress is in `integrity.state_table` (`audit_log_integrity_state` by default), one row per name, with the time it
was written in `updated_at`. It is operational, never evidence: a monitor may read it, and nothing it says changes what
verification finds.

```sql
SELECT name, value, updated_at FROM audit_log_integrity_state ORDER BY name;
```

| Name                  | Written                                        | Value                                         | Stale means                                                        |
|-----------------------|------------------------------------------------|-----------------------------------------------|--------------------------------------------------------------------|
| `seal.last_run`       | When a seal run ends without a failure         | `at`, `seals`, `entries`, `sweep`             | Older than a few seal intervals: the scheduler or sealing stopped  |
| `seal.last`           | After each seal commits                        | `sequence`, `id`, `sealed_at`                 | Old while entries are being recorded: nothing is being sealed      |
| `seal.recent`         | After a recent pass's seal moves it on         | `last_recorded_at`                            | Old while entries are being recorded: the recent pass stopped      |
| `sweep.cursor`        | After each window of an unfinished sweep       | `recorded_at`, `id`, `from_its_time`          | Present for days: the sweep keeps stopping before its end          |
| `sweep.completed`     | When a sweep reaches the end of the table      | `at`                                          | Older than a day and a sweep's length: the sweep is overdue        |
| `anchor.last`         | After a pass that anchored a seal              | `sequence`, `anchor`, `anchored_at`           | Behind `seal.last`: anchoring lags sealing                         |
| `anchor.last_failure` | When anchoring fails                           | `sequence`, `class`, `at`                     | Newer than `anchor.last`: the anchor is down                       |
| `verify.last_full`    | When a complete verification ends              | `at`, `head`, `passed`, `strict`              | Older than a day, or `passed` false: the verification did not pass |
| `retention.last_run`  | When a prune run ends, unless it was a dry run | `at`, `run_id`, `status`, `deleted`, `cursor` | Older than a day: the scheduled prune has not finished a run since |

- `verify.last_full` records whether the run passed at the strictness it ran at, and that strictness in `strict`: the
  scheduled run is strict, so a run that failed only on its anchoring records `passed` false with `strict` true. A
  monitor should alert on a stale row and on `passed` false alike.
- `seal.recent` is where the recent pass reads from, less the lookback: the latest entry time a recent pass sealed,
  which only a recent pass moves forward, so a sweep's seal of old rows never pulls the recent pass back to them.
- `retention.last_run` is written by every prune that is not a dry run, a failed one included, with its `status`:
  `complete`, `partial` or `failed`. A stale row means the scheduled prune has not finished a run since; a `partial`
  one is normal while holds or undelivered records keep entries, and a run that stopped on its time budget is resumed
  by the next. A prune never reads this row: where it resumes is read from the lifecycle journal.

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
- Run `php artisan audit-log:check` in the deploy pipeline: it reports a malformed integrity, retention, import or
  monitoring setting, a retention shorter than its preservation, a missing or misshapen integrity or lifecycle table, a
  missing lock row, a missing installation id, a maintenance connection that reaches another installation, a lifecycle
  journal that does not verify, holds projection drift and an anchor disk that is not configured. It notes, without
  failing, a hold whose review date has passed and an import batch left `running` for an hour. It writes nothing: the
  migrations seed the installation id, and a check only reads it.
- When the application's environment is `production`, `audit-log:check` also lists a `[production]` subject: the
  testing `FakeAuditStore` bound as the store, or as a destination of a stack, is a problem, since it keeps records in
  memory and loses them. A seal, sweep or verification schedule set to `null` or empty is a `[production] note:`,
  which does not fail the run, saying to run that command elsewhere and watch it with `--freshness`.

**Clocks.** Recording servers and the database must run NTP. The package records time from the application's clock,
and verification reports an entry recorded far ahead of its own clock as `future_unsealed`, so a server whose clock
runs ahead shows up there.

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

| Key                    | Protects                                                                       | Keep it                                          |
|------------------------|--------------------------------------------------------------------------------|--------------------------------------------------|
| `app.key` for records  | The outbox and the members of bulk and disclosure manifests                    | Until no row needs decrypting                    |
| Owners' data keys      | Each owner's encrypted fields, one key per unit and generation                 | Until the owner is erased; destroying one erases |
| Wrapping keys          | Every owner's data key, wrapped (`privacy.keys`, or derived from `app.key`)    | Until `audit-log:rewrap` has rewrapped every key |
| Row-HMAC keys          | Each entry's `hmac`, and an imported row's `source_digest`, under its `key_id` | As long as the entries they signed               |
| Seal-verification keys | Each seal's `signature`, under its `key_id`                                    | As long as the seals, which pruning keeps        |
| Journal keys           | Each lifecycle journal row's `hmac`, under its `key_id`                        | As long as the journal, which nothing prunes     |
| `app.key` for exports  | An export artifact's members, which `audit-log:export --verify` reads          | As long as an export's verification is promised  |

- These are separate lifetimes, though one ring key may serve as both a row-HMAC and a seal-verification key: an
  encryption key may be retired or destroyed on its own schedule, while a ring key is kept for as long as a seal names
  it, which is as long as the log is kept. An owner's key row is signed under the ring too, so a ring key also lives as
  long as a key row names it.
- An owner's data keys are stored only wrapped. Erasure destroys them, so their lifetime is the owner's, and nothing
  else rotates them but `audit-log:rewrap --rotate`, which supersedes every live key: a superseded key still opens what
  it sealed, and the next write of its unit opens a new generation.
- The wrapping keys are `privacy.keys`, with `privacy.current` naming the key that wraps, or without them keys derived
  from `app.key` and each of `app.previous_keys`. A derived key gives domain separation, not independence from
  `app.key`: a rotated `app.key` must stay in `app.previous_keys` until `audit-log:rewrap` has rewrapped every key it
  wrapped, and a run that ends `partial` has named the keys it could not. To rotate a wrapping key, add the new one,
  point `privacy.current` at it, run `audit-log:rewrap`, and drop the old one only once a run ends `complete`.
- To move from the derived keys to `privacy.keys`, set both `privacy.keys` and `privacy.current`, leave `app.key` and
  `app.previous_keys` in place, and run `audit-log:rewrap`. An explicit ring keeps the keys derived from `app.key` and
  `app.previous_keys` to unwrap only, never to wrap, so the existing keys still open and the rewrap moves them onto
  `privacy.current`. Once a run ends `complete`, a later rotation of `app.key` reaches none of them.
  `audit-log:check` reports any live or superseded key wrapped under a key the ring no longer holds.
- A wrapping key backed up with the database restores what an erasure destroyed. Keep the wrapping keys out of the
  database's backups, or bind a `Contracts\KeyWrapper` over a key service whose keys an erasure can reach.
- A retired `app.key` must stay in `app.previous_keys` for as long as the artifacts sealed under it are kept, or their
  manifests can no longer be read and `audit-log:verify` reports them `manifest_unreadable`, though their entries still
  verify.
- Export artifacts need `app.key` kept, or listed in `app.previous_keys`, for as long as their verification is
  promised. An `audit_log.trail_exported` entry and its artifact are never pruned, so the database keeps them, but the
  artifact's members are encrypted under `app.key`, and a key dropped from both leaves the export unverifiable.
- The journal's key and an import's source-digest key are derived from the ring key a row names, each under its own
  info string, so keeping that ring key keeps them. A source digest under a key the ring no longer holds cannot be
  compared, and a re-import of its line is then counted a conflict, never a duplicate.
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
triggers for each engine, as SQL that its tests run as written. Run both of your engine's grant blocks, the key block
after the other: verification reads the owners' key tables while the package's key store is in use, so a user granted
the first block alone cannot verify.

- The application's user inserts and selects entries, artifacts, seals and members, may update only a seal's four
  anchor columns, and needs `SELECT`, `INSERT`, `UPDATE` and `DELETE` on the integrity state table; it is granted no
  DDL.
- The maintenance user, `storage.maintenance_connection`'s, is the only one that may delete an entry, its artifact or
  its receipts, since pruning deletes them together and keeps every seal and member. It also inserts the lifecycle
  journal and never updates or deletes a row of it, inserts and deletes the holds projection, and updates the lock row;
  the application's user only reads the journal and the holds.
- The application's user inserts owners' keys, on a session of its own, and key uses, and never updates a key; the
  maintenance user updates a key's state, wrapped key, wrapping key and erasure, for an erasure or a rewrap, and
  inserts the owner markers, all inside its journalled transactions.
- The maintenance credentials can still delete rows outside the package, and the journal and the seals make that
  detectable, not impossible: keep them to whoever may prune, hold, release, erase, reinstate and rewrap.
- Run `audit-log:verify` as a user that can read the tables, the key tables included, and write the integrity state
  table.
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

## Scale

- A single entries table, with the indexes the migrations create, handles tens of millions of rows comfortably: every
  read the package makes, from the trail to sealing, the sweep and verification, pages through an index in batches.
- Batched pruning keeps it that size: `audit-log:prune` deletes in chunks of `retention.batch`, each its own
  transaction, so retention holds the table to the entries it must keep without one long lock.
- For hundreds of millions of rows, or for analytics, stream entries to a warehouse or SIEM through a delivery
  destination, such as a destination of a stack store or the outbox's drain, and keep a shorter retention in the
  database.
- Partitioning is not supported. The entries table's primary key is `id` alone, and partitioning the table yourself is
  not supported: an engine that partitions needs the partition key in every unique key, which would break the
  uniqueness of `id`, and the seals assume one table in which every entry is found by its id.

## Compliance

Installing the package is not compliance. It records activity, signs and seals it, and verifies what it holds; it does
not decide what an application records, how long the log is kept, who may read it or its keys, how the anchor is
configured, or who answers an alert. A control framework's requirements for audit logging are met, or not, by those
decisions and by the evidence that they were followed, and the limits in [the threat model](../design/threat-model.md)
hold whatever is configured.
