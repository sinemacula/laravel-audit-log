# Retention

Entries are kept forever until a retention policy says otherwise. A prune then deletes, entry by entry, what the policy
no longer keeps, leaving what a hold keeps, what has not been sealed and what has not been delivered, and journals every
deletion so `audit-log:verify` can account for it. This guide covers configuring retention, writing a policy of your
own, preservation, holds, prune runs and what verification says afterwards.

Two guarantees are stated apart here, as everywhere in the package. Whoever holds the database credentials can still
delete or change rows: a hold, a prune and the lifecycle journal never stop that. What the package's cryptographic
evidence does is make a deletion it did not journal detectable: the seals and the journal let `audit-log:verify` tell
an entry pruned under a signed record from one that went missing.

## Retention by category

The package binds `Lifecycle\ConfiguredRetentionPolicy`, which reads the `retention.*` settings. Nothing is pruned by
default: `retention.after_days` is `0`, forever.

```php
// config/audit-log.php
'retention' => [
    'after_days' => 365,
    'categories' => [
        'security'          => 730,
        'access_management' => 1095,
        'audit'             => 0,
    ],
    'preserve'   => [
        'security' => 365,
    ],
],
```

| Setting                 | Default      | What it says                                                                     |
|-------------------------|--------------|----------------------------------------------------------------------------------|
| `retention.after_days`  | `0`          | Days an entry of a category not listed is kept, 0 to 36500; `0` keeps it forever |
| `retention.categories`  | `[]`         | Days each category is kept, 0 to 36500, `0` forever, over `after_days`           |
| `retention.preserve`    | `[]`         | Days each category must stay readable, 0 to 36500, `0` forever                   |
| `retention.batch`       | `1000`       | Entries deleted in one transaction, 100 to 10000                                 |
| `retention.max_seconds` | `3000`       | The time budget of a run, 60 to 86400 seconds                                    |
| `retention.schedule`    | `30 3 * * *` | When the scheduler runs `audit-log:prune`; `null` or empty for never             |

- Retention is counted back from the UTC midnight of the day a run starts: an entry is past retention when it occurred
  strictly before that midnight less the category's days. One cut-off holds for each category and tenant for the whole
  run, so a run that crosses midnight decides alike from its first seal to its last.
- A malformed setting prunes nothing: the run is refused before it deletes anything, and `php artisan audit-log:check`
  names the setting.
- `audit_log.trail_exported` is never pruned, whatever its category's retention, so an export can still be verified
  while the database and its keys live. Every other code, the package's own included, follows its category's
  retention.
- The configured policy's version is `config:` and the first 16 hex characters of the SHA-256 of its settings, so the
  journal records a new policy row whenever the settings change, and never when only the keys rotate.

## A policy of your own

Bind `Contracts\RetentionPolicy` for retention the configuration cannot express, such as a period per tenant:

```php
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Records\Reference;

final class ContractedRetention implements RetentionPolicy
{
    public function version(): string
    {
        return 'contracts:2026-11';
    }

    public function retainFor(string $category, ?Reference $tenant): ?int
    {
        return $tenant === null ? 365 : Contract::forTenant($tenant)->retentionDays($category);
    }

    public function preserveFor(string $category, ?Reference $tenant): ?int
    {
        return $category === 'security' ? 365 : null;
    }
}
```

```php
// AppServiceProvider::register()
$this->app->singleton(RetentionPolicy::class, ContractedRetention::class);
```

- `version()` is 1 to 64 characters of clean text, and must change whenever any answer could, so the journal records
  every policy a run ran under.
- `retainFor()` answers 1 to 36500 days, or `null` to keep forever. A run asks once per category and tenant pair it
  meets, and freezes the answer for the rest of the run; an entry of no tenant is asked with a `null` tenant.
- A policy keeps no state and never reads the entries table. Whatever it throws, or an answer out of range, stops the
  run, which ends `failed` with `policy_failed`; the chunks it committed stand.
- With a policy of your own bound, the scheduler runs `audit-log:prune` whatever the settings say.

## Preservation

Preservation is how long an entry must stay readable, whatever retention allows. `retention.preserve` sets it per
category, `0` meaning forever, and `preserveFor()` answers it for a policy of your own, `PHP_INT_MAX` meaning forever
and `null` meaning nothing obliges the package to keep the entry.

A retention shorter than its preservation is refused, never quietly lengthened. The configured policy is checked before
any run, so a category kept for 30 days and preserved for 90 prunes nothing until one of them changes. A policy of your
own is checked as each pair is first met, and a conflict there stops the run, which ends `failed` with
`configuration_refused`.

## Holds

A hold keeps every entry its scope matches from being pruned until it is released. It is journalled, signed and sealed,
and every decision a prune or a release makes is read from the verified journal, never from the `audit_log_holds`
projection, which only lists holds for `audit-log:holds` and `audit-log:check`.

```php
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Records\Reference;

$scope = HoldScope::tenants(Reference::to($organisation))
    ->categories('security', 'access_management')
    ->occurredBetween(now()->subYear(), null);

$result = AuditLog::lifecycle()->hold(
    $scope,
    new Authority(Reference::to($user), 'case.review', 'app:ticket-123'),
    HoldBasis::LEGAL_CLAIM,
    reviewBy: now()->addMonths(6),
);

AuditLog::lifecycle()->release($result->hold->id, new Authority(Reference::to($user), 'case.closed'));
```

- A scope starts from `HoldScope::all()`, `HoldScope::tenants()` or `HoldScope::tenantless()`, the entries of no
  tenant, and is narrowed by `withTenantless()`, `about()`, the activity of references as actor or subject,
  `categories()`, `occurredBetween()` and `importBatch()`. Each dimension is ANDed with the others, at most 100 tenants,
  100 references and 50 categories are held, and an empty or self-contradicting scope is refused.
- A tenant's hold never keeps an entry of no tenant unless the scope adds them, and a window keeps an entry whose time
  cannot be read, so a hold never lets go of an entry it cannot place.
- The basis is one of `legal_claim`, `regulatory`, `investigation` or `other`. The package records it and the review
  date and decides nothing from either: `audit-log:check` notes a hold whose review date has passed, and nothing
  releases it but a release.
- `AuditLog::lifecycle()->holds()` lists the active holds from the verified journal, and
  `AuditLog::lifecycle()->rebuildHolds()` rebuilds the projection from it.
- Releasing a hold that is not active, never placed or released already, throws an `UnknownHoldException`, is recorded
  `denied` with `unknown_hold`, and writes nothing.
- The package authorises none of this. The authority is whoever the caller says it is: check the operator's right to
  hold or release before calling.

The same from the shell:

```bash
php artisan audit-log:hold --tenant=organisation:org_01 --tenantless --category=security --from=2026-01-01 \
    --basis=legal_claim --review-by=2027-05-01 --by-type=App\\Models\\User --by-id=7 --reason=case.review \
    --reference=app:ticket-123
php artisan audit-log:holds
php artisan audit-log:release 01932b4e-d000-7000-8000-000000000001 --by-type=App\\Models\\User --by-id=7 \
    --reason=case.closed
```

- `audit-log:hold` starts the scope from exactly one of `--all`, `--tenant` or `--tenantless`; `--tenant`, which may be
  repeated, takes `--tenantless` too, to add the entries of no tenant. `--about` (repeatable, `type:id`), `--category`
  (repeatable), `--from`, `--to` and `--import-batch` narrow it. `--basis` is required; `--review-by`, `--from` and
  `--to` take an ISO-8601 time with `Z` or an offset, or a `Y-m-d` date at UTC midnight. It prints the hold's id.
- `audit-log:release` takes the hold's id, and exits 1 for a hold that is not active.
- `audit-log:holds` lists each active hold by its id, basis, placement, review date, scope digest and dimensions,
  counting the tenants and references a scope names rather than printing them; `--json` writes one JSON object, and
  `--rebuild` rebuilds the projection and prints how many holds it holds.
- Every command trusts the shell, as `audit-log:seal`, `audit-log:verify` and `audit-log:replay` do: `--by-type` and
  `--by-id` assert the operator, `--reason` is a reason code and `--reference` the ticket or case, and none of them
  proves who ran the command. The boundary is the maintenance connection's credentials. Each exits 0 when it is done, 1
  when it is refused or fails at run time, naming the failure by its class, and 2 for an argument or option it refuses,
  before anything runs.

## Prune runs

`audit-log:prune` runs on Laravel's scheduler at `retention.schedule`, by default `30 3 * * *`, in the background and
without overlapping, but only when a category is kept for less than forever or a policy of your own is bound; with
everything kept forever it is not registered at all. It can be run by hand, or through `AuditLog::lifecycle()->prune()`:

```bash
php artisan audit-log:prune --dry-run
php artisan audit-log:prune --max-seconds=600 --json
```

- A run walks the seals, oldest first, from where the last run stopped up to the latest seal when it started, and
  deletes in chunks of `retention.batch`, each in a transaction of its own behind the lifecycle lock. Entries that have
  not been sealed yet are left to a later run.
- Before deleting, a chunk reads its candidates again under the lock, checks each row's signature and its membership of
  the seal, and decides again from the verified row. A seal or a candidate that fails is skipped and named, and the run
  ends `partial` and exits 1.
- An entry an active hold matches is kept. So is an entry with an outbox row or a receipt not yet delivered, a failed
  delivery included, until it is delivered or replayed; the run then ends `partial`.
- `--max-seconds`, from 60 to 86400, or `retention.max_seconds`, is the run's time budget, checked between chunks. A run
  that stops on its budget before its last seal ends `partial`, and the next run resumes after its cursor. After any
  other run the next starts again from the first seal, so an entry a released hold or a finished delivery frees is
  reached.
- `--dry-run` takes no lock and writes nothing: it counts what would be deleted per category and tenant pair and per
  seal, counting held entries as a run would. It is a plan, not a promise. The command names each pair's tenant by the
  first 12 hexadecimal characters of the SHA-256 of its canonical `["type","id"]`, never by the reference itself, as
  `audit-log:holds` never prints one; `PruneResult::$plan` holds the references. `--json` writes the result as one JSON
  object.

A run ends with one of three statuses:

| Status     | Meaning                                                                                              |
|------------|------------------------------------------------------------------------------------------------------|
| `complete` | Every seal to the boundary was walked and every entry found past retention was deleted               |
| `partial`  | The run stopped on its time budget, skipped a seal, or kept an entry that is held or awaits delivery |
| `failed`   | The run stopped on `policy_failed`, `configuration_refused`, `journal_broken` or `prune_failed`      |

The `PruneResult` a run returns carries its run id (`operationId`), `status` and `failure`, the `policyVersion`, the
entries `deleted`, the `seals` they were deleted from, the entries `held` and `pendingDelivery`, the `skippedSeals` and
their ids, the `cursor` and the seals `remaining`, the deletions per category (`categories`, the 50 largest named and
the rest summed under `_other`) and the number of tenants affected, and whether it `committed` and was `recorded`. The
run journals a `policy` row when its policy's version is new, a `prune_run` row as it starts and another as it finishes,
and a `prune` row for every chunk, holding the signed prune record of exactly the entries that chunk deleted. Each run
is recorded as `audit_log.pruned`, by no one, after its finish row commits.

## After a prune

`audit-log:verify` reads the journal with the seals. A member of a seal that is gone and that a valid prune record
covers is `pruned`, and the seal still verifies; a member gone with no record covering it is missing, as before. A
member a valid prune record covers that is present again is `resurrected`, an incomplete finding: a record an
application stores again by hand through `AuditStore::store()` is not refused, and verification reports it. The outbox
drain and `audit-log:replay` never store a pruned record again: they find it among the sealed members and complete it
as pruned.

Every lifecycle operation writes its activity record after it commits: `audit_log.held`, `audit_log.released`,
`audit_log.pruned` and `audit_log.imported`. A record that cannot be written never undoes the operation: it is
reported, the result says `recorded: false`, and the command warns. `audit-log:reconcile` then writes, from the
journal, every record still missing for the operations journalled within the days `--since` looks back, 7 by default
and up to 3650, and skips those already recorded, stored or still waiting in the outbox. A record's id is derived from
its code and its operation, so however often it is written, by the operation or by reconciliation, it is stored once:

```bash
php artisan audit-log:reconcile --since=30
```

It is never scheduled. Run it by hand, one at a time, after a command warned; `--json` writes its counts as one JSON
object, and it exits 1 when an operation's journal rows do not verify. `AuditLog::lifecycle()->reconcile()` does the
same from code.
