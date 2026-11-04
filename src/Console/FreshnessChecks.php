<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\DatabaseManager;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityProgress;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Delivery\DeliverySettings;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\NullAnchor;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\PruneStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\RetentionSettings;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * The freshness checks of `audit-log:check --freshness`: whether the runs the
 * package records progress for are still running, read from that progress and,
 * in outbox mode, from the outbox.
 *
 * Six signals, in order: `sealing` (`seal.last_run` within
 * `monitor.seal_minutes`), `sweep` (`sweep.completed`), `verification`
 * (`verify.last_full`, failed when it did not pass) and `retention`
 * (`retention.last_run`, failed when the run failed; applicable only when the
 * prune can delete something), each within `monitor.daily_minutes`;
 * `anchoring`, failed when `anchor.last_failure` is newer than `anchor.last`,
 * applicable only when an anchor other than the null one is bound, with no
 * limit; and `outbox`, the oldest row waiting for a drain, by when it fell due,
 * within `monitor.outbox_minutes`, applicable only in outbox mode.
 *
 * A signal with no progress never ran, which is a problem only when its run is
 * scheduled and the log's oldest entry is older than its limit, so a fresh
 * install is not stale; a run whose schedule is disabled is still judged by
 * what it recorded, since it may run elsewhere. Every read is a point read by
 * name, or the first row of an index (the entries' by the time they were
 * recorded, the outbox's by when a row falls due), on the writer, so the
 * statements are fixed whatever the tables hold. The checks write nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FreshnessChecks
{
    /** @var int Seconds in a minute, the unit the limits are configured in. */
    private const int MINUTE = 60;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @param  \Illuminate\Database\DatabaseManager  $database
     * @param  \SineMacula\Laravel\AuditLog\Database\IntegrityProgress  $progress
     * @param  \SineMacula\Laravel\AuditLog\Console\IntegritySchedule  $schedule
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\AuditLog\Contracts\Clock  $clock
     */
    public function __construct(

        /** The configuration the settings are read from. */
        private ConfigRepository $config,

        /** The connections the entries and the outbox are read on. */
        private DatabaseManager $database,

        /** The progress the runs record. */
        private IntegrityProgress $progress,

        /** The schedule that says whether the prune can delete anything. */
        private IntegritySchedule $schedule,

        /** The container the anchor is resolved from on every call. */
        private Container $container,

        /** The time every age is judged at. */
        private Clock $clock,
    ) {}

    /**
     * A reader for each monitoring setting, in the order the settings are
     * listed; each throws when what it reads is malformed.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return list<\Closure(): int>
     */
    public static function readers(ConfigRepository $config): array
    {
        $monitor = new MonitorSettings($config);

        return [$monitor->sealMinutes(...), $monitor->dailyMinutes(...), $monitor->outboxMinutes(...)];
    }

    /**
     * Every signal, in order: sealing, the sweep, verification, retention,
     * anchoring and the outbox.
     *
     * @return list<\SineMacula\Laravel\AuditLog\Console\FreshnessSignal>
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    public function signals(): array
    {
        $monitor   = new MonitorSettings($this->config);
        $seals     = new SealSettings($this->config);
        $seal      = $monitor->sealMinutes()   * self::MINUTE;
        $daily     = $monitor->dailyMinutes()  * self::MINUTE;
        $outbox    = $monitor->outboxMinutes() * self::MINUTE;
        $schedules = [$seals->sealSchedule(), $seals->sweepSchedule(), $seals->verifySchedule(), (new RetentionSettings($this->config))->schedule()];
        $mode      = (new DeliverySettings($this->config))->mode();

        $now     = $this->clock->now();
        $oldest  = $this->oldestEntryAge($now);
        $overdue = static fn (?string $schedule, int $limit): bool => $schedule !== null && $oldest !== null && $oldest > $limit;
        $sealRun = $this->progress->get(IntegrityProgress::SEAL_LAST_RUN);
        $sweep   = $this->progress->get(IntegrityProgress::SWEEP_COMPLETED);
        $verify  = $this->progress->get(IntegrityProgress::VERIFY_LAST_FULL);
        $failed  = $verify !== null && ($verify['passed'] ?? null) !== true;

        return [
            self::judged('sealing', self::ageOf($sealRun, 'at', $now), $seal, $overdue($schedules[0], $seal), false),
            self::judged('sweep', self::ageOf($sweep, 'at', $now), $daily, $overdue($schedules[1], $daily), false),
            self::judged('verification', self::ageOf($verify, 'at', $now), $daily, $overdue($schedules[2], $daily), $failed),
            $this->retention($now, $daily, $overdue($schedules[3], $daily)),
            $this->anchoring($now),
            $mode === DeliveryMode::OUTBOX ? $this->outbox($now, $outbox) : new FreshnessSignal('outbox', FreshnessSignal::NOT_APPLICABLE, null, null, false),
        ];
    }

    /**
     * The retention signal: not applicable while the prune can delete nothing,
     * and otherwise judged by the last prune run, failed when that run failed.
     *
     * @param  \Carbon\CarbonImmutable  $now
     * @param  int  $limit
     * @param  bool  $overdue
     * @return \SineMacula\Laravel\AuditLog\Console\FreshnessSignal
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    private function retention(CarbonImmutable $now, int $limit, bool $overdue): FreshnessSignal
    {
        if (!$this->schedule->prunes()) {
            return new FreshnessSignal('retention', FreshnessSignal::NOT_APPLICABLE, null, null, false);
        }

        $run = $this->progress->get(IntegrityProgress::RETENTION_LAST_RUN);

        return self::judged('retention', self::ageOf($run, 'at', $now), $limit, $overdue, $run !== null && ($run['status'] ?? null) === PruneStatus::FAILED->value);
    }

    /**
     * The anchoring signal: not applicable while the bound anchor is the null
     * one, failed when the last failure to anchor is newer than the last seal
     * anchored, or when the anchor cannot be resolved, and aged by the last
     * seal anchored, with no limit.
     *
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\AuditLog\Console\FreshnessSignal
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    private function anchoring(CarbonImmutable $now): FreshnessSignal
    {
        try {
            $anchor = $this->container->make(CheckpointAnchor::class);
        } catch (\Throwable) {
            // An anchor that cannot be resolved anchors nothing; sealing
            // reports why, by the class of what was thrown
            return new FreshnessSignal('anchoring', FreshnessSignal::FAILED, null, null, true);
        }

        if ($anchor instanceof NullAnchor) {
            return new FreshnessSignal('anchoring', FreshnessSignal::NOT_APPLICABLE, null, null, false);
        }

        $last     = $this->progress->get(IntegrityProgress::ANCHOR_LAST);
        $anchored = self::instantOf($last, 'anchored_at');
        $failed   = self::instantOf($this->progress->get(IntegrityProgress::ANCHOR_LAST_FAILURE), 'at');
        $failing  = $failed !== null && ($anchored === null || $failed->greaterThan($anchored));

        $status = match (true) {
            $failing           => FreshnessSignal::FAILED,
            $anchored === null => FreshnessSignal::NEVER_RUN,
            default            => FreshnessSignal::OK,
        };

        return new FreshnessSignal('anchoring', $status, self::ageOf($last, 'anchored_at', $now), null, $failing);
    }

    /**
     * The outbox signal: the oldest row that has not failed, by when it fell
     * due, read first from the outbox's due index; an empty outbox is fresh.
     *
     * @param  \Carbon\CarbonImmutable  $now
     * @param  int  $limit
     * @return \SineMacula\Laravel\AuditLog\Console\FreshnessSignal
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    private function outbox(CarbonImmutable $now, int $limit): FreshnessSignal
    {
        $due = $this->database->connection(DeliveryTables::outboxConnection())
            ->table(DeliveryTables::outboxTable())
            ->useWritePdo()
            ->whereNull('failed_at')
            ->orderBy('available_at')
            ->value('available_at');

        if (!is_string($due)) {
            return new FreshnessSignal('outbox', FreshnessSignal::OK, null, $limit, false);
        }

        return self::judged('outbox', max(0, $now->getTimestamp() - StoredTime::instant($due)->getTimestamp()), $limit, false, false);
    }

    /**
     * How old the log's oldest entry is, in seconds, read first from the index
     * of the time entries were recorded, or `null` when the log is empty.
     *
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?int
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    private function oldestEntryAge(CarbonImmutable $now): ?int
    {
        $recorded = $this->database->connection(StorageConnection::name())
            ->table(EntrySettings::table())
            ->useWritePdo()
            ->orderBy('recorded_at')
            ->value('recorded_at');

        return is_string($recorded) ? max(0, $now->getTimestamp() - StoredTime::instant($recorded)->getTimestamp()) : null;
    }

    /**
     * A signal judged by its age against its limit: never run without an age, a
     * problem only when overdue; failed when its run says so; stale past its
     * limit; and otherwise ok.
     *
     * @param  string  $signal
     * @param  ?int  $age
     * @param  int  $limit
     * @param  bool  $overdue
     * @param  bool  $failed
     * @return \SineMacula\Laravel\AuditLog\Console\FreshnessSignal
     */
    private static function judged(string $signal, ?int $age, int $limit, bool $overdue, bool $failed): FreshnessSignal
    {
        $status = match (true) {
            $age === null => FreshnessSignal::NEVER_RUN,
            $failed       => FreshnessSignal::FAILED,
            $age > $limit => FreshnessSignal::STALE,
            default       => FreshnessSignal::OK,
        };

        return new FreshnessSignal($signal, $status, $age, $limit, $status === FreshnessSignal::NEVER_RUN ? $overdue : $status !== FreshnessSignal::OK);
    }

    /**
     * How many seconds before now the time under the field of the progress was,
     * never less than none, or `null` when there is no such time.
     *
     * @param  ?array<string, scalar|null>  $progress
     * @param  string  $field
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?int
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    private static function ageOf(?array $progress, string $field, CarbonImmutable $now): ?int
    {
        $instant = self::instantOf($progress, $field);

        return $instant === null ? null : max(0, $now->getTimestamp() - $instant->getTimestamp());
    }

    /**
     * The time under the field of the progress, or `null` when the progress or
     * the field is missing or is not an instant in the package's form.
     *
     * @param  ?array<string, scalar|null>  $progress
     * @param  string  $field
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    private static function instantOf(?array $progress, string $field): ?CarbonImmutable
    {
        $at = $progress[$field] ?? null;

        return is_string($at) && StoredTime::isInstant($at) ? StoredTime::instant(StoredTime::toStorage($at)) : null;
    }
}
