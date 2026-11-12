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
 * The freshness checks of `audit-log:check --freshness`: whether sealing, the
 * sweep, verification, retention, anchoring and the outbox are still running.
 *
 * A run whose schedule is disabled is still judged by its progress, since it
 * may run elsewhere.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FreshnessChecks
{
    /** @var string The cause of a signal whose collaborator cannot be resolved, by what it is and the class of what was thrown. */
    private const string UNRESOLVED = 'the bound %s could not be resolved: %s';

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
     * A reader for each monitoring setting; each throws when it is malformed.
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
     * The retention signal, judged by the last prune; not applicable while the
     * prune can delete nothing, failed when the policy cannot be resolved.
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
        // Read first, so a malformed retention setting fails the run under
        // `config` rather than reading as a policy that cannot be resolved
        (new RetentionSettings($this->config))->retainsAnythingForLess();

        try {
            $prunes = $this->schedule->prunes();
        } catch (\Throwable $exception) {
            // Named, never reported: reporting writes to the log, and the check
            // writes nothing
            return new FreshnessSignal('retention', FreshnessSignal::FAILED, null, $limit, true, sprintf(self::UNRESOLVED, 'retention policy', $exception::class));
        }

        if (!$prunes) {
            return new FreshnessSignal('retention', FreshnessSignal::NOT_APPLICABLE, null, null, false);
        }

        $run = $this->progress->get(IntegrityProgress::RETENTION_LAST_RUN);

        return self::judged('retention', self::ageOf($run, 'at', $now), $limit, $overdue, $run !== null && ($run['status'] ?? null) === PruneStatus::FAILED->value);
    }

    /**
     * The anchoring signal, aged by the last anchored seal with no limit;
     * failed after a later failure, not applicable for the null anchor.
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
        } catch (\Throwable $exception) {
            // Sealing reports why, so the check names only the class
            return new FreshnessSignal('anchoring', FreshnessSignal::FAILED, null, null, true, sprintf(self::UNRESOLVED, 'anchor', $exception::class));
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
     * The outbox signal: the oldest unfailed row by when it was queued, which a
     * retry never moves; an empty outbox is fresh.
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
        $queued = $this->database->connection(DeliveryTables::outboxConnection())
            ->table(DeliveryTables::outboxTable())
            ->useWritePdo()
            ->whereNull('failed_at')
            ->orderBy('created_at')
            ->value('created_at');

        if (!is_string($queued)) {
            return new FreshnessSignal('outbox', FreshnessSignal::OK, null, $limit, false);
        }

        return self::judged('outbox', max(0, $now->getTimestamp() - StoredTime::instant($queued)->getTimestamp()), $limit, false, false);
    }

    /**
     * How old the log's oldest entry is, in seconds, or `null` when the log is
     * empty.
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
     * A signal judged by its age against its limit; one that never ran is a
     * problem only when overdue.
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
     * How many seconds ago the progress field's time was, never negative, or
     * `null` when there is none.
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
     * The progress field's time, or `null` when it is missing or not an instant
     * in the package's form.
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
