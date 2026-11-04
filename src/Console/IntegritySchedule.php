<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Console\Scheduling\CacheEventMutex;
use Illuminate\Console\Scheduling\Event;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\RetentionSettings;

/**
 * The runs the package schedules: sealing (`audit-log:seal`, every five minutes
 * by default), the sweep (`audit-log:seal --sweep`, daily), a full, strict
 * verification that sweeps first (`audit-log:verify --strict --sweep-first`,
 * daily) and the prune (`audit-log:prune`, daily), each when its schedule
 * setting gives a cron expression.
 *
 * The prune is scheduled only when it can delete something: when the bound
 * retention policy is not the configured one, whose answers the schedule cannot
 * know, or when the configured one keeps anything for less than forever. A
 * policy left unbound counts as the configured one. A bound policy that cannot
 * be resolved is reported and the prune is still scheduled, so the run refuses
 * and records the failure rather than retention stopping without a trace.
 *
 * A schedule set to `null` or empty registers nothing for that run, so the
 * application can run the command elsewhere. A malformed schedule registers
 * nothing for that run either, and is reported, never thrown: the schedule is
 * resolved by `schedule:run`, `schedule:list` and `schedule:work`, and an
 * exception there would stop every task of the application. The other runs are
 * still registered.
 *
 * Each run is started in the background, so a long sweep or verification never
 * holds up the application's tasks due in the same minute. Each is kept from
 * overlapping itself by a lock that lapses well inside its period, 15 minutes
 * for sealing and 23 hours for the daily runs, so a run killed before it
 * released its lock skips at most the runs within that time. Each runs on one
 * server only when the cache store the scheduler's locks are taken in, the one
 * `Schedule::useCache()` set from `cache.schedule_store` or the scheduler's
 * environment, or else the default store, is one every server shares.
 * Registering reads configuration, the schedule and the bound retention policy
 * alone: it issues no query and resolves no store, and each command is named by
 * its string, so no command class is resolved.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class IntegritySchedule
{
    /** @var list<string> The cache drivers every server shares, on which a run is kept to one server. */
    public const array SHARED_CACHE_DRIVERS = ['redis', 'memcached', 'database', 'dynamodb'];

    /** @var int How long a sealing run's overlap lock lasts, in minutes. */
    private const int SEAL_OVERLAP_MINUTES = 15;

    /** @var int How long a sweep's, a verification's or a prune's overlap lock lasts, in minutes: 23 hours, inside the day between runs. */
    private const int DAILY_OVERLAP_MINUTES = 1380;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSettings  $settings
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\RetentionSettings  $retention
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Config\Repository  $config
     * @param  \Illuminate\Contracts\Debug\ExceptionHandler  $handler
     */
    public function __construct(

        /** The sealing settings the integrity runs' schedules are read from. */
        private SealSettings $settings,

        /** The retention settings the prune's schedule is read from. */
        private RetentionSettings $retention,

        /** The container the bound retention policy is resolved from. */
        private Container $container,

        /** The configuration the cache stores' drivers are read from. */
        private ConfigRepository $config,

        /** The handler a malformed schedule, or a policy that cannot be resolved, is reported to. */
        private ExceptionHandler $handler,
    ) {}

    /**
     * Register sealing, the sweep, the strict verification and the prune on the
     * schedule, each when its setting gives a cron expression, and the prune
     * only when it can delete something.
     *
     * @param  \Illuminate\Console\Scheduling\Schedule  $schedule
     * @return void
     */
    public function register(Schedule $schedule): void
    {
        $this->add($schedule, 'audit-log:seal', $this->settings->sealSchedule(...), self::SEAL_OVERLAP_MINUTES);
        $this->add($schedule, 'audit-log:seal --sweep', $this->settings->sweepSchedule(...), self::DAILY_OVERLAP_MINUTES);
        $this->add($schedule, 'audit-log:verify --strict --sweep-first', $this->settings->verifySchedule(...), self::DAILY_OVERLAP_MINUTES);
        $this->add($schedule, 'audit-log:prune', $this->pruneSchedule(...), self::DAILY_OVERLAP_MINUTES);
    }

    /**
     * When the prune runs: its setting's cron expression, or `null` when the
     * setting gives none, or when the policy is the configured one and keeps
     * everything forever.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private function pruneSchedule(): ?string
    {
        $cron = $this->retention->schedule();

        if ($cron === null || !$this->isConfiguredPolicy()) {
            return $cron;
        }

        return $this->retention->retainsAnythingForLess() ? $cron : null;
    }

    /**
     * Whether the retention policy is the one the package binds: true when no
     * policy is bound, and false for any other class or for a bound policy that
     * cannot be resolved, which is reported.
     *
     * @return bool
     */
    private function isConfiguredPolicy(): bool
    {
        if (!$this->container->bound(RetentionPolicy::class)) {
            return true;
        }

        try {
            return $this->container->make(RetentionPolicy::class) instanceof ConfiguredRetentionPolicy;
        } catch (\Throwable $exception) {
            // The prune refuses the policy itself and records the refusal; an
            // exception here would stop every task of the application
            $this->handler->report($exception);

            return false;
        }
    }

    /**
     * Register one run at the expression its setting gives, in the background,
     * kept from overlapping itself and, on a shared cache, to one server;
     * nothing when the setting gives none, or when it is malformed, which is
     * reported.
     *
     * @param  \Illuminate\Console\Scheduling\Schedule  $schedule
     * @param  string  $command
     * @param  \Closure(): ?string  $expression
     * @param  int  $overlapMinutes
     * @return void
     */
    private function add(Schedule $schedule, string $command, \Closure $expression, int $overlapMinutes): void
    {
        try {
            $cron = $expression();
        } catch (\InvalidArgumentException $exception) {
            // The message names the setting and never its value
            $this->handler->report($exception);

            return;
        }

        if ($cron === null) {
            return;
        }

        $event = $schedule->command($command)->cron($cron)->withoutOverlapping($overlapMinutes)->runInBackground();

        if (!$this->isLockShared($event)) {
            return;
        }

        $event->onOneServer();
    }

    /**
     * Whether the cache store the scheduler takes the run's locks in has a
     * driver every server shares: the store its mutex was given, or the default
     * store when it was given none, read from configuration alone, so no store
     * is resolved. A mutex the cache does not back says nothing of a shared
     * store, so the run is not kept to one server.
     *
     * @param  \Illuminate\Console\Scheduling\Event  $event
     * @return bool
     */
    private function isLockShared(Event $event): bool
    {
        if (!$event->mutex instanceof CacheEventMutex) {
            return false;
        }

        $store = $event->mutex->store ?? $this->config->get('cache.default');

        if (!is_string($store)) {
            return false;
        }

        return in_array($this->config->get("cache.stores.{$store}.driver"), self::SHARED_CACHE_DRIVERS, true);
    }
}
