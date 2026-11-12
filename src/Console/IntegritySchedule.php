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
 * The runs the package schedules: sealing, the sweep, a strict verification and
 * the prune, each when its schedule setting gives a cron expression.
 *
 * A malformed schedule is reported, never thrown, since `schedule:run` would
 * otherwise stop every task.
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
     * Register each run whose setting gives a cron expression, and the prune
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
     * Whether the prune can delete something: the bound policy is not the
     * configured one, or it keeps anything for less than forever.
     *
     * @return bool
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function prunes(): bool
    {
        return $this->deletesUnder($this->isConfiguredPolicy());
    }

    /**
     * The prune's cron expression, or `null` when unset or the prune can delete
     * nothing; an unresolvable policy is reported and counts as deleting.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private function pruneSchedule(): ?string
    {
        $cron = $this->retention->schedule();

        if ($cron === null) {
            return null;
        }

        try {
            $configured = $this->isConfiguredPolicy();
        } catch (\Throwable $exception) {
            // The prune refuses the policy itself and records the refusal; an
            // exception here would stop every task of the application
            $this->handler->report($exception);

            $configured = false;
        }

        return $this->deletesUnder($configured) ? $cron : null;
    }

    /**
     * Whether the prune can delete something under a policy that is, or is not,
     * the configured one.
     *
     * @param  bool  $configured
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private function deletesUnder(bool $configured): bool
    {
        return !$configured || $this->retention->retainsAnythingForLess();
    }

    /**
     * Whether the retention policy is the package's own, as it is when none is
     * bound.
     *
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function isConfiguredPolicy(): bool
    {
        if (!$this->container->bound(RetentionPolicy::class)) {
            return true;
        }

        return $this->container->make(RetentionPolicy::class) instanceof ConfiguredRetentionPolicy;
    }

    /**
     * Register one run in the background, without overlap and, on a shared
     * cache, on one server; a malformed setting registers nothing.
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
     * Whether the scheduler's lock store has a driver every server shares, read
     * from configuration so no store is resolved.
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
