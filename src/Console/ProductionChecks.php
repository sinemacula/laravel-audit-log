<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\AuditLog\Delivery\StoreCapabilities;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;

/**
 * The production checks of `audit-log:check`: the testing fake store bound in
 * production, and notes on disabled seal, sweep and verification schedules.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ProductionChecks
{
    /** @var string The environment the checks are made in. */
    public const string ENVIRONMENT = 'production';

    /** @var string The problem of the fake bound as the store, or as a destination of a stack, by the destination's id: `store` for the store itself. */
    private const string FAKE_STORE = 'The testing fake store is bound as the destination [%s], which keeps records in memory and loses them; bind a real store.';

    /** @var string The problem of a store that cannot be resolved, by the class of what was thrown. */
    private const string UNRESOLVED_STORE = 'The bound store could not be resolved (%s).';

    /** @var string The note on a disabled schedule, by its setting and the command it would schedule. */
    private const string UNSCHEDULED = '`%s` is disabled, so the package does not schedule `%s`; run it elsewhere and monitor it with'
        . ' `audit-log:check --freshness`.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $application
     * @param  \Illuminate\Config\Repository  $config
     * @param  \SineMacula\Laravel\AuditLog\Delivery\StoreCapabilities  $capabilities
     */
    public function __construct(

        /** The application whose environment decides whether the checks are made. */
        private Application $application,

        /** The configuration the schedules are read from. */
        private ConfigRepository $config,

        /** What the bound store says of itself, and of its destinations. */
        private StoreCapabilities $capabilities,
    ) {}

    /**
     * The production subject's checks in production; otherwise none.
     *
     * @return array<string, list<\Closure(): list<string>>>
     */
    public function subject(): array
    {
        return $this->isProduction() ? ['production' => [$this->problems(...)]] : [];
    }

    /**
     * Every production problem: the testing fake store bound as the store or a
     * stack destination, by its id, or a store that cannot be resolved.
     *
     * @return list<string>
     */
    public function problems(): array
    {
        try {
            $destinations = $this->capabilities->destinationClasses();
        } catch (\Throwable $exception) {
            return [sprintf(self::UNRESOLVED_STORE, $exception::class)];
        }

        $fakes = array_keys($destinations, FakeAuditStore::class, true);

        return array_map(static fn (string $id): string => sprintf(self::FAKE_STORE, $id), $fakes);
    }

    /**
     * The note on each disabled seal, sweep or verification schedule, in
     * production; a malformed one is left to `config`.
     *
     * @return list<string>
     */
    public function notes(): array
    {
        if (!$this->isProduction()) {
            return [];
        }

        $seals     = new SealSettings($this->config);
        $notes     = [];
        $schedules = [
            'integrity.seal.schedule'       => [$seals->sealSchedule(...), 'audit-log:seal'],
            'integrity.seal.sweep_schedule' => [$seals->sweepSchedule(...), 'audit-log:seal --sweep'],
            'integrity.verify.schedule'     => [$seals->verifySchedule(...), 'audit-log:verify --strict --sweep-first'],
        ];

        foreach ($schedules as $setting => [$schedule, $command]) {

            try {
                $disabled = $schedule() === null;
            } catch (\InvalidArgumentException) {
                // The malformed schedule is listed under `config`
                continue;
            }

            if (!$disabled) {
                continue;
            }

            $notes[] = sprintf(self::UNSCHEDULED, 'audit-log.' . $setting, $command);
        }

        return $notes;
    }

    /**
     * Whether the application's environment is production.
     *
     * @return bool
     */
    private function isProduction(): bool
    {
        return $this->application->environment(self::ENVIRONMENT);
    }
}
