<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Recorder;

/**
 * Registers event definitions as an application does at boot.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait DefinesEvents
{
    /**
     * Register the definitions as the only ones, as an application does at
     * boot.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  ...$definitions
     * @return void
     */
    protected static function define(EventDefinition ...$definitions): void
    {
        $catalogue = new EventCatalogue;

        foreach ($definitions as $definition) {
            $catalogue->define($definition);
        }

        $recorder = new Recorder($catalogue, new ContributorRegistry);

        app()->instance(EventCatalogue::class, $catalogue);
        app()->instance(Recorder::class, $recorder);

        AuditLog::swap($recorder);
    }
}
