<?php

declare(strict_types = 1);

namespace Tests\Integration\Octane\Fixtures;

use Illuminate\Foundation\Application;
use Laravel\Octane\ApplicationFactory;
use Laravel\Octane\Octane;

/**
 * Octane's application factory over an application the test already booted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class BootedApplicationFactory extends ApplicationFactory
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Foundation\Application  $app
     */
    public function __construct(

        /** The booted application the worker serves. */
        private readonly Application $app,
    ) {
        parent::__construct($app->basePath());
    }

    /**
     * Return the booted application, with the worker's instances bound, warmed.
     *
     * @param  array<array-key, mixed>  $initialInstances
     * @return \Illuminate\Foundation\Application
     */
    #[\Override]
    public function createApplication(array $initialInstances = []): Application
    {
        foreach ($initialInstances as $abstract => $instance) {
            $this->app->instance((string) $abstract, $instance);
        }

        return $this->warm($this->app, Octane::defaultServicesToWarm());
    }
}
