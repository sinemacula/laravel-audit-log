<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Migrations\Migration;

/**
 * Loads a migration file the package ships, as Laravel's migrator would.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait LoadsShippedMigrations
{
    /**
     * Require the shipped migration file and return its instance.
     *
     * @param  string  $path
     * @return \Illuminate\Database\Migrations\Migration
     *
     * @SuppressWarnings("php:S4833")
     * @SuppressWarnings("php:S2003")
     */
    protected function loadMigration(string $path): Migration
    {
        $migration = include $path;

        if (!$migration instanceof Migration) {
            self::fail(sprintf('%s did not return a Migration instance.', basename($path)));
        }

        return $migration;
    }
}
