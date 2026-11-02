<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Database;

use Illuminate\Database\Schema\Builder;

/**
 * Migration collision guard.
 *
 * Helper for the shipped migration. Surfaces a clear error before any schema
 * mutation if the table the migration creates already exists, naming the
 * configuration key that renames it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class MigrationCollisionGuard
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\Schema\Builder  $schema
     */
    public function __construct(

        /** Schema builder */
        private Builder $schema,
    ) {}

    /**
     * Throw if the table already exists. The configuration key is the one,
     * under `audit-log`, that names the table.
     *
     * @param  string  $table
     * @param  string  $configKey
     * @return void
     *
     * @throws \SineMacula\Laravel\AuditLog\Database\TableAlreadyExistsException
     */
    public function ensureNotExists(string $table, string $configKey): void
    {
        if (!$this->schema->hasTable($table)) {
            return;
        }

        $connection = $this->schema->getConnection()->getName() ?? 'default';

        $message = sprintf(
            'Cannot install the laravel-audit-log migration for the \'%s\' table: a table with that name already exists on connection \'%s\'.'
            . ' Set `%s` in config/audit-log.php to a different name and re-run the migration.',
            $table,
            $connection,
            $configKey,
        );

        throw new TableAlreadyExistsException($message);
    }
}
