<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;

/**
 * Configures a second connection to the worker's database, or one to a database
 * of its own, for the maintenance connection to point at.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ConnectsSecondDatabases
{
    /** @var string A second connection to the worker's database. */
    protected const string MAINTENANCE = 'audit_maintenance';

    /** @var string A connection to a database of its own. */
    protected const string OTHER = 'audit_other';

    /**
     * Configure `MAINTENANCE` as a second connection to the worker's database.
     *
     * @return void
     */
    protected function sameDatabase(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('database.connections.' . self::MAINTENANCE, $config->array('database.connections.' . self::CONNECTION));
        $config->set('audit-log.storage.maintenance_connection', self::MAINTENANCE);

        $root = DB::connection(self::CONNECTION);

        if ($root->getDriverName() !== 'sqlite') {
            return;
        }

        $same = DB::connection(self::MAINTENANCE);

        $same->setPdo($root->getPdo());
        $same->setReadPdo($root->getPdo());
    }

    /**
     * Configure `OTHER`, a connection to a database whose state table holds no
     * installation id.
     *
     * @return void
     */
    protected function otherDatabase(): void
    {
        $config = app(ConfigRepository::class);

        DB::purge(self::OTHER);

        $config->set('database.connections.' . self::OTHER, [...$config->array('database.connections.' . self::CONNECTION), 'prefix' => 'other_']);

        $schema = DB::connection(self::OTHER)->getSchemaBuilder();

        $schema->dropIfExists(IntegrityTables::stateTable());
        $schema->create(IntegrityTables::stateTable(), static function (Blueprint $table): void {
            $table->string('name', 64)->primary();
            $table->text('value');
            $table->dateTime('updated_at', 6);
        });

        $this->beforeApplicationDestroyed(static fn () => DB::connection(self::OTHER)->getSchemaBuilder()->dropIfExists(IntegrityTables::stateTable()));
    }
}
