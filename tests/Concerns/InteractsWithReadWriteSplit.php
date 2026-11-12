<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/**
 * Makes the storage connection a read/write split whose replica lags: every
 * write lands on the primary SQLite file only, so a read served by the replica
 * does not see it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InteractsWithReadWriteSplit
{
    /** @var string Connection that reads from the replica and writes to the primary. */
    protected const string SPLIT_CONNECTION = 'split';

    /** @var string Direct connection to the primary file. */
    protected const string PRIMARY_CONNECTION = 'primary';

    /** @var string Direct connection to the replica file. */
    protected const string REPLICA_CONNECTION = 'replica';

    /** @var string Absolute path to the shipped entries migration file. */
    private const string ENTRIES_MIGRATION = __DIR__ . '/../../database/migrations/2026_11_02_000000_create_audit_log_entries_table.php';

    /** @var list<string> Temporary SQLite files created for this test. */
    private array $splitFiles = [];

    /**
     * Register the primary, the replica and the split connection, migrate the
     * entries table on the primary and the replica, and make the split
     * connection the storage connection.
     *
     * @return void
     */
    protected function useReadWriteSplit(): void
    {
        $config  = app(ConfigRepository::class);
        $primary = $this->createSplitFile();
        $replica = $this->createSplitFile();

        $config->set('database.connections.' . self::PRIMARY_CONNECTION, ['driver' => 'sqlite', 'database' => $primary, 'prefix' => '']);
        $config->set('database.connections.' . self::REPLICA_CONNECTION, ['driver' => 'sqlite', 'database' => $replica, 'prefix' => '']);

        // The top-level `database` is what Testbench inspects; Laravel uses the
        // `read` and `write` entries for the two PDOs.
        $config->set('database.connections.' . self::SPLIT_CONNECTION, [
            'driver'   => 'sqlite',
            'database' => $primary,
            'read'     => ['database' => $replica],
            'write'    => ['database' => $primary],
            'sticky'   => false,
            'prefix'   => '',
        ]);

        $migration = require self::ENTRIES_MIGRATION;

        assert($migration instanceof Migration && method_exists($migration, 'up'));

        foreach ([self::PRIMARY_CONNECTION, self::REPLICA_CONNECTION] as $connection) {
            $config->set('audit-log.storage.connection', $connection);
            $migration->up();
        }

        $config->set('audit-log.storage.connection', self::SPLIT_CONNECTION);
    }

    /**
     * Close the split's connections and delete their files.
     *
     * @return void
     */
    protected function removeReadWriteSplit(): void
    {
        foreach ([self::SPLIT_CONNECTION, self::PRIMARY_CONNECTION, self::REPLICA_CONNECTION] as $connection) {
            DB::purge($connection);
        }

        foreach ($this->splitFiles as $file) {
            if (!is_file($file)) {
                continue;
            }

            unlink($file);
        }

        $this->splitFiles = [];
    }

    /**
     * Create an empty temporary SQLite database file.
     *
     * @return string
     */
    private function createSplitFile(): string
    {
        $file = tempnam(sys_get_temp_dir(), 'audit-split-');

        self::assertIsString($file);

        $this->splitFiles[] = $file;

        return $file;
    }
}
