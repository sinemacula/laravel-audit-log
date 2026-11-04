<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Database\Connection;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;

/**
 * The delete triggers of the entries and the artifacts on SQLite, which a prune
 * drops and recreates around its deletes.
 *
 * SQLite has no users, so the storage note's triggers refuse every delete they
 * cover, the maintenance one included. A prune on SQLite therefore drops the
 * delete triggers of the entries and the artifacts that are installed, deletes,
 * and creates them again with the documented text, all inside the chunk's own
 * transaction, so a chunk that rolls back restores them as they were and no
 * other connection ever sees them missing. A trigger that is not installed is
 * neither dropped nor created. On every other engine nothing runs: the
 * documented triggers there let the maintenance user delete.
 *
 * This is the one place the package changes the schema at runtime.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SqliteDeleteTriggers
{
    /** @var string What every delete trigger's name is, after its table. */
    public const string SUFFIX = '_no_delete';

    /** @var string The documented text of a delete trigger, by its table, which it names three times. */
    private const string STATEMENT = <<<'SQL'
        CREATE TRIGGER %1$s_no_delete BEFORE DELETE ON %1$s
        BEGIN
            SELECT RAISE(ABORT, '%1$s refuses DELETE');
        END;
        SQL;

    /**
     * The names of the delete triggers of the entries and the artifacts that
     * are installed, each dropped, on SQLite; on any other engine, none, and no
     * statement runs.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    public function dropPresent(Connection $connection): array
    {
        if ($connection->getDriverName() !== 'sqlite') {
            return [];
        }

        $names = [EntrySettings::table() . self::SUFFIX, EntrySettings::artifactsTable() . self::SUFFIX];

        $present = $connection->table('sqlite_master')
            ->useWritePdo()
            ->where('type', 'trigger')
            ->whereIn('name', $names)
            ->pluck('name')
            ->all();

        $dropped = array_values(array_filter($names, static fn (string $name): bool => in_array($name, $present, true)));

        foreach ($dropped as $name) {
            $connection->unprepared(sprintf('DROP TRIGGER %s', $name));
        }

        return $dropped;
    }

    /**
     * Create again each delete trigger named, with the documented text of its
     * table, on SQLite; on any other engine nothing runs.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  list<string>  $names
     * @return void
     */
    public function recreate(Connection $connection, array $names): void
    {
        if ($connection->getDriverName() !== 'sqlite') {
            return;
        }

        foreach ($names as $name) {
            $connection->unprepared(self::statementFor(substr($name, 0, -strlen(self::SUFFIX))));
        }
    }

    /**
     * The documented text of the delete trigger of the table, as the storage
     * note gives it.
     *
     * @param  string  $table
     * @return string
     */
    public static function statementFor(string $table): string
    {
        return sprintf(self::STATEMENT, $table);
    }
}
