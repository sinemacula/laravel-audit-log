<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Database\Connection;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;

/**
 * SQLite's entry and artifact delete triggers, which a prune drops and
 * recreates inside the chunk's transaction.
 *
 * SQLite has no users, so the triggers refuse even the maintenance delete; a
 * rollback restores them unseen by other connections.
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
     * Drop the installed delete triggers on SQLite and return their names; none
     * on any other engine.
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
            $connection->statement(sprintf('DROP TRIGGER %s', $name));
        }

        return $dropped;
    }

    /**
     * Create each named delete trigger again on SQLite; nothing runs on any
     * other engine.
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
            $connection->statement(self::statementFor(substr($name, 0, -strlen(self::SUFFIX))));
        }
    }

    /**
     * The documented text of the table's delete trigger.
     *
     * @param  string  $table
     * @return string
     */
    public static function statementFor(string $table): string
    {
        return sprintf(self::STATEMENT, $table);
    }
}
