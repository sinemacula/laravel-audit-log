<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Keys;

use Illuminate\Database\Connection;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Records\EnvelopeKeys;

/**
 * Append-only rows of which key encrypted a field of which entry; a duplicate
 * is never ignored, so a conflict surfaces as a unique violation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class KeyUses
{
    /** @var int Most rows one statement inserts on SQLite. */
    public const int SQLITE_ROWS_PER_STATEMENT = 400;

    /** @var int Most rows one statement inserts on any other engine. */
    public const int ROWS_PER_STATEMENT = 10000;

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * One row per distinct canonical lower-case UUID key the entry names,
     * sorted by key.
     *
     * @param  string  $entryId
     * @param  array<array-key, string>  $keyIds
     * @return list<array{key_id: string, entry_id: string}>
     *
     * @throws \InvalidArgumentException
     */
    public static function rowsFor(string $entryId, array $keyIds): array
    {
        if (preg_match(EnvelopeKeys::KEY_PATTERN, $entryId) !== 1) {
            throw new \InvalidArgumentException('A key use\'s entry id must be a lower-case UUID.');
        }

        $keys = array_values(array_unique(array_filter($keyIds, static fn (string $keyId): bool => preg_match(EnvelopeKeys::KEY_PATTERN, $keyId) === 1)));

        sort($keys, SORT_STRING);

        return array_map(static fn (string $keyId): array => ['key_id' => $keyId, 'entry_id' => $entryId], $keys);
    }

    /**
     * Insert the rows, as many to a statement as the engine allows.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  list<array{key_id: string, entry_id: string}>  $rows
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function insert(Connection $connection, #[\SensitiveParameter] array $rows): void
    {
        $table = KeyTables::keyUsesTable();

        foreach (array_chunk($rows, self::rowsPerStatement($connection)) as $chunk) {
            $connection->table($table)->insert($chunk);
        }
    }

    /**
     * Most rows one statement inserts on the connection's engine.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return positive-int
     */
    public static function rowsPerStatement(Connection $connection): int
    {
        return $connection->getDriverName() === 'sqlite' ? self::SQLITE_ROWS_PER_STATEMENT : self::ROWS_PER_STATEMENT;
    }
}
