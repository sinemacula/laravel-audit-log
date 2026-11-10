<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Keys;

use Illuminate\Database\Connection;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Records\EnvelopeKeys;

/**
 * The key uses: which key encrypted a field of which entry, one row per
 * distinct key of each entry, written with the entry it describes and never
 * changed or removed, so an owner's entries are found through its keys and
 * verification proves every envelope has its row.
 *
 * A row is made only for a key that is a canonical lower-case UUID, whatever
 * encrypter named it, and for an entry whose id is one. Rows are inserted many
 * to a statement, at most 400 on SQLite and 10,000 elsewhere, so even an import
 * chunk of several owners stays under the placeholders every engine allows;
 * a row that is already there is never ignored, so a conflict surfaces as the
 * unique violation it is.
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
     * The rows that record the keys the entry's envelopes name: one per
     * distinct key that is a canonical lower-case UUID, sorted by key.
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
     * Insert the rows on the connection, as many to a statement as the engine
     * allows, and nothing when there are none.
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
