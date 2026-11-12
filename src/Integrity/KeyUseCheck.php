<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use Illuminate\Database\DatabaseManager;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Records\EnvelopeKeys;

/**
 * Finds a segment's entries missing a key use for a key their envelopes name,
 * which would hide the entry from its owner's erasure.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class KeyUseCheck
{
    /** @var int Most entries whose key uses one statement reads. */
    public const int BATCH = 500;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\DatabaseManager  $database
     */
    public function __construct(

        /** The connections the storage connection is resolved from on every check. */
        private DatabaseManager $database,
    ) {}

    /**
     * The ids of the entries short of a key use, in the order given: each entry
     * one of whose keys has no key use naming the entry.
     *
     * @param  array<int|string, list<string>>  $expected
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    public function missing(array $expected): array
    {
        $missing = [];

        foreach (array_chunk(self::askable($expected), self::BATCH, true) as $batch) {
            $stored = $this->storedUses(array_map(strval(...), array_keys($batch)));

            foreach ($batch as $entryId => $keyIds) {
                $short = array_filter($keyIds, static fn (string $keyId): bool => !isset($stored[self::pairOf($keyId, (string) $entryId)]));

                if ($short === []) {
                    continue;
                }

                $missing[] = (string) $entryId;
            }
        }

        return $missing;
    }

    /**
     * Every key use of the entries, as its key and entry pair, read in one
     * statement on the writer.
     *
     * @param  list<string>  $entryIds
     * @return array<string, true>
     *
     * @throws \InvalidArgumentException
     */
    private function storedUses(array $entryIds): array
    {
        $uses = $this->database->connection(StorageConnection::name())
            ->table(KeyTables::keyUsesTable())
            ->useWritePdo()
            ->whereIn('entry_id', $entryIds)
            ->get(['key_id', 'entry_id']);

        $stored = [];

        foreach ($uses as $use) {
            $stored[self::pairOf((string) $use->key_id, (string) $use->entry_id)] = true;
        }

        return $stored;
    }

    /**
     * The entries that can have a key use, with their keys; a non-canonical id
     * is never given one, so no engine compares a UUID column with anything
     * else.
     *
     * @param  array<int|string, list<string>>  $expected
     * @return array<int|string, non-empty-list<string>>
     */
    private static function askable(array $expected): array
    {
        $askable = [];

        foreach ($expected as $entryId => $keyIds) {
            $keys = array_values(array_filter($keyIds, self::isCanonical(...)));

            if ($keys === [] || !self::isCanonical((string) $entryId)) {
                continue;
            }

            $askable[$entryId] = $keys;
        }

        return $askable;
    }

    /**
     * Whether the id is a canonical lower-case UUID.
     *
     * @param  string  $id
     * @return bool
     */
    private static function isCanonical(string $id): bool
    {
        return preg_match(EnvelopeKeys::KEY_PATTERN, $id) === 1;
    }

    /**
     * The key and entry as one key of a set.
     *
     * @param  string  $keyId
     * @param  string  $entryId
     * @return string
     */
    private static function pairOf(string $keyId, string $entryId): string
    {
        return $keyId . ' ' . $entryId;
    }
}
