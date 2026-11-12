<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\PruneRecord;

/**
 * The prune ledger the package binds: the records of the journal's `prune`
 * rows, read on the writer so a replica's lag never hides a committed prune.
 *
 * The row's own signature is not checked here: verification checks the seal
 * key's signature on the record.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class JournalPruneLedger implements PruneLedger
{
    /** @var int How deep a payload may nest. */
    private const int DEPTH = 64;

    /** @var string The refusal of a seal's prune row with no readable record. */
    private const string UNREADABLE = 'The lifecycle journal holds a prune row of the seal `%s` with no record that can be read.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\DatabaseManager  $database
     */
    public function __construct(

        /** Resolves the storage connection on every call. */
        private DatabaseManager $database,
    ) {}

    /**
     * Every prune record of the seal in sequence order, or none when it was
     * never pruned.
     *
     * @param  string  $sealId
     * @return list<\SineMacula\Laravel\AuditLog\Integrity\PruneRecord>
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    #[\Override]
    public function recordsFor(string $sealId): array
    {
        return self::recordsOn($this->database->connection(StorageConnection::name()), $sealId);
    }

    /**
     * Every prune record of the seal on the connection given, for a prune chunk
     * inside its own transaction.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $sealId
     * @return list<\SineMacula\Laravel\AuditLog\Integrity\PruneRecord>
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     *
     * @internal
     */
    public static function recordsOn(Connection $connection, string $sealId): array
    {
        $payloads = $connection
            ->table(LifecycleTables::journalTable())
            ->where('kind', JournalKind::PRUNE->value)
            ->where('seal_id', $sealId)
            ->orderBy('sequence')
            ->useWritePdo()
            ->pluck('payload')
            ->all();

        return array_values(array_map(static fn (#[\SensitiveParameter] mixed $payload): PruneRecord => self::recordOf($payload, $sealId), $payloads));
    }

    /**
     * The record a prune row's stored payload holds.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $payload
     * @param  string  $sealId
     * @return \SineMacula\Laravel\AuditLog\Integrity\PruneRecord
     *
     * @throws \UnexpectedValueException
     */
    private static function recordOf(#[\SensitiveParameter] mixed $payload, string $sealId): PruneRecord
    {
        try {
            $decoded = is_string($payload) ? json_decode($payload, true, self::DEPTH, JSON_THROW_ON_ERROR) : null;
        } catch (\JsonException) {
            $decoded = null;
        }

        $record = is_array($decoded) ? ($decoded['record'] ?? null) : null;

        if (!is_array($record)) {
            throw new \UnexpectedValueException(sprintf(self::UNREADABLE, $sealId));
        }

        return PruneRecord::fromArray($record);
    }
}
