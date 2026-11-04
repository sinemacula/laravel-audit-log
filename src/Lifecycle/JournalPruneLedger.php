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
 * The prune ledger the package binds: the records the lifecycle journal's
 * `prune` rows hold, each written in the transaction that deleted the members
 * it sets.
 *
 * A seal's records are read in one indexed statement, by the seal id of the
 * rows of kind `prune`, in the order of their sequence, on the storage
 * connection's writer: verification needs no credentials that can delete, and a
 * replica's lag never hides a committed prune. Each row's payload is decoded
 * and its `record` read as a prune record of version 2. A payload that is not
 * JSON or holds no record is an `UnexpectedValueException` naming the seal, and
 * a record that cannot be read one naming its field; verification reports
 * either as a forged record of the seal. The row's own signature is not checked
 * here: the record carries the seal key's, which verification checks, and
 * `audit-log:verify`'s journal section checks the row's. It keeps no state
 * between calls.
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

    /** @var string The refusal of a prune row of a seal that holds no record, by the seal's id. */
    private const string UNREADABLE = 'The lifecycle journal holds a prune row of the seal `%s` with no record that can be read.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\DatabaseManager  $database
     */
    public function __construct(

        /** The connections the storage connection is resolved from on every call. */
        private DatabaseManager $database,
    ) {}

    /**
     * Every record the journal's prune rows hold for the seal, in the order of
     * their sequence, or none when the seal was never pruned.
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
     * Every record the journal's prune rows hold for the seal, read on the
     * connection given, in the order of their sequence: what a prune chunk
     * reads inside its own lifecycle transaction.
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
