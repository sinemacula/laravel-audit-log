<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Database\Connection;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\PruneBitmap;
use SineMacula\Laravel\AuditLog\Integrity\PruneCoverage;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Integrity\SealSigner;
use SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException;
use SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;

/**
 * One chunk of a prune, inside a lifecycle transaction behind the lock, signing
 * a prune record of exactly what it deleted.
 *
 * A candidate that does not authenticate, or that a prune record already
 * covers, skips the seal, so a prune never erases evidence of tampering.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PruneChunk
{
    /** @var int The most ids one statement names. */
    public const int STATEMENT_IDS = 500;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Journal  $journal
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSigner  $sealSigner
     * @param  \SineMacula\Laravel\AuditLog\Integrity\RecordSigner  $recordSigner
     * @param  \SineMacula\Laravel\AuditLog\Stores\RowCodec  $codec
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\PendingDeliveries  $deliveries
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\SqliteDeleteTriggers  $triggers
     * @param  \SineMacula\Laravel\AuditLog\Integrity\PruneCoverage  $coverage
     */
    public function __construct(

        /** The journal the chunk's prune row is appended to. */
        private Journal $journal,

        /** The signer of the chunk's prune record. */
        private SealSigner $sealSigner,

        /** The signer each candidate's row is verified with. */
        private RecordSigner $recordSigner,

        /** The codec each candidate's row is decoded with. */
        private RowCodec $codec,

        /** The deliveries not yet finished, read after the lock. */
        private PendingDeliveries $deliveries,

        /** The delete triggers SQLite's prune drops and recreates. */
        private SqliteDeleteTriggers $triggers,

        /** What the seal's prune records already account for. */
        private PruneCoverage $coverage,
    ) {}

    /**
     * Prune the seal's ids and return what the chunk did, with the replay it
     * ended with.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay  $replay
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecisions  $decisions
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\PruneSeal  $seal
     * @param  list<string>  $ids
     * @param  string  $runId
     * @param  string  $prunedAt
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\PruneChunkOutcome
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\PruneMismatchException
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\RetentionConflictException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @SuppressWarnings("php:S107")
     */
    public function run(
        Connection $connection,
        JournalReplay $replay,
        RetentionDecisions $decisions,
        PruneSeal $seal,
        array $ids,
        string $runId,
        string $prunedAt,
    ): PruneChunkOutcome {
        $replay = $replay->advance($connection);
        $rows   = self::candidates($connection, $ids);

        $forged = array_filter($rows, fn (#[\SensitiveParameter] array $row): bool => !$this->isAuthentic($row, $seal));

        if ($forged !== [] || ($rows !== [] && $this->isAnyPrunedAlready($connection, $seal, $rows))) {
            return PruneChunkOutcome::skippingTheSeal($replay);
        }

        $holds      = $replay->holds();
        $eligible   = array_values(array_filter($rows, fn (#[\SensitiveParameter] array $row): bool => $this->isEligible($row, $decisions)));
        $unheld     = array_values(array_filter($eligible, static fn (#[\SensitiveParameter] array $row): bool => !self::isHeld($row, $holds)));
        $unheldIds  = array_map(static fn (#[\SensitiveParameter] array $row): string => (string) $row['id'], $unheld);
        $pending    = [...$this->deliveries->inOutbox($connection, $unheldIds), ...$this->deliveries->undelivered($connection, $unheldIds)];
        $deletable  = array_values(array_diff($unheldIds, $pending));
        $held       = count($eligible)  - count($unheld);
        $ineligible = count($rows)      - count($eligible);
        $waiting    = count($unheldIds) - count($deletable);

        if ($deletable === []) {
            return new PruneChunkOutcome([], $held, $waiting, $ineligible, false, $replay);
        }

        usort($deletable, strcmp(...));

        self::delete($connection, $deletable, $this->triggers);

        $replay = $this->journalPrune($connection, $replay, $seal, $deletable, $runId, $prunedAt);

        return new PruneChunkOutcome($deletable, $held, $waiting, $ineligible, false, $replay);
    }

    /**
     * Whether any hold keeps the stored row, matched in PHP so a dry run counts
     * held entries exactly as a chunk keeps them.
     *
     * @param  array<string, scalar|null>  $row
     * @param  list<\SineMacula\Laravel\AuditLog\Lifecycle\Hold>  $holds
     * @return bool
     */
    public static function isHeld(#[\SensitiveParameter] array $row, array $holds): bool
    {
        foreach ($holds as $hold) {
            if ($hold->scope->matches($row)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether the row is the seal's member as sealed, with its HMAC and
     * verifying under the key it names.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $row
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\PruneSeal  $seal
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private function isAuthentic(#[\SensitiveParameter] array $row, PruneSeal $seal): bool
    {
        $id = $row['id'] ?? null;

        if (!is_string($id) || !$seal->hasMember($id) || ($row['hmac'] ?? null) !== $seal->memberHmac($id)) {
            return false;
        }

        try {
            return $this->recordSigner->verifies($this->codec->decode($row));
        } catch (\UnexpectedValueException|UnknownKeyException) {
            return false;
        }
    }

    /**
     * Whether a prune record of the seal already covers a row, stored again
     * after its prune, or the records cannot be read.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\PruneSeal  $seal
     * @param  non-empty-list<array<string, scalar|null>>  $rows
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private function isAnyPrunedAlready(Connection $connection, PruneSeal $seal, #[\SensitiveParameter] array $rows): bool
    {
        try {
            $records = JournalPruneLedger::recordsOn($connection, $seal->envelope->id);
        } catch (\UnexpectedValueException) {
            // A record that cannot be read may set any member
            return true;
        }

        if ($records === []) {
            return false;
        }

        $ids = array_map(static fn (#[\SensitiveParameter] array $row): string => (string) $row['id'], $rows);

        return $this->coverage->of($seal->envelope, $seal->digest, $seal->memberIds, [], $ids, true, $records)->recheck !== [];
    }

    /**
     * Whether the verified row is eligible under its pair's decision and its
     * code is not protected.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $row
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecisions  $decisions
     * @return bool
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\RetentionConflictException
     * @throws \UnexpectedValueException
     */
    private function isEligible(#[\SensitiveParameter] array $row, RetentionDecisions $decisions): bool
    {
        $decoded    = $this->codec->decode($row);
        $category   = self::textOf($decoded['category']);
        $occurredAt = self::textOf($decoded['occurred_at']);
        $type       = self::textOf($decoded['tenant_type']);
        $id         = self::textOf($decoded['tenant_id']);

        if ($category === null || $occurredAt === null || ($type === null) !== ($id === null)) {
            return false;
        }

        try {
            $tenant = $type === null || $id === null ? null : Reference::of($type, $id);
        } catch (\InvalidArgumentException) {
            return false;
        }

        return $decisions->for($category, $tenant)->admits($occurredAt)
            && PackageActivity::tryFrom(self::textOf($decoded['event']) ?? '')?->isProtected() !== true;
    }

    /**
     * Sign the prune record of the deleted positions and append it to the
     * journal, returning the replay that accepted it.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay  $replay
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\PruneSeal  $seal
     * @param  list<string>  $deleted
     * @param  string  $runId
     * @param  string  $prunedAt
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     */
    private function journalPrune(Connection $connection, JournalReplay $replay, PruneSeal $seal, array $deleted, string $runId, string $prunedAt): JournalReplay
    {
        $envelope  = $seal->envelope;
        $positions = array_map($seal->positionOf(...), $deleted);
        $record    = $this->sealSigner->signPrune(
            $envelope->logId,
            $envelope->id,
            $seal->digest,
            $envelope->memberCount,
            PruneBitmap::encode($positions, $envelope->memberCount),
            count($positions),
            $runId,
            $prunedAt,
        );

        $payload = ['record' => [...$record->toArray(), 'signature' => $record->signature], 'run_id' => $runId];

        return $this->journal->append($connection, $replay, JournalKind::PRUNE, $runId, null, $payload, sealId: $envelope->id);
    }

    /**
     * The candidates' full rows, read on the connection's writer.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  list<string>  $ids
     * @return list<array<string, scalar|null>>
     *
     * @throws \InvalidArgumentException
     */
    private static function candidates(Connection $connection, array $ids): array
    {
        $rows = [];

        foreach (array_chunk($ids, self::STATEMENT_IDS) as $chunk) {
            foreach ($connection->table(EntrySettings::table())->useWritePdo()->whereIn('id', $chunk)->get()->all() as $row) {
                /** @var array<string, scalar|null> $stored */
                $stored = (array) $row;
                $rows[] = $stored;
            }
        }

        return $rows;
    }

    /**
     * The value when it is text, else `null`.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return ?string
     */
    private static function textOf(#[\SensitiveParameter] mixed $value): ?string
    {
        return is_string($value) ? $value : null;
    }

    /**
     * Delete the entries after their artifacts and receipts, around SQLite's
     * delete triggers, refusing a row count mismatch.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  list<string>  $ids
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\SqliteDeleteTriggers  $triggers
     * @return void
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\PruneMismatchException
     */
    private static function delete(Connection $connection, array $ids, SqliteDeleteTriggers $triggers): void
    {
        $chunks  = array_chunk($ids, self::STATEMENT_IDS);
        $dropped = $triggers->dropPresent($connection);

        foreach ([EntrySettings::artifactsTable(), DeliveryTables::deliveriesTable()] as $table) {
            foreach ($chunks as $chunk) {
                $connection->table($table)->whereIn('entry_id', $chunk)->delete();
            }
        }

        foreach ($chunks as $chunk) {
            $affected = $connection->table(EntrySettings::table())->whereIn('id', $chunk)->delete();

            if ($affected !== count($chunk)) {
                throw PruneMismatchException::of(count($chunk), $affected);
            }
        }

        $triggers->recreate($connection, $dropped);
    }
}
