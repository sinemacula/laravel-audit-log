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
 * One chunk of a prune, inside a lifecycle transaction the caller's
 * `MaintenanceTransaction::run()` opened, behind the lock: every decision it
 * makes is read after the lock, and it signs a prune record of exactly what it
 * deleted.
 *
 * The replay is advanced first, so the holds it applies are those of the
 * verified chain, every hold committed before the lock among them. The
 * candidates' full rows are read next; an id that is not returned is left
 * alone, since it was pruned already or was never present, and no record ever
 * covers it. Every row returned must verify under the key it names, carry the
 * HMAC its member was sealed with, and be a member of the authenticated seal,
 * or the chunk deletes nothing and the seal is skipped for the run, so a prune
 * never erases evidence of tampering. So is a row whose member a valid prune
 * record of the seal already sets: an entry stored again after it was pruned
 * stays, reported `resurrected`, and no record ever sets a member twice. A seal
 * whose prune records cannot be read is skipped the same way. Each verified
 * row's eligibility is then decided again from that row: its pair's decision of
 * the run, its time before the cut-off, and a code that is not protected. A row
 * any active hold matches is kept, and so is one with an outbox row or a
 * receipt not yet delivered.
 *
 * What is left is deleted, its artifacts and receipts first, then the entries,
 * each statement naming at most 500 ids, and every delete of entries must
 * affect exactly the rows it names, or a `PruneMismatchException` rolls the
 * chunk back. On SQLite the installed delete triggers are dropped before and
 * created again after, in the same transaction. The prune record sets exactly
 * the deleted members' positions, names the run as its operation, and is
 * appended to the journal as the chunk's `prune` row, so the deletion and its
 * record commit together or not at all. A chunk with nothing left to delete
 * writes nothing but the lock.
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
     * Prune the ids of the seal, inside the lifecycle transaction the
     * connection holds, and return what the chunk did, with the replay it ended
     * with.
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
     * Whether any of the holds keeps the stored row, each hold's scope matched
     * in PHP against the row as the engine stores it, so a dry run counts held
     * entries exactly as a chunk keeps them.
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
     * Whether the candidate's row is the seal's member as it was sealed: a
     * member of the seal, carrying the HMAC it was sealed with, and verifying
     * under the key it names. A row that cannot be decoded, or whose key the
     * ring no longer holds, is not.
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
     * Whether a valid prune record of the seal already sets the member of any
     * of the rows, read on the chunk's connection after the lock, so the row
     * was stored again after it was pruned; or whether the seal's records
     * cannot be read, so what they set is unknown.
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
     * Whether the verified row is eligible, decided from the row itself: its
     * pair's decision of the run admits its time, and its code is not
     * protected. A row whose tenant cannot be referenced never is.
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
     * Sign the prune record of the deleted members' positions and append it to
     * the journal as the chunk's `prune` row, returning the replay that
     * accepted it.
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
     * The candidates' full rows, read on the connection's writer, at most 500
     * ids to a statement.
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
     * Delete the entries of the ids, their artifacts and receipts first, at
     * most 500 ids to a statement, around SQLite's delete triggers, refusing a
     * delete of entries that affects another number of rows than it names.
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
