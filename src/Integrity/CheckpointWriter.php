<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Str;
use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * Writes one seal: one attempt, in one transaction on the storage connection,
 * that reads the last seal afresh, selects the entries to seal, and inserts the
 * seal's checkpoint and then every one of its members, or writes nothing.
 *
 * The last seal is read whole and its digest recomputed from its fields. A
 * stored digest that disagrees, or a seal of another log id, is refused with a
 * `SealChainException`, so a seal is never chained onto one that has been
 * altered and one chain never mixes two logs. Its signature is not checked
 * here: a seal signed under a key since retired is extended, and verification
 * reports any seal whose signature fails.
 *
 * Every seal commits to the lifecycle journal's head, so the journal is
 * anchored exactly as the entries are. The head, the sequence and HMAC of the
 * journal's last row, is read after the last seal inside the seal's own
 * transaction, so a seal that wins its sequence sees every row committed before
 * the seal it extends. A head whose sequence or HMAC cannot be read is refused
 * with a `SealChainException`, so a seal never commits to a row it cannot
 * name; an empty journal is committed to as none. A head behind the last
 * seal's commitment, a lower sequence, none after a commitment to a row, or
 * another HMAC at the committed sequence, is refused the same way, so
 * commitments never run backwards and a journal whose tail was removed or
 * replaced is never sealed over.
 *
 * The selection is a plain `SELECT`, never a locking read, of the entries
 * recorded no later than the bound, after the position given, in `(recorded_at,
 * id)` order so batches are deterministic: membership, not the order, is what
 * is sealed. The recent pass reads entries that are no seal's member; the sweep
 * reads a window of entries whether sealed or not, so one statement never reads
 * more than its limit of rows, and seals those of them that are no seal's
 * member. A candidate whose id is not a lower-case UUID, whose HMAC is not 64
 * lower-case hex, or whose time cannot be read is left out and counted, never
 * sealed and never fatal; the position still moves past it, from its time and
 * id exactly as stored, however long or malformed, so a malformed row at the
 * end of a batch never stops the batch's seal or sealing after it.
 *
 * Every row is written with a parameterised `INSERT … VALUES`, never one from a
 * `SELECT` and never one that ignores a conflict: the checkpoint first, then
 * the members in chunks small enough for every engine's placeholder limit. A
 * concurrent sealer's seal of the same sequence or of the same entry makes the
 * attempt fail as a whole, and Laravel's one-attempt transaction rolls it back
 * with no savepoint; the caller decides whether to try again.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CheckpointWriter
{
    /** @var int Members inserted by one statement: 900 placeholders, under the oldest SQLite limit of 999. */
    public const int MEMBER_CHUNK = 300;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\DatabaseManager  $database
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSigner  $signer
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSettings  $settings
     * @param  \SineMacula\Laravel\AuditLog\Contracts\Clock  $clock
     */
    public function __construct(

        /** The connections the storage connection is resolved from on every attempt. */
        private DatabaseManager $database,

        /** The signer that signs each seal under the ring's signing key. */
        private SealSigner $signer,

        /** The settings the log id is read from. */
        private SealSettings $settings,

        /** The clock that says when a seal is made. */
        private Clock $clock,
    ) {}

    /**
     * Seal, in one attempt, at most the limit of entries that are no seal's
     * member, recorded no later than the bound and after the position: the
     * recent pass.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\SealCursor  $after
     * @param  string  $until
     * @param  int  $limit
     * @return \SineMacula\Laravel\AuditLog\Integrity\SealBatch
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\SealChainException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     * @throws \Throwable
     */
    public function write(?SealCursor $after, string $until, int $limit): SealBatch
    {
        return $this->attempt(static function (Connection $connection) use ($after, $until, $limit): array {
            $rows = self::bounded($connection->table(EntrySettings::table() . ' as e'), 'e.', $after, $until)
                ->leftJoin(IntegrityTables::membersTable() . ' as m', 'm.entry_id', '=', 'e.id')
                ->whereNull('m.entry_id')
                ->orderBy('e.recorded_at')
                ->orderBy('e.id')
                ->limit($limit)
                ->useWritePdo()
                ->get(['e.id', 'e.hmac', 'e.recorded_at'])
                ->all();

            return [$rows, $rows];
        }, $limit);
    }

    /**
     * Seal, in one attempt, the entries of a window that are no seal's member:
     * the window is at most the limit of entries recorded no later than the
     * bound and after the position, sealed or not: the sweep.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\SealCursor  $after
     * @param  string  $until
     * @param  int  $limit
     * @return \SineMacula\Laravel\AuditLog\Integrity\SealBatch
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\SealChainException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     * @throws \Throwable
     */
    public function writeWindow(?SealCursor $after, string $until, int $limit): SealBatch
    {
        return $this->attempt(static function (Connection $connection) use ($after, $until, $limit): array {
            $window = self::bounded($connection->table(EntrySettings::table()), '', $after, $until)
                ->select(['id', 'hmac', 'recorded_at'])
                ->orderBy('recorded_at')
                ->orderBy('id')
                ->limit($limit);

            $rows = $connection->query()
                ->fromSub($window, 'w')
                ->leftJoin(IntegrityTables::membersTable() . ' as m', 'm.entry_id', '=', 'w.id')
                ->orderBy('w.recorded_at')
                ->orderBy('w.id')
                ->useWritePdo()
                ->get(['w.id', 'w.hmac', 'w.recorded_at', 'm.entry_id as member_entry_id'])
                ->all();

            return [$rows, array_values(array_filter($rows, static fn (#[\SensitiveParameter] \stdClass $row): bool => $row->member_entry_id === null))];
        }, $limit);
    }

    /**
     * Make one attempt in one transaction on the storage connection, with no
     * retry and so no savepoint: read the last seal, select the rows, and seal
     * the candidates among them, if any can be sealed.
     *
     * @param  \Closure(\Illuminate\Database\Connection): array{0: list<\stdClass>, 1: list<\stdClass>}  $select
     * @param  int  $limit
     * @return \SineMacula\Laravel\AuditLog\Integrity\SealBatch
     *
     * @throws \Throwable
     */
    private function attempt(\Closure $select, int $limit): SealBatch
    {
        $connection = $this->database->connection(StorageConnection::name());

        return $connection->transaction(function (Connection $connection) use ($select, $limit): SealBatch {
            $head                = $this->head($connection);
            [$rows, $candidates] = $select($connection);
            [$members, $times]   = self::sealable($candidates);
            $skipped             = count($candidates) - count($members);
            $last                = $rows === [] ? null : self::positionOf($rows[array_key_last($rows)]);

            if ($members === []) {
                return new SealBatch(null, null, count($rows), $skipped, $last, $limit);
            }

            $seal   = $this->envelope($head, $members, $times, self::journalHeadAfter($head[0] ?? null, $connection));
            $digest = $seal->digest();

            $this->insert($connection, $seal, $digest, $members);

            return new SealBatch($seal, $digest, count($rows), $skipped, $last, $limit);
        }, 1);
    }

    /**
     * The last seal in the chain and its recomputed digest, or `null` when
     * there is none; a row stored at a sequence below 1 is outside the chain
     * and never extended. One whose stored digest disagrees with its fields, or
     * that belongs to another log, is refused.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return ?array{0: \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope, 1: string}
     *
     * @throws \SineMacula\Laravel\AuditLog\Integrity\SealChainException
     */
    private function head(Connection $connection): ?array
    {
        $stored = $connection->table(IntegrityTables::checkpointsTable())->useWritePdo()->where('sequence', '>=', 1)->orderByDesc('sequence')->first();

        if ($stored === null) {
            return null;
        }

        $seal   = (array) $stored;
        $head   = SealEnvelope::fromRow($seal);
        $digest = $head->digest();

        if (($seal['seal_digest'] ?? null) !== $digest) {
            throw SealChainException::forHead($head->id);
        }

        if ($head->logId !== $this->settings->logId()) {
            throw SealChainException::forLog($head->id);
        }

        return [$head, $digest];
    }

    /**
     * The lifecycle journal's head, once it is known not to be behind the last
     * seal's commitment: at or after the committed sequence, and holding the
     * committed HMAC at that sequence when it has not moved.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\SealEnvelope  $previous
     * @param  \Illuminate\Database\Connection  $connection
     * @return ?array{0: int, 1: string}
     *
     * @throws \SineMacula\Laravel\AuditLog\Integrity\SealChainException
     */
    private static function journalHeadAfter(?SealEnvelope $previous, Connection $connection): ?array
    {
        $journal = self::journalHead($connection);

        if ($previous?->journalSequence === null) {
            return $journal;
        }

        $behind = $journal === null
            || $journal[0] < $previous->journalSequence
            || ($journal[0] === $previous->journalSequence && !hash_equals((string) $previous->journalHead, $journal[1]));

        if ($behind) {
            throw SealChainException::forJournalBehind($previous->id);
        }

        return $journal;
    }

    /**
     * The sequence and HMAC of the lifecycle journal's last row, the greatest
     * sequence from 1, or `null` when the journal has none; one whose sequence
     * or HMAC cannot be read is refused.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return ?array{0: int, 1: string}
     *
     * @throws \SineMacula\Laravel\AuditLog\Integrity\SealChainException
     */
    private static function journalHead(Connection $connection): ?array
    {
        $stored = $connection->table(LifecycleTables::journalTable())->useWritePdo()->where('sequence', '>=', 1)->orderByDesc('sequence')->first(['sequence', 'hmac']);

        if ($stored === null) {
            return null;
        }

        $sequence = IntegerSetting::parse($stored->sequence ?? null);
        $hmac     = $stored->hmac ?? null;

        if ($sequence === null || !self::matches(SealEnvelope::DIGEST_PATTERN, $hmac)) {
            throw SealChainException::forJournal();
        }

        return [$sequence, $hmac];
    }

    /**
     * The envelope of the next seal: one more than the last seal's sequence,
     * chained onto its recomputed digest, holding the members, between the
     * earliest and latest of their times, made now under the signing key, and
     * committing to the journal's head, if it has one.
     *
     * @param  ?array{0: \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope, 1: string}  $head
     * @param  non-empty-list<array{0: string, 1: string}>  $members
     * @param  non-empty-list<string>  $times
     * @param  ?array{0: int, 1: string}  $journal
     * @return \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     */
    private function envelope(?array $head, array $members, array $times, ?array $journal): SealEnvelope
    {
        $now                         = $this->clock->now();
        [$previous, $previousDigest] = $head ?? [null, null];

        return new SealEnvelope(
            $this->settings->logId(),
            Str::uuid7($now)->toString(),
            $previous === null ? 1 : $previous->sequence + 1,
            $previous?->id,
            $previousDigest,
            count($members),
            SealEnvelope::membersDigest($members),
            min($times),
            max($times),
            StoredTime::format($now),
            $this->signer->signingKeyId(),
            journalSequence: $journal[0] ?? null,
            journalHead: $journal[1]     ?? null,
        );
    }

    /**
     * Insert the seal's checkpoint, signed, and then its members, a chunk at a
     * time.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope  $seal
     * @param  string  $digest
     * @param  non-empty-list<array{0: string, 1: string}>  $members
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     */
    private function insert(Connection $connection, SealEnvelope $seal, string $digest, array $members): void
    {
        $connection->table(IntegrityTables::checkpointsTable())->insert($seal->toRow($digest, $this->signer->sign($seal)));

        $rows = array_map(static fn (array $member): array => ['checkpoint_id' => $seal->id, 'entry_id' => $member[0], 'hmac' => $member[1]], $members);

        foreach (array_chunk($rows, self::MEMBER_CHUNK) as $chunk) {
            $connection->table(IntegrityTables::membersTable())->insert($chunk);
        }
    }

    /**
     * The query bounded to the rows recorded no later than the bound and after
     * the position: later than its time, or at its time with a greater id, or
     * at its time or later when it starts at its time. The columns are named
     * with the prefix given. The position's time is always a lower bound of its
     * own, so that an engine reads the index of the time and id from there, in
     * order, rather than gathering every later row and sorting them first.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  string  $prefix
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\SealCursor  $after
     * @param  string  $until
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \InvalidArgumentException
     */
    private static function bounded(Builder $query, string $prefix, ?SealCursor $after, string $until): Builder
    {
        $time = $prefix . 'recorded_at';
        $id   = $prefix . 'id';

        $query->where($time, '<=', StoredTime::toStorage($until));

        if ($after === null) {
            return $query;
        }

        $query->where($time, '>=', $after->recordedAt);

        if ($after->startsAtItsTime()) {
            return $query;
        }

        return $query->where(static function (Builder $later) use ($time, $id, $after): void {
            $later->where($time, '>', $after->recordedAt)->orWhere(static function (Builder $same) use ($time, $id, $after): void {
                $same->where($time, '=', $after->recordedAt)->where($id, '>', $after->id);
            });
        });
    }

    /**
     * The members the candidates make, each an entry id and its HMAC, and their
     * times in the package's form, leaving out each candidate whose id is not a
     * lower-case UUID, whose HMAC is not 64 lower-case hex, or whose time
     * cannot be read.
     *
     * @param  list<\stdClass>  $rows
     * @return array{0: list<array{0: string, 1: string}>, 1: list<string>}
     */
    private static function sealable(#[\SensitiveParameter] array $rows): array
    {
        $members = [];
        $times   = [];

        foreach ($rows as $candidate) {

            $id   = $candidate->id   ?? null;
            $hmac = $candidate->hmac ?? null;
            $time = self::timeOf($candidate->recorded_at ?? null);

            if ($time === null || !self::matches(SealEnvelope::UUID_PATTERN, $id) || !self::matches(SealEnvelope::DIGEST_PATTERN, $hmac)) {
                continue;
            }

            $members[] = [$id, $hmac];
            $times[]   = $time;
        }

        return [$members, $times];
    }

    /**
     * Whether the stored value is a string the pattern matches.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $pattern
     * @param  mixed  $value
     * @return bool
     *
     * @phpstan-assert-if-true string $value
     */
    private static function matches(string $pattern, mixed $value): bool
    {
        return is_string($value) && preg_match($pattern, $value) === 1;
    }

    /**
     * The stored time in the package's form, or `null` when it is not a stored
     * time.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $stored
     * @return ?string
     */
    private static function timeOf(mixed $stored): ?string
    {
        if (!is_string($stored)) {
            return null;
        }

        try {
            return StoredTime::fromStorage($stored);
        } catch (\UnexpectedValueException) {
            return null;
        }
    }

    /**
     * The position after the row, its time and id as the database returned
     * them, a number read as its digits.
     *
     * @param  \stdClass  $row
     * @return \SineMacula\Laravel\AuditLog\Integrity\SealCursor
     */
    private static function positionOf(#[\SensitiveParameter] \stdClass $row): SealCursor
    {
        return SealCursor::after(self::textOf($row->recorded_at ?? null), self::textOf($row->id ?? null));
    }

    /**
     * The stored value as text: a string as it is, a number as its digits, and
     * `null` as empty.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return string
     */
    private static function textOf(mixed $value): string
    {
        return is_scalar($value) ? (string) $value : '';
    }
}
