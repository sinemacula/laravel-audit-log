<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Keys;

use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeySigner;
use SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException;
use SineMacula\Laravel\AuditLog\Records\EnvelopeKeys;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Where the owners' keys are read: always through a writer, so a replica
 * lagging an erasure never hands back a key the erasure revoked.
 *
 * A record's keys are looked up at once, every unit it encrypts for in one
 * statement on the storage connection's writer, and only live keys whose
 * signature verifies are ever handed to encrypt with: a live key that does not
 * verify, or names a signing key the ring does not hold, is an
 * `UnexpectedValueException`. A page's keys are read by id in one statement,
 * and the journal rows of its erased keys' erasures in one more, both left
 * unverified for the reader to decide, a row too malformed to read left out; on
 * SQLite each binds at most 400 ids, so a page past 400 distinct keys takes a
 * statement for each 400. An owner's keys, a unit's live key and largest
 * generation, and a page of every key are read on the connection the caller
 * gives: the key session, the maintenance connection, or verification's.
 *
 * Nothing is kept between calls: no key row, wrapped key or data key outlives
 * the call that read it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class KeyStore
{
    /** @var string Why a live key is refused for encryption; it names nothing of the key or its owner. */
    private const string UNVERIFIED = 'A live subject key does not verify under its signing key.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\DatabaseManager  $database
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeySigner  $signer
     */
    public function __construct(

        /** The manager the storage connection is resolved from on every call. */
        private DatabaseManager $database,

        /** Verifies a live key before it is handed out. */
        private SubjectKeySigner $signer,
    ) {}

    /**
     * The live key of each unit that has one, by the unit's digest, read in one
     * statement on the storage connection's writer, each verified.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Keys\KeyUnit>  $units
     * @return array<string, \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow>
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    public function liveFor(#[\SensitiveParameter] array $units): array
    {
        $digests = array_values(array_unique(array_map(static fn (KeyUnit $unit): string => $unit->digest(), $units)));

        if ($digests === []) {
            return [];
        }

        $live = [];

        foreach (self::live($this->storage())->whereIn('unit', $digests)->orderBy('generation')->get() as $stored) {
            $row = $this->verified((array) $stored);

            $live[$row->unit] = $row;
        }

        return $live;
    }

    /**
     * The keys with the ids, by id, read in one statement on the storage
     * connection's writer, or one for each 400 on SQLite, in any state and
     * unverified, so the reader decides what each is. An id that is not a
     * canonical lower-case UUID names no key, and a row too malformed to read
     * is left out.
     *
     * @param  list<string>  $ids
     * @return array<string, \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow>
     *
     * @throws \InvalidArgumentException
     */
    public function byIds(array $ids): array
    {
        $ids = self::uuids($ids);

        if ($ids === []) {
            return [];
        }

        $keys       = [];
        $connection = $this->storage();

        foreach (self::chunks($connection, $ids) as $chunk) {
            foreach (self::keys($connection)->whereIn('id', $chunk)->get() as $stored) {
                $row = self::readable((array) $stored);

                if ($row === null) {
                    continue;
                }

                $keys[$row->id] = $row;
            }
        }

        return $keys;
    }

    /**
     * Every key of the owner, in every unit and state, through the owner's
     * index on the connection's writer, by id; unverified, for the caller
     * verifies them.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @return list<\SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow>
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    public function ofOwner(Connection $connection, #[\SensitiveParameter] Reference $owner): array
    {
        $rows = self::keys($connection)
            ->where('owner_type', $owner->type)
            ->where('owner_id', $owner->id)
            ->orderBy('id')
            ->get();

        return array_values(array_map(static fn (object $stored): SubjectKeyRow => SubjectKeyRow::fromRow((array) $stored), $rows->all()));
    }

    /**
     * The unit's live key on the connection's writer, verified as a record's
     * are, or `null` when the unit has none: the key creator's read once it
     * holds the owner's lock.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\AuditLog\Keys\KeyUnit  $unit
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    public function liveOf(Connection $connection, #[\SensitiveParameter] KeyUnit $unit): ?SubjectKeyRow
    {
        $stored = self::live($connection)->where('unit', $unit->digest())->orderByDesc('generation')->first();

        return $stored === null ? null : $this->verified((array) $stored);
    }

    /**
     * The journal rows with the ids, by id, read in one statement on the
     * storage connection's writer, or one for each 400 on SQLite, with their
     * payloads and left unverified, so the reader verifies each before it
     * believes an erasure. An id that is not a canonical lower-case UUID names
     * no row, and a row too malformed to read is left out.
     *
     * @param  list<string>  $ids
     * @return array<string, \SineMacula\Laravel\AuditLog\Integrity\JournalRow>
     *
     * @throws \InvalidArgumentException
     */
    public function erasureRows(array $ids): array
    {
        $ids = self::uuids($ids);

        if ($ids === []) {
            return [];
        }

        $rows       = [];
        $connection = $this->storage();

        foreach (self::chunks($connection, $ids) as $chunk) {
            foreach ($connection->table(LifecycleTables::journalTable())->useWritePdo()->whereIn('id', $chunk)->get() as $stored) {
                try {
                    $row = JournalRow::fromRow((array) $stored, true);
                } catch (\UnexpectedValueException) {
                    // A row that cannot be read cannot be verified, so it
                    // proves no erasure, as a missing one proves none
                    continue;
                }

                $rows[$row->id] = $row;
            }
        }

        return $rows;
    }

    /**
     * The unit's largest generation in any state on the connection's writer, or
     * 0 when the unit has no key.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $unit
     * @return int
     *
     * @throws \UnexpectedValueException
     */
    public function largestGeneration(Connection $connection, string $unit): int
    {
        $largest = self::keys($connection)->where('unit', $unit)->max('generation');

        return match (true) {
            $largest === null                            => 0,
            is_int($largest)                             => $largest,
            is_string($largest) && ctype_digit($largest) => (int) $largest,
            default                                      => throw new \UnexpectedValueException('A unit\'s largest generation is malformed.'),
        };
    }

    /**
     * Up to the limit of keys after the id, or from the first, in id order,
     * each as its stored row, read on the connection's writer: a page of every
     * key, for verification and the check.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  ?string  $afterId
     * @param  int  $limit
     * @return list<array<string, mixed>>
     *
     * @throws \InvalidArgumentException
     */
    public function page(Connection $connection, ?string $afterId, int $limit): array
    {
        if ($limit < 1) {
            throw new \InvalidArgumentException('A page of keys holds at least one key.');
        }

        $query = self::keys($connection)->orderBy('id')->limit($limit);

        if ($afterId !== null) {
            $query->where('id', '>', $afterId);
        }

        return array_values(array_map(static fn (object $stored): array => (array) $stored, $query->get()->all()));
    }

    /**
     * The row, verified under the signing key it names: one that does not
     * verify, or names a key the ring does not hold, is refused without naming
     * the key or its owner.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $stored
     * @return \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow
     *
     * @throws \UnexpectedValueException
     */
    private function verified(#[\SensitiveParameter] array $stored): SubjectKeyRow
    {
        $row = SubjectKeyRow::fromRow($stored);

        try {
            $verifies = $this->signer->verifies($row);
        } catch (UnknownKeyException) {
            $verifies = false;
        }

        return $verifies ? $row : throw new \UnexpectedValueException(self::UNVERIFIED);
    }

    /**
     * The storage connection, resolved on every call.
     *
     * @return \Illuminate\Database\Connection
     *
     * @throws \InvalidArgumentException
     */
    private function storage(): Connection
    {
        return $this->database->connection(StorageConnection::name());
    }

    /**
     * The subject keys table on the connection's writer.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \InvalidArgumentException
     */
    private static function keys(Connection $connection): Builder
    {
        return $connection->table(KeyTables::subjectKeysTable())->useWritePdo();
    }

    /**
     * The live keys on the connection's writer.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \InvalidArgumentException
     */
    private static function live(Connection $connection): Builder
    {
        return self::keys($connection)->where('state', KeyState::LIVE->value);
    }

    /**
     * The row a stored row holds, or `null` when it is too malformed to read.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $stored
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow
     */
    private static function readable(#[\SensitiveParameter] array $stored): ?SubjectKeyRow
    {
        try {
            return SubjectKeyRow::fromRow($stored);
        } catch (\UnexpectedValueException) {
            // A key too malformed to read is one the reader cannot open
            return null;
        }
    }

    /**
     * The distinct ids that are canonical lower-case UUIDs, the only form a key
     * or a journal row's id takes, so no engine is asked to compare a UUID
     * column with anything else.
     *
     * @param  list<string>  $ids
     * @return list<string>
     */
    private static function uuids(array $ids): array
    {
        return array_values(array_unique(array_filter($ids, static fn (string $id): bool => preg_match(EnvelopeKeys::KEY_PATTERN, $id) === 1)));
    }

    /**
     * The ids in the lists one statement each binds: all of them in one on
     * MySQL and PostgreSQL, and at most 400 a statement on SQLite, whose oldest
     * builds allow 999 placeholders, so a page past 400 distinct keys adds a
     * statement rather than fail.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  non-empty-list<string>  $ids
     * @return list<non-empty-list<string>>
     */
    private static function chunks(Connection $connection, array $ids): array
    {
        return $connection->getDriverName() === 'sqlite' ? array_chunk($ids, KeyUses::SQLITE_ROWS_PER_STATEMENT) : [$ids];
    }
}
