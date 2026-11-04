<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Database;

use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Str;

/**
 * The installation's identity: one id, a UUID version 7, kept under
 * `installation.id` in the integrity state table, seeded by the migration that
 * creates the table and written once, through the storage connection's writer.
 *
 * The id is written with a plain insert, never an upsert, so the first write
 * wins and no later one replaces it. A seal run or a lifecycle operation that
 * finds none, because the seeded row was lost, writes it again, and a write
 * that loses a race to a concurrent first write reads the winner's id instead;
 * `audit-log:check` only reads it, and reports one that is absent. A lifecycle
 * operation confirms, before it takes its lock, that the maintenance connection
 * reads the same id the storage connection does, so its deletions and journal
 * rows land in the database that holds the entries and the seals. The value is
 * a JSON object `{id}`, as progress is; a value that is not one, or whose id is
 * not a lower-case UUID, reads as absent. The row is never progress, so
 * `IntegrityProgress` neither reads nor writes it. This is a database helper
 * and names no clock: each caller passes its own instant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class InstallationIdentity
{
    /** @var string The state table's row the installation id is kept under. */
    public const string NAME = 'installation.id';

    /** @var string How a time is written: UTC to the microsecond, as every time the package stores. */
    private const string TIME_FORMAT = 'Y-m-d H:i:s.u';

    /** @var string What an installation id must be: a lower-case UUID. */
    private const string ID_PATTERN = '/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/';

    /** @var string The refusal of a storage connection that reads no installation id. */
    private const string ABSENT = 'The storage connection reaches no installation id; the package\'s migrations seed it, and `audit-log:seal` writes'
        . ' it when it is missing.';

    /** @var string The refusal of a storage connection that reads a malformed installation id. */
    private const string MALFORMED = 'The installation id the storage connection reads is malformed; it is never replaced, so it must be restored.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\DatabaseManager  $database
     */
    public function __construct(

        /** The connections the storage and maintenance connections are resolved from on every call. */
        private DatabaseManager $database,
    ) {}

    /**
     * The installation id, read through the storage connection's writer, and
     * written there first, as at the given time, when there is none yet.
     *
     * @param  \DateTimeInterface  $at
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    public function ensure(\DateTimeInterface $at): string
    {
        $connection = StorageConnection::resolvedName();
        $value      = $this->valueThrough($connection);

        if ($value === null) {
            $this->insert($connection, $at);

            $value = $this->valueThrough($connection);
        }

        return self::wellFormed($value);
    }

    /**
     * Ensure the installation id through the storage connection, then confirm
     * the maintenance connection reads the same one; when both are the same
     * connection, by name, no second read is made.
     *
     * @param  \DateTimeInterface  $at
     * @return void
     *
     * @throws \SineMacula\Laravel\AuditLog\Database\InstallationMismatchException
     */
    public function confirm(\DateTimeInterface $at): void
    {
        $this->confirmAgainst($this->ensure($at));
    }

    /**
     * Read the installation id through the storage connection and confirm the
     * maintenance connection reads the same one, writing nothing: a storage
     * connection that reads no id, or a malformed one, is refused, as is a
     * maintenance connection that reads none or another; when both are the same
     * connection, by name, no second read is made.
     *
     * @return void
     *
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Database\InstallationMismatchException
     */
    public function check(): void
    {
        $value = self::present($this->valueThrough(StorageConnection::resolvedName()));

        $this->confirmAgainst(self::wellFormed($value));
    }

    /**
     * The installation id read through the named connection's writer, or `null`
     * when it reads none, or one that is malformed.
     *
     * @param  string  $connection
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public function idThrough(string $connection): ?string
    {
        return self::idIn($this->valueThrough($connection));
    }

    /**
     * The state table's row of a new installation id, a UUID version 7 of the
     * given time, as written at that time in UTC to the microsecond: what the
     * migration that creates the table seeds, and what `ensure()` writes when
     * there is none.
     *
     * @param  \DateTimeInterface  $at
     * @return array{name: string, value: string, updated_at: string}
     *
     * @throws \JsonException
     */
    public static function row(\DateTimeInterface $at): array
    {
        $instant = \DateTimeImmutable::createFromInterface($at)->setTimezone(new \DateTimeZone('UTC'));

        return [
            'name'       => self::NAME,
            'value'      => json_encode(['id' => Str::uuid7($instant)->toString()], JSON_THROW_ON_ERROR),
            'updated_at' => $instant->format(self::TIME_FORMAT),
        ];
    }

    /**
     * Confirm the maintenance connection reads the installation id given, the
     * one the storage connection reads; when both are the same connection, by
     * name, no read is made.
     *
     * @param  string  $storage
     * @return void
     *
     * @throws \SineMacula\Laravel\AuditLog\Database\InstallationMismatchException
     */
    private function confirmAgainst(string $storage): void
    {
        $maintenance = StorageConnection::resolvedMaintenanceName();

        if ($maintenance === StorageConnection::resolvedName()) {
            return;
        }

        $id = $this->idThrough($maintenance);

        if ($id === null) {
            throw InstallationMismatchException::absent();
        }

        if ($id !== $storage) {
            throw InstallationMismatchException::mismatched();
        }
    }

    /**
     * Insert the installation id, a new UUID version 7, as written at the given
     * time; a concurrent first write that won leaves its own in place.
     *
     * @param  string  $connection
     * @param  \DateTimeInterface  $at
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    private function insert(string $connection, \DateTimeInterface $at): void
    {
        try {
            $this->state($connection)->insert(self::row($at));
        } catch (UniqueConstraintViolationException) { // @phpstan-ignore catch.neverThrown
            // A concurrent first write won; the caller reads its id.
        }
    }

    /**
     * The stored value of the installation id's row, read through the named
     * connection's writer, or `null` when there is no such row.
     *
     * @param  string  $connection
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private function valueThrough(string $connection): ?string
    {
        $value = $this->state($connection)->where('name', self::NAME)->value('value');

        return is_string($value) ? $value : null;
    }

    /**
     * A query of the state table on the named connection's writer.
     *
     * @param  string  $connection
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \InvalidArgumentException
     */
    private function state(string $connection): Builder
    {
        return $this->database->connection($connection)->table(IntegrityTables::stateTable())->useWritePdo();
    }

    /**
     * The stored value of the installation id's row the storage connection
     * reads, refused as absent when there is none.
     *
     * @param  ?string  $value
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private static function present(?string $value): string
    {
        return $value ?? throw new \UnexpectedValueException(self::ABSENT);
    }

    /**
     * The id the storage connection reads, from the stored value of its row,
     * refused as malformed when it holds none.
     *
     * @param  ?string  $value
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private static function wellFormed(?string $value): string
    {
        return self::idIn($value) ?? throw new \UnexpectedValueException(self::MALFORMED);
    }

    /**
     * The id a stored value holds: a JSON object of the one field `id`, a
     * lower-case UUID, and `null` for anything else.
     *
     * @param  ?string  $value
     * @return ?string
     */
    private static function idIn(?string $value): ?string
    {
        $decoded = $value === null ? null : json_decode($value);

        if (!$decoded instanceof \stdClass || array_keys(get_object_vars($decoded)) !== ['id']) {
            return null;
        }

        return is_string($decoded->id) && preg_match(self::ID_PATTERN, $decoded->id) === 1 ? $decoded->id : null;
    }
}
